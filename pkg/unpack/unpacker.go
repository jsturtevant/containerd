/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package unpack

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/cleanup"
	"github.com/containerd/containerd/pkg/kmutex"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/containerd/tracing"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

const (
	labelSnapshotRef = "containerd.io/snapshot.ref"
	unpackSpanPrefix = "pkg.unpack.unpacker"
)

// Result returns information about the unpacks which were completed.
type Result struct {
	Unpacks int
}

type unpackerConfig struct {
	platforms []*Platform

	content content.Store

	limiter               *semaphore.Weighted
	duplicationSuppressor kmutex.KeyedLocker
}

// Platform represents a platform-specific unpack configuration which includes
// the platform matcher as well as snapshotter and applier.
type Platform struct {
	Platform platforms.Matcher

	SnapshotterKey string
	Snapshotter    snapshots.Snapshotter
	SnapshotOpts   []snapshots.Opt

	Applier   diff.Applier
	ApplyOpts []diff.ApplyOpt
}

type UnpackerOpt func(*unpackerConfig) error

func WithUnpackPlatform(u Platform) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		if u.Platform == nil {
			u.Platform = platforms.All
		}
		if u.Snapshotter == nil {
			return fmt.Errorf("snapshotter must be provided to unpack")
		}
		if u.SnapshotterKey == "" {
			if s, ok := u.Snapshotter.(fmt.Stringer); ok {
				u.SnapshotterKey = s.String()
			} else {
				u.SnapshotterKey = "unknown"
			}
		}
		if u.Applier == nil {
			return fmt.Errorf("applier must be provided to unpack")
		}

		c.platforms = append(c.platforms, &u)

		return nil
	})
}

func WithLimiter(l *semaphore.Weighted) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		c.limiter = l
		return nil
	})
}

func WithDuplicationSuppressor(d kmutex.KeyedLocker) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		c.duplicationSuppressor = d
		return nil
	})
}

// Unpacker unpacks images by hooking into the image handler process.
// Unpacks happen in the backgrounds and waited on to complete.
type Unpacker struct {
	unpackerConfig

	unpacks int32
	ctx     context.Context
	eg      *errgroup.Group
}

// NewUnpacker creates a new instance of the unpacker which can be used to wrap an
// image handler and unpack in parallel to handling. The unpacker will handle
// calling the block handlers when they are needed by the unpack process.
func NewUnpacker(ctx context.Context, cs content.Store, opts ...UnpackerOpt) (*Unpacker, error) {
	eg, ctx := errgroup.WithContext(ctx)

	u := &Unpacker{
		unpackerConfig: unpackerConfig{
			content:               cs,
			duplicationSuppressor: kmutex.NewNoop(),
		},
		ctx: ctx,
		eg:  eg,
	}
	for _, opt := range opts {
		if err := opt(&u.unpackerConfig); err != nil {
			return nil, err
		}
	}
	if len(u.platforms) == 0 {
		return nil, fmt.Errorf("no unpack platforms defined: %w", errdefs.ErrInvalidArgument)
	}
	return u, nil
}

// Unpack wraps an image handler to filter out blob handling and scheduling them
// during the unpack process. When an image config is encountered, the unpack
// process will be started in a goroutine.
func (u *Unpacker) Unpack(h images.Handler) images.Handler {
	var (
		lock   sync.Mutex
		layers = map[digest.Digest][]ocispec.Descriptor{}
	)

	wasmHandler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		unlock, err := u.lockBlobDescriptor(ctx, desc)
		if err != nil {
			return nil, err
		}
		children, err := h.Handle(ctx, desc)
		unlock()
		if err != nil {
			return children, err
		}

		fetchesDone, fetchErr := u.fetchAsync(ctx, children, h)
		for _, c := range fetchesDone {
			select {
			case <-ctx.Done():
				cleanup.Do(ctx, func(ctx context.Context) {})
				return children, ctx.Err()
			case err := <-fetchErr:
				if err != nil {
					cleanup.Do(ctx, func(ctx context.Context) {})
					return children, err
				}
			case <-c:
			}
		}

		wasmDescs := []ocispec.Descriptor{}
		switch desc.MediaType {
		case ocispec.MediaTypeImageManifest:
			var config *ocispec.Descriptor
			var wasmModules []ocispec.Descriptor
			var wasmComponents []ocispec.Descriptor

			manifestInfo, err := u.content.Info(ctx, desc.Digest)
			if err != nil {
				return children, err
			}
			if manifestInfo.Labels["wasm-unpacked"] != "" {
				return children, err
			}
			for i, child := range children {
				if child.MediaType == "application/vnd.w3c.wasm.module.v1+json" {
					config = &children[i]
					continue
				}
				if child.MediaType == "application/vnd.w3c.wasm.module.v1+wasm" {
					wasmModules = append(wasmModules, children[i])
					continue
				}
				if child.MediaType == "application/vnd.w3c.wasm.component.v1+wasm" {
					wasmComponents = append(wasmComponents, children[i])
					continue
				}
			}

			if config == nil {
				log.G(ctx).Debug("not a wasm image. not processing as wasm")
				return children, nil
			}

			if len(wasmModules) == 0 && len(wasmComponents) == 0 {
				log.G(ctx).Debug("not a wasm image. not processing as wasm")
				return children, nil
			}

			if len(wasmModules) > 0 && len(wasmComponents) > 0 {
				return nil, fmt.Errorf("image contains both wasm modules and components. This isn't currently supported")
			}

			if len(wasmModules) == 1 && runtime.GOOS == "windows" {
				// write new layer
				moduleReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: wasmModules[0].Digest})
				if err != nil {
					return nil, err
				}
				defer moduleReader.Close()

				var newTarBuffer bytes.Buffer
				newTarWriter := tar.NewWriter(&newTarBuffer)
				tr := tar.NewReader(content.NewReader(moduleReader))

				for {
					hdr, err := tr.Next()
					if err == io.EOF {
						break // End of archive
					}
					if err != nil {
						return nil, fmt.Errorf("error copying tar: %w", err)
					}

					if strings.HasSuffix(hdr.Name, ".wasm") {
						//fmt.Printf("Found Wasm File, moving to correct location %s:\n", hdr.Name)
						createFolderHeader(newTarWriter, "Files")
						createFolderHeader(newTarWriter, "Files/Windows")
						createFolderHeader(newTarWriter, "Files/Windows/System32")
						createFolderHeader(newTarWriter, "Files/Windows/System32/config")
						createFile(newTarWriter, "Files/Windows/System32/config/DEFAULT")
						createFile(newTarWriter, "Files/Windows/System32/config/SAM")
						createFile(newTarWriter, "Files/Windows/System32/config/SECURITY")
						createFile(newTarWriter, "Files/Windows/System32/config/SOFTWARE")
						createFile(newTarWriter, "Files/Windows/System32/config/SYSTEM")

						hdr.Name = "Files/" + hdr.Name
						if err := newTarWriter.WriteHeader(hdr); err != nil {
							return nil, fmt.Errorf("error copying tar: %w", err)
						}

						if _, err := io.Copy(newTarWriter, tr); err != nil {
							return nil, fmt.Errorf("error copying tar: %w", err)
						}
						continue
					}

					//fmt.Printf("writing file with name %s:\n", hdr.Name)
					if err := newTarWriter.WriteHeader(hdr); err != nil {
						return nil, fmt.Errorf("error copying tar: %w", err)
					}

					if _, err := io.Copy(newTarWriter, tr); err != nil {
						return nil, fmt.Errorf("error copying tar: %w", err)
					}
				}
				if err := newTarWriter.Close(); err != nil {
					return nil, fmt.Errorf("error copying tar: %w", err)
				}

				moduleLayerWriter, err := u.content.Writer(ctx,
					content.WithRef("wasm-module-"+wasmModules[0].Digest.String()),
					content.WithDescriptor(ocispec.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar"}),
				)
				if err != nil {
					return nil, err
				}

				if _, err := io.Copy(moduleLayerWriter, &newTarBuffer); err != nil {
					return nil, fmt.Errorf("error copying tar: %w", err)
				}

				if err := moduleLayerWriter.Commit(ctx, 0, moduleLayerWriter.Digest(), content.WithLabels(map[string]string{"wasm-module-original": wasmModules[0].Digest.String()})); err != nil {
					return nil, fmt.Errorf("error copying tar: %w", err)
				}
				layerInfo := content.Info{
					Digest: wasmModules[0].Digest,
					Labels: map[string]string{
						"wasm-unpacked": moduleLayerWriter.Digest().String(),
					},
				}
				u.content.Update(ctx, layerInfo, fmt.Sprintf("labels.%s", "wasm-unpacked"))

				//wasmDescs = append(wasmDescs, ocispec.Descriptor{
				//	MediaType: "application/vnd.oci.image.layer.v1.tar",
				//	Digest:    moduleLayerWriter.Digest(),
				//})

				// update the image config layers.
				configReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: config.Digest})
				if err != nil {
					return nil, err
				}
				defer configReader.Close()

				spec := ocispec.Image{}
				data, err := io.ReadAll(content.NewReader(configReader))
				if err != nil {
					return nil, err
				}
				json.Unmarshal(data, &spec)
				spec.RootFS.DiffIDs = []digest.Digest{}
				spec.RootFS.DiffIDs = append(spec.RootFS.DiffIDs, moduleLayerWriter.Digest())
				spec.OS = "windows"
				spec.Architecture = "amd64"

				configWriter, err := u.content.Writer(ctx,
					content.WithRef("wasm-"+wasmModules[0].Digest.String()),
					content.WithDescriptor(ocispec.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar"}),
				)
				if err != nil {
					return nil, err
				}

				json.NewEncoder(configWriter).Encode(spec)
				if err := configWriter.Commit(ctx, 0, configWriter.Digest(), content.WithLabels(map[string]string{"wasm-config-original": config.Digest.String()})); err != nil {
					return nil, fmt.Errorf("error copying tar: %w", err)
				}
				configInfo := content.Info{
					Digest: config.Digest,
					Labels: map[string]string{
						"wasm-unpacked": configWriter.Digest().String(),
					},
				}
				u.content.Update(ctx, configInfo, fmt.Sprintf("labels.%s", "wasm-unpacked"))

				//wasmDescs = append(wasmDescs, ocispec.Descriptor{
				//	MediaType: "application/vnd.oci.image.config.v1+json",
				//	Digest:    moduleLayerWriter.Digest(),
				//})

				// update the manifest.
				manifestReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: desc.Digest})
				if err != nil {
					return nil, err
				}
				defer manifestReader.Close()

				manifest := ocispec.Manifest{}
				data, err = io.ReadAll(content.NewReader(manifestReader))
				if err != nil {
					return nil, err
				}
				json.Unmarshal(data, &manifest)

				manifest.Layers = []ocispec.Descriptor{}
				manifest.Layers = append(manifest.Layers, ocispec.Descriptor{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    moduleLayerWriter.Digest(),
				})
				manifest.Config = ocispec.Descriptor{
					MediaType: "application/vnd.oci.image.config.v1+json",
					Digest:    configWriter.Digest(),
				}

				manifestWriter, err := u.content.Writer(ctx,
					content.WithRef("wasm-"+desc.Digest.String()),
					content.WithDescriptor(ocispec.Descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json"}),
				)
				if err != nil {
					return nil, err
				}

				json.NewEncoder(manifestWriter).Encode(manifest)
				if err := manifestWriter.Commit(ctx, 0, manifestWriter.Digest(), content.WithLabels(map[string]string{"wasm-config-original": desc.Digest.String()})); err != nil {
					return nil, fmt.Errorf("error copying tar: %w", err)
				}
				manifestInfo := content.Info{
					Digest: desc.Digest,
					Labels: map[string]string{
						"wasm-unpacked": manifestWriter.Digest().String(),
					},
				}
				u.content.Update(ctx, manifestInfo, fmt.Sprintf("labels.%s", "wasm-unpacked"))

				wasmDescs = append(wasmDescs, ocispec.Descriptor{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Digest:    manifestWriter.Digest(),
				})
			}

			if len(wasmModules) > 0 {
				//TODO
				// append them together and write them to a new tar file.
				// update the image spec layer.
			}
		}

		return wasmDescs, nil
	})

	defaultunpacker := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		ctx, span := tracing.StartSpan(ctx, tracing.Name(unpackSpanPrefix, "UnpackHandler"))
		defer span.End()
		span.SetAttributes(
			tracing.Attribute("descriptor.media.type", desc.MediaType),
			tracing.Attribute("descriptor.digest", desc.Digest.String()))
		unlock, err := u.lockBlobDescriptor(ctx, desc)
		if err != nil {
			return nil, err
		}
		children, err := h.Handle(ctx, desc)
		unlock()
		if err != nil {
			return children, err
		}

		switch desc.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
			var nonLayers []ocispec.Descriptor
			var manifestLayers []ocispec.Descriptor
			// Split layers from non-layers, layers will be handled after
			// the config
			for i, child := range children {
				span.SetAttributes(
					tracing.Attribute("descriptor.child."+strconv.Itoa(i), []string{child.MediaType, child.Digest.String()}),
				)
				if images.IsLayerType(child.MediaType) {
					manifestLayers = append(manifestLayers, child)
				} else {
					nonLayers = append(nonLayers, child)
				}
			}

			lock.Lock()
			for _, nl := range nonLayers {
				layers[nl.Digest] = manifestLayers
			}
			lock.Unlock()

			children = nonLayers
		case images.MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig:
			lock.Lock()
			l := layers[desc.Digest]
			lock.Unlock()
			if len(l) > 0 {
				u.eg.Go(func() error {
					return u.unpack(h, desc, l)
				})
			}
		}
		return children, nil
	})

	return images.Handlers(wasmHandler, defaultunpacker)
}

func createFolderHeader(tw *tar.Writer, name string) {
	system32 := &tar.Header{
		Name:     name,
		Typeflag: tar.TypeDir,
	}

	if err := tw.WriteHeader(system32); err != nil {

		os.Exit(1)
	}
}

func createFile(tw *tar.Writer, name string) {
	system32 := &tar.Header{
		Name: name,
		Mode: 0600,
		Size: int64(len("")),
	}

	if err := tw.WriteHeader(system32); err != nil {
		os.Exit(1)
	}

	if _, err := tw.Write([]byte("")); err != nil {
		os.Exit(1)
	}
}

// Wait waits for any ongoing unpack processes to complete then will return
// the result.
func (u *Unpacker) Wait() (Result, error) {
	if err := u.eg.Wait(); err != nil {
		return Result{}, err
	}
	return Result{
		Unpacks: int(u.unpacks),
	}, nil
}

func (u *Unpacker) unpack(
	h images.Handler,
	config ocispec.Descriptor,
	layers []ocispec.Descriptor,
) error {
	ctx := u.ctx
	ctx, layerSpan := tracing.StartSpan(ctx, tracing.Name(unpackSpanPrefix, "unpack"))
	defer layerSpan.End()
	p, err := content.ReadBlob(ctx, u.content, config)
	if err != nil {
		return err
	}

	var i ocispec.Image
	if err := json.Unmarshal(p, &i); err != nil {
		return fmt.Errorf("unmarshal image config: %w", err)
	}
	diffIDs := i.RootFS.DiffIDs
	if len(layers) != len(diffIDs) {
		return fmt.Errorf("number of layers and diffIDs don't match: %d != %d", len(layers), len(diffIDs))
	}

	// TODO: Support multiple unpacks rather than just first match
	var unpack *Platform

	imgPlatform := platforms.Normalize(ocispec.Platform{OS: i.OS, Architecture: i.Architecture})
	for _, up := range u.platforms {
		if up.Platform.Match(imgPlatform) {
			unpack = up
			break
		}
	}

	if unpack == nil {
		return fmt.Errorf("unpacker does not support platform %s for image %s", imgPlatform, config.Digest)
	}

	atomic.AddInt32(&u.unpacks, 1)

	var (
		sn = unpack.Snapshotter
		a  = unpack.Applier
		cs = u.content

		chain []digest.Digest

		fetchC   []chan struct{}
		fetchErr chan error
	)

	// If there is an early return, ensure any ongoing
	// fetches get their context cancelled
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	doUnpackFn := func(i int, desc ocispec.Descriptor) error {
		parent := identity.ChainID(chain)
		chain = append(chain, diffIDs[i])
		chainID := identity.ChainID(chain).String()

		unlock, err := u.lockSnChainID(ctx, chainID, unpack.SnapshotterKey)
		if err != nil {
			return err
		}
		defer unlock()

		if _, err := sn.Stat(ctx, chainID); err == nil {
			// no need to handle
			return nil
		} else if !errdefs.IsNotFound(err) {
			return fmt.Errorf("failed to stat snapshot %s: %w", chainID, err)
		}

		// inherits annotations which are provided as snapshot labels.
		snapshotLabels := snapshots.FilterInheritedLabels(desc.Annotations)
		if snapshotLabels == nil {
			snapshotLabels = make(map[string]string)
		}
		snapshotLabels[labelSnapshotRef] = chainID

		var (
			key    string
			mounts []mount.Mount
			opts   = append(unpack.SnapshotOpts, snapshots.WithLabels(snapshotLabels))
		)

		for try := 1; try <= 3; try++ {
			// Prepare snapshot with from parent, label as root
			key = fmt.Sprintf(snapshots.UnpackKeyFormat, uniquePart(), chainID)
			mounts, err = sn.Prepare(ctx, key, parent.String(), opts...)
			if err != nil {
				if errdefs.IsAlreadyExists(err) {
					if _, err := sn.Stat(ctx, chainID); err != nil {
						if !errdefs.IsNotFound(err) {
							return fmt.Errorf("failed to stat snapshot %s: %w", chainID, err)
						}
						// Try again, this should be rare, log it
						log.G(ctx).WithField("key", key).WithField("chainid", chainID).Debug("extraction snapshot already exists, chain id not found")
					} else {
						// no need to handle, snapshot now found with chain id
						return nil
					}
				} else {
					return fmt.Errorf("failed to prepare extraction snapshot %q: %w", key, err)
				}
			} else {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("unable to prepare extraction snapshot: %w", err)
		}

		// Abort the snapshot if commit does not happen
		abort := func(ctx context.Context) {
			if err := sn.Remove(ctx, key); err != nil {
				log.G(ctx).WithError(err).Errorf("failed to cleanup %q", key)
			}
		}

		// only kick off fetch the first time
		if fetchErr == nil {
			layersToFetch := layers[i:]
			fetchC, fetchErr = u.fetchAsync(ctx, layersToFetch, h)
		}

		// wait for an error or this layer to complete
		select {
		case <-ctx.Done():
			cleanup.Do(ctx, abort)
			return ctx.Err()
		case err := <-fetchErr:
			if err != nil {
				cleanup.Do(ctx, abort)
				return err
			}
		case <-fetchC[i]:
		}

		diff, err := a.Apply(ctx, desc, mounts, unpack.ApplyOpts...)
		if err != nil {
			cleanup.Do(ctx, abort)
			return fmt.Errorf("failed to extract layer %s: %w", diffIDs[i], err)
		}
		if diff.Digest != diffIDs[i] {
			cleanup.Do(ctx, abort)
			return fmt.Errorf("wrong diff id calculated on extraction %q", diffIDs[i])
		}

		if err = sn.Commit(ctx, chainID, key, opts...); err != nil {
			cleanup.Do(ctx, abort)
			if errdefs.IsAlreadyExists(err) {
				return nil
			}
			return fmt.Errorf("failed to commit snapshot %s: %w", key, err)
		}

		// Set the uncompressed label after the uncompressed
		// digest has been verified through apply.
		cinfo := content.Info{
			Digest: desc.Digest,
			Labels: map[string]string{
				labels.LabelUncompressed: diff.Digest.String(),
			},
		}
		if _, err := cs.Update(ctx, cinfo, "labels."+labels.LabelUncompressed); err != nil {
			return err
		}
		return nil
	}

	for i, desc := range layers {
		_, layerSpan := tracing.StartSpan(ctx, tracing.Name(unpackSpanPrefix, "unpackLayer"))
		layerSpan.SetAttributes(
			tracing.Attribute("layer.media.type", desc.MediaType),
			tracing.Attribute("layer.media.size", desc.Size),
			tracing.Attribute("layer.media.digest", desc.Digest.String()),
		)
		if err := doUnpackFn(i, desc); err != nil {
			layerSpan.SetStatus(err)
			layerSpan.End()
			return err
		}
		layerSpan.End()
	}

	chainID := identity.ChainID(chain).String()
	cinfo := content.Info{
		Digest: config.Digest,
		Labels: map[string]string{
			fmt.Sprintf("containerd.io/gc.ref.snapshot.%s", unpack.SnapshotterKey): chainID,
		},
	}
	_, err = cs.Update(ctx, cinfo, fmt.Sprintf("labels.containerd.io/gc.ref.snapshot.%s", unpack.SnapshotterKey))
	if err != nil {
		return err
	}
	log.G(ctx).WithFields(log.Fields{
		"config":  config.Digest,
		"chainID": chainID,
	}).Debug("image unpacked")

	return nil
}

func (u *Unpacker) fetchAsync(ctx context.Context, layers []ocispec.Descriptor, h images.Handler) ([]chan struct{}, chan error) {
	fetchErr := make(chan error, 1)
	fetchDone := make([]chan struct{}, len(layers))
	for i := range fetchDone {
		fetchDone[i] = make(chan struct{})
	}

	go func(layers []ocispec.Descriptor) {
		err := u.fetch(ctx, h, layers, fetchDone)
		if err != nil {
			fetchErr <- err
		}
		close(fetchErr)
	}(layers)
	return fetchDone, fetchErr
}

func (u *Unpacker) fetch(ctx context.Context, h images.Handler, layers []ocispec.Descriptor, done []chan struct{}) error {
	eg, ctx2 := errgroup.WithContext(ctx)
	for i, desc := range layers {
		ctx2, layerSpan := tracing.StartSpan(ctx2, tracing.Name(unpackSpanPrefix, "fetchLayer"))
		layerSpan.SetAttributes(
			tracing.Attribute("layer.media.type", desc.MediaType),
			tracing.Attribute("layer.media.size", desc.Size),
			tracing.Attribute("layer.media.digest", desc.Digest.String()),
		)
		desc := desc
		i := i
		if err := u.acquire(ctx); err != nil {
			return err
		}

		eg.Go(func() error {
			unlock, err := u.lockBlobDescriptor(ctx2, desc)
			if err != nil {
				u.release()
				return err
			}

			_, err = h.Handle(ctx2, desc)

			unlock()
			u.release()

			if err != nil && !errors.Is(err, images.ErrSkipDesc) {
				return err
			}
			close(done[i])

			return nil
		})
		layerSpan.End()
	}

	return eg.Wait()
}

func (u *Unpacker) acquire(ctx context.Context) error {
	if u.limiter == nil {
		return nil
	}
	return u.limiter.Acquire(ctx, 1)
}

func (u *Unpacker) release() {
	if u.limiter == nil {
		return
	}
	u.limiter.Release(1)
}

func (u *Unpacker) lockSnChainID(ctx context.Context, chainID, snapshotter string) (func(), error) {
	key := u.makeChainIDKeyWithSnapshotter(chainID, snapshotter)

	if err := u.duplicationSuppressor.Lock(ctx, key); err != nil {
		return nil, err
	}
	return func() {
		u.duplicationSuppressor.Unlock(key)
	}, nil
}

func (u *Unpacker) lockBlobDescriptor(ctx context.Context, desc ocispec.Descriptor) (func(), error) {
	key := u.makeBlobDescriptorKey(desc)

	if err := u.duplicationSuppressor.Lock(ctx, key); err != nil {
		return nil, err
	}
	return func() {
		u.duplicationSuppressor.Unlock(key)
	}, nil
}

func (u *Unpacker) makeChainIDKeyWithSnapshotter(chainID, snapshotter string) string {
	return fmt.Sprintf("sn://%s/%v", snapshotter, chainID)
}

func (u *Unpacker) makeBlobDescriptorKey(desc ocispec.Descriptor) string {
	return fmt.Sprintf("blob://%v", desc.Digest)
}

func uniquePart() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.Nanosecond(), base64.URLEncoding.EncodeToString(b[:]))
}
