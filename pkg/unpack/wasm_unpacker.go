package unpack

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/cleanup"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	exec "golang.org/x/sys/execabs"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (u *Unpacker) wasmFunc(h images.Handler) images.HandlerFunc {
	return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
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
			var componentConfig *ocispec.Descriptor

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
				if child.MediaType == "application/vnd.wasm.component.config.v1+json" {
					componentConfig = &children[i]
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

			if len(wasmComponents) > 0 && componentConfig == nil {
				return nil, fmt.Errorf("image contains components but no component config. This isn't currently supported")
			}

			if len(wasmModules) == 1 && runtime.GOOS == "windows" {
				moduleReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: wasmModules[0].Digest})
				if err != nil {
					return nil, err
				}
				defer moduleReader.Close()

				moduleName := ""
				m := bytes.Buffer{}
				l := int64(0)
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
						moduleName = hdr.Name
						io.Copy(&m, tr)
						l = hdr.Size
						continue
					}
				}

				// write new layer with the original module
				newTarBuffer, err := writeWindowsTar(moduleName, &m, l)
				if err != nil {
					return nil, fmt.Errorf("error writing new tar file: %w", err)
				}

				newManifest, err := u.generate_wasm_manifests(ctx, desc, wasmModules, config, newTarBuffer)
				if err != nil {
					return nil, err
				}

				wasmDescs = append(wasmDescs, newManifest)
			}

			if len(wasmComponents) > 0 && runtime.GOOS == "windows" {
				// append them together and write them to a new tar file.
				// update the image spec layer.

				// copy the digest to temp folder
				tempDir, err := os.MkdirTemp("", shaOnly(desc))
				if err != nil {
					return nil, err
				}
				defer os.RemoveAll(tempDir)

				for _, wasmComponent := range wasmComponents {
					err = u.write_wasm_file(ctx, tempDir, wasmComponent)
					if err != nil {
						return nil, err
					}
				}

				err = u.write_wasm_file(ctx, tempDir, *componentConfig)
				if err != nil {
					return nil, err
				}

				cmdArgs := []string{"compose", "-c", shaOnly(*componentConfig), "-o", "app.wasm", shaOnly(wasmComponents[0])}
				cmd := exec.Command("wasm-tools", cmdArgs...)
				cmd.Dir = tempDir
				output, err := cmd.CombinedOutput()
				if err != nil {
					return nil, fmt.Errorf("error running wasm-tools: %w. output: %s", err, output)
				}

				newwasm, err := os.ReadFile(filepath.Join(tempDir, "app.wasm"))
				if err != nil {
					return nil, err
				}

				// write new layer with the original module
				newTarBuffer, err := writeWindowsTar("app.wasm", bytes.NewBuffer(newwasm), int64(len(newwasm)))
				if err != nil {
					return nil, fmt.Errorf("error writing new tar file: %w", err)
				}

				newManifest, err := u.generate_wasm_manifests(ctx, desc, wasmComponents, config, newTarBuffer)
				if err != nil {
					return nil, err
				}

				wasmDescs = append(wasmDescs, newManifest)
			}
		}

		return wasmDescs, nil
	})
}

func shaOnly(desc ocispec.Descriptor) string {
	return strings.TrimPrefix(desc.Digest.String(), "sha256:")
}

func (u *Unpacker) write_wasm_file(ctx context.Context, dir string, wasmComponent ocispec.Descriptor) error {
	componentReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: wasmComponent.Digest})
	if err != nil {
		return err
	}
	defer componentReader.Close()

	cf, err := os.OpenFile(filepath.Join(dir, shaOnly(wasmComponent)), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	io.Copy(cf, content.NewReader(componentReader))
	err = cf.Close()
	if err != nil {
		return err
	}
	return nil
}

func (u *Unpacker) generate_wasm_manifests(ctx context.Context, originalManifest ocispec.Descriptor, originalWasmFiles []ocispec.Descriptor, originalConfig *ocispec.Descriptor, newTarlayer bytes.Buffer) (ocispec.Descriptor, error) {
	moduleLayerWriter, err := u.content.Writer(ctx,
		content.WithRef("wasm-module-"+originalWasmFiles[0].Digest.String()),
		content.WithDescriptor(ocispec.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar"}),
	)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	if _, err := io.Copy(moduleLayerWriter, &newTarlayer); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("error copying tar: %w", err)
	}

	if err := moduleLayerWriter.Commit(ctx, 0, moduleLayerWriter.Digest(), content.WithLabels(map[string]string{"wasm-module-original": originalWasmFiles[0].Digest.String()})); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("error copying tar: %w", err)
	}
	layerInfo := content.Info{
		Digest: originalWasmFiles[0].Digest,
		Labels: map[string]string{
			"wasm-unpacked": moduleLayerWriter.Digest().String(),
		},
	}
	u.content.Update(ctx, layerInfo, fmt.Sprintf("labels.%s", "wasm-unpacked"))

	// update the image config layers.
	configReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: originalConfig.Digest})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer configReader.Close()

	spec := ocispec.Image{}
	data, err := io.ReadAll(content.NewReader(configReader))
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	json.Unmarshal(data, &spec)
	spec.RootFS.DiffIDs = []digest.Digest{}
	spec.RootFS.DiffIDs = append(spec.RootFS.DiffIDs, moduleLayerWriter.Digest())
	spec.OS = "windows"
	spec.Architecture = "amd64"

	configWriter, err := u.content.Writer(ctx,
		content.WithRef("wasm-"+originalWasmFiles[0].Digest.String()),
		content.WithDescriptor(ocispec.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar"}),
	)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	json.NewEncoder(configWriter).Encode(spec)
	if err := configWriter.Commit(ctx, 0, configWriter.Digest(), content.WithLabels(map[string]string{"wasm-config-original": originalConfig.Digest.String()})); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("error copying tar: %w", err)
	}
	configInfo := content.Info{
		Digest: originalConfig.Digest,
		Labels: map[string]string{
			"wasm-unpacked": configWriter.Digest().String(),
		},
	}
	u.content.Update(ctx, configInfo, fmt.Sprintf("labels.%s", "wasm-unpacked"))

	// update the manifest.
	manifestReader, err := u.content.ReaderAt(ctx, ocispec.Descriptor{Digest: originalManifest.Digest})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer manifestReader.Close()

	manifest := ocispec.Manifest{}
	data, err = io.ReadAll(content.NewReader(manifestReader))
	if err != nil {
		return ocispec.Descriptor{}, err
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
		content.WithRef("wasm-"+originalManifest.Digest.String()),
		content.WithDescriptor(ocispec.Descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json"}),
	)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	json.NewEncoder(manifestWriter).Encode(manifest)
	if err := manifestWriter.Commit(ctx, 0, manifestWriter.Digest(), content.WithLabels(map[string]string{"wasm-config-original": originalManifest.Digest.String()})); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("error copying tar: %w", err)
	}
	manifestInfo := content.Info{
		Digest: originalManifest.Digest,
		Labels: map[string]string{
			"wasm-unpacked": manifestWriter.Digest().String(),
		},
	}
	u.content.Update(ctx, manifestInfo, fmt.Sprintf("labels.%s", "wasm-unpacked"))

	return ocispec.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    manifestWriter.Digest(),
	}, nil
}

func writeWindowsTar(name string, reader io.Reader, length int64) (bytes.Buffer, error) {
	var newTarBuffer bytes.Buffer
	newTarWriter := tar.NewWriter(&newTarBuffer)

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

	hdr := &tar.Header{
		Name: "Files/" + name,
		Size: length,
	}
	if err := newTarWriter.WriteHeader(hdr); err != nil {
		return bytes.Buffer{}, fmt.Errorf("error copying tar: %w", err)
	}

	if _, err := io.Copy(newTarWriter, reader); err != nil {
		return bytes.Buffer{}, fmt.Errorf("error copying tar: %w", err)
	}

	if err := newTarWriter.Close(); err != nil {
		return bytes.Buffer{}, fmt.Errorf("error copying tar: %w", err)
	}

	return newTarBuffer, nil
}
