package image

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Default byte caps for reading container image layers.
const (
	DefaultMaxFileBytes  int64 = 32 * 1024 * 1024  // 32 MiB per file
	DefaultMaxTotalBytes int64 = 256 * 1024 * 1024 // 256 MiB across all layers
)

// Sentinel errors for unsafe or oversized image layer entries.
var (
	ErrPathTraversal     = errors.New("tar entry contains path traversal outside root")
	ErrSymlinkEscape     = errors.New("tar symlink or hardlink escapes root directory")
	ErrFileTooLarge      = errors.New("tar entry exceeds per-file byte limit")
	ErrTotalBytesLimit   = errors.New("image layers exceed total byte read limit")
)

// FlattenOptions configures limits when streaming and flattening image layers.
type FlattenOptions struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// FlatFS holds the flattened, in-memory view of files extracted from container layers.
type FlatFS struct {
	Files     map[string][]byte
	Symlinks  map[string]string
	TotalRead int64
}

// FlattenLayers streams layers from bottom to top, applying OCI/Docker whiteouts,
// rejecting path traversal and root-escaping symlinks, and enforcing per-file and total byte caps.
func FlattenLayers(layers []v1.Layer, opts FlattenOptions) (*FlatFS, error) {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	if opts.MaxTotalBytes <= 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}

	fs := &FlatFS{
		Files:    make(map[string][]byte),
		Symlinks: make(map[string]string),
	}

	for i, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("uncompress layer %d: %w", i, err)
		}
		err = applyLayerTar(rc, fs, opts)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("process layer %d: %w", i, err)
		}
	}

	return fs, nil
}

func applyLayerTar(r io.Reader, fs *FlatFS, opts FlattenOptions) error {
	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		cleanPath, err := sanitizeTarPath(hdr.Name)
		if err != nil {
			return err
		}
		if cleanPath == "" || cleanPath == "." {
			continue
		}

		base := path.Base(cleanPath)
		dir := path.Dir(cleanPath)
		if dir == "." {
			dir = ""
		}

		// Handle OCI/Docker opaque whiteout: .wh..wh..opq removes all prior entries under dir.
		if base == ".wh..wh..opq" {
			applyOpaqueWhiteout(fs, dir)
			continue
		}

		// Handle OCI/Docker explicit whiteout: .wh.<name> removes dir/<name> and any children.
		if strings.HasPrefix(base, ".wh.") {
			targetName := strings.TrimPrefix(base, ".wh.")
			targetPath := targetName
			if dir != "" {
				targetPath = dir + "/" + targetName
			}
			applyExplicitWhiteout(fs, targetPath)
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			if err := validateLinkTarget(cleanPath, hdr.Linkname); err != nil {
				return err
			}
			delete(fs.Files, cleanPath)
			fs.Symlinks[cleanPath] = hdr.Linkname

		case tar.TypeReg:
			if hdr.Size > opts.MaxFileBytes {
				return fmt.Errorf("file %q (%d bytes > max %d): %w", cleanPath, hdr.Size, opts.MaxFileBytes, ErrFileTooLarge)
			}
			if fs.TotalRead+hdr.Size > opts.MaxTotalBytes {
				return fmt.Errorf("reading %q exceeds total cap (%d bytes): %w", cleanPath, opts.MaxTotalBytes, ErrTotalBytesLimit)
			}

			// Read up to MaxFileBytes+1 to detect unexpected stream overrun.
			limited := io.LimitReader(tr, opts.MaxFileBytes+1)
			data, readErr := io.ReadAll(limited)
			if readErr != nil {
				return fmt.Errorf("read %q: %w", cleanPath, readErr)
			}
			if int64(len(data)) > opts.MaxFileBytes {
				return fmt.Errorf("file %q stream exceeded max %d bytes: %w", cleanPath, opts.MaxFileBytes, ErrFileTooLarge)
			}
			fs.TotalRead += int64(len(data))
			if fs.TotalRead > opts.MaxTotalBytes {
				return fmt.Errorf("total bytes read (%d) exceeded cap (%d): %w", fs.TotalRead, opts.MaxTotalBytes, ErrTotalBytesLimit)
			}

			delete(fs.Symlinks, cleanPath)
			fs.Files[cleanPath] = data
		}
	}
}

func sanitizeTarPath(raw string) (string, error) {
	norm := strings.ReplaceAll(raw, `\`, "/")
	norm = strings.TrimPrefix(norm, "./")
	norm = strings.TrimPrefix(norm, "/")

	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", fmt.Errorf("invalid tar path %q: %w", raw, ErrPathTraversal)
		}
	}

	cleaned := path.Clean(norm)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("invalid cleaned tar path %q: %w", raw, ErrPathTraversal)
	}
	return cleaned, nil
}

func validateLinkTarget(entryPath, linkname string) error {
	normLink := strings.ReplaceAll(linkname, `\`, "/")
	if strings.HasPrefix(normLink, "/") {
		for _, seg := range strings.Split(normLink, "/") {
			if seg == ".." {
				return fmt.Errorf("link %q -> %q: %w", entryPath, linkname, ErrSymlinkEscape)
			}
		}
		return nil
	}

	resolved := path.Clean(path.Join(path.Dir(entryPath), normLink))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("link %q -> %q resolves to %q: %w", entryPath, linkname, resolved, ErrSymlinkEscape)
	}
	return nil
}

func applyOpaqueWhiteout(fs *FlatFS, dir string) {
	prefix := dir + "/"
	for k := range fs.Files {
		if dir == "" || strings.HasPrefix(k, prefix) {
			delete(fs.Files, k)
		}
	}
	for k := range fs.Symlinks {
		if dir == "" || strings.HasPrefix(k, prefix) {
			delete(fs.Symlinks, k)
		}
	}
}

func applyExplicitWhiteout(fs *FlatFS, targetPath string) {
	delete(fs.Files, targetPath)
	delete(fs.Symlinks, targetPath)

	prefix := targetPath + "/"
	for k := range fs.Files {
		if strings.HasPrefix(k, prefix) {
			delete(fs.Files, k)
		}
	}
	for k := range fs.Symlinks {
		if strings.HasPrefix(k, prefix) {
			delete(fs.Symlinks, k)
		}
	}
}

// SortedPathsWithPrefix returns all file paths in FlatFS matching prefix in lexicographical order.
func (f *FlatFS) SortedPathsWithPrefix(prefix string) []string {
	var out []string
	for p := range f.Files {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Reader returns a bytes.Reader for the given relative path if present.
func (f *FlatFS) Reader(relPath string) (*bytes.Reader, bool) {
	data, ok := f.Files[relPath]
	if !ok {
		return nil, false
	}
	return bytes.NewReader(data), true
}
