package image

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Default byte caps for reading container image layers.
const (
	DefaultMaxFileBytes  int64 = 128 * 1024 * 1024 // 128 MiB per file
	DefaultMaxTotalBytes int64 = 512 * 1024 * 1024 // 512 MiB across all layers
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
		case tar.TypeSymlink:
			if err := validateLinkTarget(cleanPath, hdr.Linkname); err != nil {
				return err
			}
			delete(fs.Files, cleanPath)
			fs.Symlinks[cleanPath] = hdr.Linkname

		case tar.TypeLink:
			// Tar hardlinks are always relative to the archive root.
			hardTarget := "/" + strings.TrimPrefix(strings.ReplaceAll(hdr.Linkname, `\`, "/"), "/")
			if err := validateLinkTarget(cleanPath, hardTarget); err != nil {
				return err
			}
			delete(fs.Files, cleanPath)
			fs.Symlinks[cleanPath] = hardTarget

		case tar.TypeReg:
			if !isRelevantImageFile(cleanPath) {
				continue
			}
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

func isRelevantImageFile(cleanPath string) bool {
	switch cleanPath {
	case "etc/os-release",
		"usr/lib/os-release",
		"var/lib/dpkg/status",
		"lib/apk/db/installed",
		"usr/local/include/php/main/php_version.h",
		"usr/local/lib/php.ini":
		return true
	}

	if strings.HasPrefix(cleanPath, "var/lib/dpkg/status.d/") ||
		strings.HasPrefix(cleanPath, "var/lib/rpm/") ||
		strings.HasPrefix(cleanPath, "usr/lib/sysimage/rpm/") {
		return true
	}

	lower := strings.ToLower(cleanPath)
	if strings.HasSuffix(lower, "/php_version.h") {
		return true
	}

	if (strings.HasPrefix(lower, "etc/") || strings.HasPrefix(lower, "usr/local/etc/") || strings.HasPrefix(lower, "opt/")) &&
		(strings.HasSuffix(lower, ".ini") || strings.HasSuffix(lower, ".conf")) {
		return true
	}
	if (strings.HasPrefix(lower, "usr/lib/php/") || strings.HasPrefix(lower, "usr/share/php/")) &&
		(strings.HasSuffix(lower, ".ini") || strings.Contains(lower, "php.ini")) {
		return true
	}

	base := path.Base(lower)
	if strings.HasSuffix(base, ".tar.xz") ||
		strings.HasSuffix(base, ".tar.gz") ||
		strings.HasSuffix(base, ".tar") ||
		strings.HasSuffix(base, ".asc") ||
		strings.HasSuffix(base, ".php") ||
		strings.HasSuffix(base, ".phpt") ||
		strings.HasSuffix(base, ".a") ||
		strings.HasSuffix(base, ".la") {
		return false
	}

	inBinOrLibDir := strings.HasPrefix(lower, "bin/") ||
		strings.HasPrefix(lower, "sbin/") ||
		strings.HasPrefix(lower, "usr/bin/") ||
		strings.HasPrefix(lower, "usr/sbin/") ||
		strings.HasPrefix(lower, "usr/local/bin/") ||
		strings.HasPrefix(lower, "usr/local/sbin/") ||
		strings.HasPrefix(lower, "usr/lib/") ||
		strings.HasPrefix(lower, "usr/lib64/") ||
		strings.HasPrefix(lower, "usr/libexec/") ||
		strings.HasPrefix(lower, "usr/local/lib/") ||
		strings.HasPrefix(lower, "usr/local/libexec/") ||
		strings.HasPrefix(lower, "opt/")

	if inBinOrLibDir && (strings.HasPrefix(base, "php") ||
		strings.HasPrefix(base, "frankenphp") ||
		strings.HasPrefix(base, "lsphp") ||
		strings.HasPrefix(base, "libphp")) {
		return true
	}

	return false
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

// SortedPathsWithPrefix returns all file and symlink paths in FlatFS matching prefix in lexicographical order.
func (f *FlatFS) SortedPathsWithPrefix(prefix string) []string {
	seen := make(map[string]struct{})
	for p := range f.Files {
		if strings.HasPrefix(p, prefix) {
			seen[p] = struct{}{}
		}
	}
	for p := range f.Symlinks {
		if strings.HasPrefix(p, prefix) {
			seen[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
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

// ReadLink returns the target of a symlink stored in FlatFS.
func (f *FlatFS) ReadLink(name string) (string, error) {
	clean := path.Clean(strings.TrimPrefix(name, "/"))
	if target, ok := f.Symlinks[clean]; ok {
		return target, nil
	}
	return "", fs.ErrNotExist
}

// Open implements io/fs.FS on FlatFS.
func (f *FlatFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &flatDir{name: ".", entries: f.readDirEntries("")}, nil
	}
	if data, ok := f.Files[name]; ok {
		return &flatFile{
			name:   path.Base(name),
			reader: bytes.NewReader(data),
			size:   int64(len(data)),
			mode:   0o644,
		}, nil
	}
	if target, ok := f.Symlinks[name]; ok {
		b := []byte(target)
		return &flatFile{
			name:   path.Base(name),
			reader: bytes.NewReader(b),
			size:   int64(len(b)),
			mode:   fs.ModeSymlink | 0o777,
		}, nil
	}
	if f.hasSubdir(name) {
		return &flatDir{name: path.Base(name), entries: f.readDirEntries(name)}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// Stat implements io/fs.StatFS on FlatFS.
func (f *FlatFS) Stat(name string) (fs.FileInfo, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.Stat()
}

// ReadDir implements io/fs.ReadDirFS on FlatFS.
func (f *FlatFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	if name != "." && !f.hasSubdir(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	dir := ""
	if name != "." {
		dir = name
	}
	return f.readDirEntries(dir), nil
}

func (f *FlatFS) hasSubdir(dir string) bool {
	prefix := dir + "/"
	for p := range f.Files {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	for p := range f.Symlinks {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func (f *FlatFS) readDirEntries(dir string) []fs.DirEntry {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	byName := make(map[string]fs.DirEntry)

	addEntry := func(fullPath string, size int64, mode fs.FileMode) {
		if !strings.HasPrefix(fullPath, prefix) {
			return
		}
		rest := strings.TrimPrefix(fullPath, prefix)
		if rest == "" {
			return
		}
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			childDir := rest[:slash]
			byName[childDir] = &flatFileInfo{name: childDir, mode: fs.ModeDir | 0o755}
			return
		}
		byName[rest] = &flatFileInfo{name: rest, size: size, mode: mode}
	}

	for p, data := range f.Files {
		addEntry(p, int64(len(data)), 0o644)
	}
	for p, target := range f.Symlinks {
		addEntry(p, int64(len(target)), fs.ModeSymlink|0o777)
	}

	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	entries := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		entries = append(entries, byName[n])
	}
	return entries
}

type flatFileInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (fi *flatFileInfo) Name() string               { return fi.name }
func (fi *flatFileInfo) Size() int64                { return fi.size }
func (fi *flatFileInfo) Mode() fs.FileMode          { return fi.mode }
func (fi *flatFileInfo) ModTime() time.Time         { return time.Time{} }
func (fi *flatFileInfo) IsDir() bool                { return fi.mode.IsDir() }
func (fi *flatFileInfo) Sys() any                   { return nil }
func (fi *flatFileInfo) Type() fs.FileMode          { return fi.mode.Type() }
func (fi *flatFileInfo) Info() (fs.FileInfo, error) { return fi, nil }

type flatFile struct {
	name   string
	reader *bytes.Reader
	size   int64
	mode   fs.FileMode
}

func (ff *flatFile) Stat() (fs.FileInfo, error) {
	return &flatFileInfo{name: ff.name, size: ff.size, mode: ff.mode}, nil
}
func (ff *flatFile) Read(b []byte) (int, error) { return ff.reader.Read(b) }
func (ff *flatFile) Close() error               { return nil }

type flatDir struct {
	name    string
	entries []fs.DirEntry
	offset  int
}

func (fd *flatDir) Stat() (fs.FileInfo, error) {
	return &flatFileInfo{name: fd.name, mode: fs.ModeDir | 0o755}, nil
}
func (fd *flatDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: fd.name, Err: fs.ErrInvalid}
}
func (fd *flatDir) Close() error { return nil }
func (fd *flatDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if fd.offset >= len(fd.entries) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	if n <= 0 || fd.offset+n > len(fd.entries) {
		out := fd.entries[fd.offset:]
		fd.offset = len(fd.entries)
		return out, nil
	}
	out := fd.entries[fd.offset : fd.offset+n]
	fd.offset += n
	return out, nil
}
