package path

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

const maxManifestFileBytes = 4 << 20 // 4 MiB cap per manifest file

var (
	dockerfileFromRe      = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--[a-z0-9-]+=\S+\s+)*(\S+)`)
	composeImageRe        = regexp.MustCompile(`^\s*-?\s*image\s*:\s*["']?([^\s"'#]+)["']?`)
	composeBuildRe        = regexp.MustCompile(`^\s*build\s*:\s*(.*)$`)
	composeBuildContextRe = regexp.MustCompile(`^\s*context\s*:\s*["']?([^\s"'#]+)["']?`)
	composeBuildFileRe    = regexp.MustCompile(`^\s*dockerfile\s*:\s*["']?([^\s"'#]+)["']?`)
	exactSemverRe         = regexp.MustCompile(`^(\d+\.\d+\.\d+(?:(?:RC|alpha|beta|dev)\d*)?)(?:$|[-_][a-zA-Z])`)
	frankenPHPVerRe       = regexp.MustCompile(`php(\d+\.\d+\.\d+(?:(?:RC|alpha|beta|dev)\d*)?)`)
)

// NormalizeImageRef strips default Docker Hub library prefixes for display.
func NormalizeImageRef(ref string) string {
	return inventory.NormalizeImageRef(ref)
}

// Options configures filesystem path scanning.
type Options struct {
	RootPath string
	Exclude  []string
}

// Collector discovers PHP version declarations and constraints in a directory tree or file.
type Collector struct {
	opts Options
}

// NewCollector creates a filesystem path Collector with the given options.
func NewCollector(opts Options) *Collector {
	return &Collector{opts: opts}
}

// Collect walks RootPath (respecting Exclude patterns and never following symlinks outside the root)
// to discover PHP references in Dockerfile*, docker-compose*.y*ml, composer.json, .php-version, and .tool-versions.
func (c *Collector) Collect(ctx context.Context) ([]inventory.PHPInstall, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root := strings.TrimSpace(c.opts.RootPath)
	if root == "" {
		return nil, fmt.Errorf("empty path target")
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve path %q: %w", root, err)
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("evaluate root path %q: %w", root, err)
	}

	info, err := os.Stat(realRoot)
	if err != nil {
		return nil, fmt.Errorf("stat path %q: %w", root, err)
	}

	if !info.IsDir() {
		return c.inspectFile(realRoot, filepath.Base(realRoot))
	}

	var installs []inventory.PHPInstall
	var buildRefs []composeBuildRef
	walkErr := filepath.WalkDir(realRoot, func(currentPath string, d fs.DirEntry, walkInErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkInErr != nil {
			return nil
		}
		if currentPath == realRoot {
			return nil
		}

		rel, relErr := filepath.Rel(realRoot, currentPath)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)

		if c.isExcluded(d.Name(), relSlash) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Never follow symlinks outside the root; never recurse into directory symlinks.
		if d.Type()&os.ModeSymlink != 0 {
			targetReal, symErr := filepath.EvalSymlinks(currentPath)
			if symErr != nil || !isWithinRoot(realRoot, targetReal) {
				return nil
			}
			targetInfo, statErr := os.Stat(targetReal)
			if statErr != nil || targetInfo.IsDir() {
				return nil
			}
		}

		if d.IsDir() {
			return nil
		}

		if isComposeFileName(strings.ToLower(d.Name())) {
			if data, readErr := readCappedFile(currentPath); readErr == nil {
				buildRefs = append(buildRefs, parseComposeBuildRefs(data, relSlash)...)
			}
		}

		found, fileErr := c.inspectFile(currentPath, relSlash)
		if fileErr != nil {
			return nil
		}
		installs = append(installs, found...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	installs = mergeComposeBuildRefs(installs, buildRefs)
	return installs, nil
}

func (c *Collector) isExcluded(baseName, relSlash string) bool {
	if baseName == ".git" {
		return true
	}
	for _, rawPattern := range c.opts.Exclude {
		pattern := strings.TrimSpace(filepath.ToSlash(rawPattern))
		if pattern == "" {
			continue
		}
		pattern = strings.TrimSuffix(pattern, "/")
		if matched, err := filepath.Match(pattern, baseName); err == nil && matched {
			return true
		}
		if matched, err := filepath.Match(pattern, relSlash); err == nil && matched {
			return true
		}
		if relSlash == pattern || strings.HasPrefix(relSlash, pattern+"/") {
			return true
		}
	}
	return false
}

func isWithinRoot(realRoot, targetReal string) bool {
	cleanRoot := filepath.Clean(realRoot)
	cleanTarget := filepath.Clean(targetReal)
	rel, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

func (c *Collector) inspectFile(fullPath, displayPath string) ([]inventory.PHPInstall, error) {
	base := filepath.Base(fullPath)
	lowerBase := strings.ToLower(base)

	switch {
	case isDockerfileName(lowerBase):
		data, err := readCappedFile(fullPath)
		if err != nil {
			return nil, err
		}
		return parseDockerfileBytes(data, displayPath), nil
	case isComposeFileName(lowerBase):
		data, err := readCappedFile(fullPath)
		if err != nil {
			return nil, err
		}
		return parseComposeBytes(data, displayPath), nil
	case lowerBase == "composer.json":
		data, err := readCappedFile(fullPath)
		if err != nil {
			return nil, err
		}
		return parseComposerBytes(data, displayPath), nil
	case base == ".php-version":
		data, err := readCappedFile(fullPath)
		if err != nil {
			return nil, err
		}
		return parsePHPVersionFileBytes(data, displayPath), nil
	case base == ".tool-versions":
		data, err := readCappedFile(fullPath)
		if err != nil {
			return nil, err
		}
		return parseToolVersionsBytes(data, displayPath), nil
	default:
		return nil, nil
	}
}

func isDockerfileName(lowerBase string) bool {
	return lowerBase == "dockerfile" ||
		strings.HasPrefix(lowerBase, "dockerfile.") ||
		strings.HasPrefix(lowerBase, "dockerfile-") ||
		strings.HasSuffix(lowerBase, ".dockerfile")
}

func isComposeFileName(lowerBase string) bool {
	if !strings.HasSuffix(lowerBase, ".yml") && !strings.HasSuffix(lowerBase, ".yaml") {
		return false
	}
	return strings.HasPrefix(lowerBase, "docker-compose") || strings.HasPrefix(lowerBase, "compose")
}

func readCappedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxManifestFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestFileBytes {
		return nil, fmt.Errorf("file %q exceeds size cap", path)
	}
	return data, nil
}

func parseDockerfileBytes(data []byte, displayPath string) []inventory.PHPInstall {
	lines := strings.Split(string(data), "\n")
	var installs []inventory.PHPInstall

	for idx, rawLine := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := dockerfileFromRe.FindStringSubmatch(trimmed)
		if len(m) < 2 {
			continue
		}
		imageRef := m[1]
		inst, ok := buildContainerRefInstall(imageRef, displayPath, lineNum, trimmed)
		if ok {
			installs = append(installs, inst)
		}
	}
	return installs
}

func parseComposeBytes(data []byte, displayPath string) []inventory.PHPInstall {
	lines := strings.Split(string(data), "\n")
	var installs []inventory.PHPInstall

	for idx, rawLine := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := composeImageRe.FindStringSubmatch(rawLine)
		if len(m) < 2 {
			continue
		}
		imageRef := m[1]
		inst, ok := buildContainerRefInstall(imageRef, displayPath, lineNum, trimmed)
		if ok {
			installs = append(installs, inst)
		}
	}
	return installs
}

type composeBuildRef struct {
	composeFile        string
	buildLineNum       int
	buildLineText      string
	dockerfileRelSlash string
	serviceImageLocs   []string
}

func parseComposeBuildRefs(data []byte, composeRelSlash string) []composeBuildRef {
	lines := strings.Split(string(data), "\n")
	composeDir := filepath.Dir(composeRelSlash)
	var refs []composeBuildRef

	for idx := 0; idx < len(lines); idx++ {
		rawLine := lines[idx]
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := composeBuildRe.FindStringSubmatch(rawLine)
		if len(m) < 2 {
			continue
		}

		buildLineNum := idx + 1
		buildIndent := countLeadingSpaces(rawLine)
		remainder := stripYAMLCommentAndQuotes(m[1])

		contextDir := "."
		dockerfileName := "Dockerfile"
		buildLineText := trimmed

		if remainder != "" {
			contextDir = remainder
		} else {
			for j := idx + 1; j < len(lines); j++ {
				subRaw := lines[j]
				subTrim := strings.TrimSpace(subRaw)
				if subTrim == "" || strings.HasPrefix(subTrim, "#") {
					continue
				}
				if countLeadingSpaces(subRaw) <= buildIndent {
					break
				}
				if cm := composeBuildContextRe.FindStringSubmatch(subRaw); len(cm) == 2 {
					contextDir = cm[1]
				}
				if dm := composeBuildFileRe.FindStringSubmatch(subRaw); len(dm) == 2 {
					dockerfileName = dm[1]
				}
			}
			buildLineText = fmt.Sprintf("build: (context: %s, dockerfile: %s)", contextDir, dockerfileName)
		}

		// Also find any image: directive belonging to the same service block so we can deduplicate if needed.
		var serviceImageLocs []string
		for j := idx - 1; j >= 0; j-- {
			subRaw := lines[j]
			subTrim := strings.TrimSpace(subRaw)
			if subTrim == "" || strings.HasPrefix(subTrim, "#") {
				continue
			}
			if countLeadingSpaces(subRaw) < buildIndent {
				break
			}
			if composeImageRe.MatchString(subRaw) {
				serviceImageLocs = append(serviceImageLocs, fmt.Sprintf("%s:%d", composeRelSlash, j+1))
			}
		}
		for j := idx + 1; j < len(lines); j++ {
			subRaw := lines[j]
			subTrim := strings.TrimSpace(subRaw)
			if subTrim == "" || strings.HasPrefix(subTrim, "#") {
				continue
			}
			if countLeadingSpaces(subRaw) < buildIndent {
				break
			}
			if composeImageRe.MatchString(subRaw) {
				serviceImageLocs = append(serviceImageLocs, fmt.Sprintf("%s:%d", composeRelSlash, j+1))
			}
		}

		resolvedDockerfile := filepath.ToSlash(filepath.Clean(filepath.Join(composeDir, contextDir, dockerfileName)))
		refs = append(refs, composeBuildRef{
			composeFile:        composeRelSlash,
			buildLineNum:       buildLineNum,
			buildLineText:      buildLineText,
			dockerfileRelSlash: resolvedDockerfile,
			serviceImageLocs:   serviceImageLocs,
		})
	}
	return refs
}

func mergeComposeBuildRefs(installs []inventory.PHPInstall, buildRefs []composeBuildRef) []inventory.PHPInstall {
	if len(buildRefs) == 0 || len(installs) == 0 {
		return installs
	}

	dropComposeImageLoc := make(map[string]bool)
	for _, ref := range buildRefs {
		prefix := ref.dockerfileRelSlash + ":"
		matched := false
		composeEv := fmt.Sprintf("%s:%d -> %s", ref.composeFile, ref.buildLineNum, ref.buildLineText)
		for i := range installs {
			if strings.HasPrefix(installs[i].BinaryPath, prefix) {
				installs[i].AddEvidence(composeEv)
				matched = true
			}
		}
		if matched {
			for _, loc := range ref.serviceImageLocs {
				dropComposeImageLoc[loc] = true
			}
		}
	}

	if len(dropComposeImageLoc) == 0 {
		return installs
	}

	filtered := make([]inventory.PHPInstall, 0, len(installs))
	for _, inst := range installs {
		if dropComposeImageLoc[inst.BinaryPath] {
			continue
		}
		filtered = append(filtered, inst)
	}
	return filtered
}

func countLeadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		switch r {
		case ' ':
			count++
		case '\t':
			count += 2
		default:
			return count
		}
	}
	return count
}

func stripYAMLCommentAndQuotes(s string) string {
	trimmed := strings.TrimSpace(s)
	if idx := strings.IndexByte(trimmed, '#'); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	return strings.Trim(trimmed, `"'`)
}

func buildContainerRefInstall(imageRef, displayPath string, lineNum int, lineText string) (inventory.PHPInstall, bool) {
	repo, tag := splitImageRepoTag(imageRef)
	lowerRepo := strings.ToLower(repo)

	isPHPImage := lowerRepo == "php" ||
		lowerRepo == "library/php" ||
		strings.HasSuffix(lowerRepo, "/library/php") ||
		strings.HasSuffix(lowerRepo, "/php") ||
		strings.HasSuffix(lowerRepo, "/php-fpm") ||
		strings.HasSuffix(lowerRepo, "/frankenphp")
	if !isPHPImage {
		return inventory.PHPInstall{}, false
	}

	sapi := inferSAPIFromImageRef(lowerRepo, tag)
	upstreamVer := extractContainerPHPVersion(imageRef, lowerRepo, tag)
	evLoc := fmt.Sprintf("%s:%d", displayPath, lineNum)

	return inventory.PHPInstall{
		ID:              fmt.Sprintf("path:%s:%d", displayPath, lineNum),
		BinaryPath:      evLoc,
		UpstreamVersion: upstreamVer,
		PackageManager:  "container",
		PackageName:     repo,
		SAPI:            sapi,
		Source:          inventory.SourcePath,
		Confidence:      inventory.ConfidenceMedium,
		Evidence: []string{
			fmt.Sprintf("%s -> %s", evLoc, lineText),
		},
	}, true
}

func splitImageRepoTag(imageRef string) (string, string) {
	ref := imageRef
	if atIdx := strings.IndexByte(ref, '@'); atIdx >= 0 {
		ref = ref[:atIdx]
	}
	lastSlash := strings.LastIndexByte(ref, '/')
	lastColon := strings.LastIndexByte(ref, ':')
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, ""
}

func inferSAPIFromImageRef(lowerRepo, tag string) inventory.SAPI {
	lowerTag := strings.ToLower(tag)
	switch {
	case strings.Contains(lowerRepo, "frankenphp") || strings.Contains(lowerTag, "frankenphp"):
		return inventory.SAPIFrankenPHP
	case strings.Contains(lowerRepo, "php-fpm") || strings.Contains(lowerTag, "fpm"):
		return inventory.SAPIFPM
	case strings.Contains(lowerTag, "apache"):
		return inventory.SAPIApache2Handler
	case strings.Contains(lowerTag, "cli"):
		return inventory.SAPICLI
	case strings.Contains(lowerTag, "zts"):
		return inventory.SAPICLI
	default:
		return inventory.SAPIUnknown
	}
}

func extractContainerPHPVersion(imageRef, lowerRepo, tag string) string {
	// Digest-only or untagged references cannot prove a version without scanning the resolved image.
	if strings.Contains(imageRef, "@sha256:") && tag == "" {
		return imageRef
	}
	if tag == "" {
		return imageRef
	}

	if strings.Contains(lowerRepo, "frankenphp") {
		if m := frankenPHPVerRe.FindStringSubmatch(tag); len(m) == 2 {
			if _, err := phpver.Parse(m[1]); err == nil {
				return m[1]
			}
		}
		return imageRef
	}

	if m := exactSemverRe.FindStringSubmatch(tag); len(m) == 2 {
		if _, err := phpver.Parse(m[1]); err == nil {
			return m[1]
		}
	}

	// Floating tag (e.g. php:8.3-fpm, php:8.3, php:latest): return raw imageRef so match reports UNKNOWN.
	return imageRef
}

type composerManifest struct {
	Require map[string]string `json:"require"`
	Config  struct {
		Platform map[string]string `json:"platform"`
	} `json:"config"`
}

func parseComposerBytes(data []byte, displayPath string) []inventory.PHPInstall {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var manifest composerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	var installs []inventory.PHPInstall

	if reqPHP, ok := manifest.Require["php"]; ok && strings.TrimSpace(reqPHP) != "" {
		lineNum := findJSONKeyValueLine(lines, "php", reqPHP, 1)
		evLoc := fmt.Sprintf("%s:%d", displayPath, lineNum)
		ver := normalizeManifestVersion(reqPHP)
		installs = append(installs, inventory.PHPInstall{
			ID:              fmt.Sprintf("path:%s:%d:require.php", displayPath, lineNum),
			BinaryPath:      evLoc,
			UpstreamVersion: ver,
			PackageManager:  "composer",
			PackageName:     "php",
			SAPI:            inventory.SAPIUnknown,
			Source:          inventory.SourcePath,
			Confidence:      inventory.ConfidenceMedium,
			Evidence: []string{
				fmt.Sprintf("%s -> require.php = %s", evLoc, strings.TrimSpace(reqPHP)),
			},
		})
	}

	if platPHP, ok := manifest.Config.Platform["php"]; ok && strings.TrimSpace(platPHP) != "" {
		lineNum := findPlatformPHPLine(lines, platPHP)
		evLoc := fmt.Sprintf("%s:%d", displayPath, lineNum)
		ver := normalizeManifestVersion(platPHP)
		installs = append(installs, inventory.PHPInstall{
			ID:              fmt.Sprintf("path:%s:%d:config.platform.php", displayPath, lineNum),
			BinaryPath:      evLoc,
			UpstreamVersion: ver,
			PackageManager:  "composer",
			PackageName:     "php",
			SAPI:            inventory.SAPIUnknown,
			Source:          inventory.SourcePath,
			Confidence:      inventory.ConfidenceMedium,
			Evidence: []string{
				fmt.Sprintf("%s -> config.platform.php = %s", evLoc, strings.TrimSpace(platPHP)),
			},
		})
	}

	return installs
}

func findJSONKeyValueLine(lines []string, key, val string, startLine int) int {
	quotedKey := `"` + key + `"`
	for i := startLine - 1; i < len(lines); i++ {
		if strings.Contains(lines[i], quotedKey) && strings.Contains(lines[i], val) {
			return i + 1
		}
	}
	for i := startLine - 1; i < len(lines); i++ {
		if strings.Contains(lines[i], quotedKey) {
			return i + 1
		}
	}
	return 1
}

func findPlatformPHPLine(lines []string, val string) int {
	platformStart := 1
	for i, line := range lines {
		if strings.Contains(line, `"platform"`) {
			platformStart = i + 1
			break
		}
	}
	return findJSONKeyValueLine(lines, "php", val, platformStart)
}

func parsePHPVersionFileBytes(data []byte, displayPath string) []inventory.PHPInstall {
	lines := strings.Split(string(data), "\n")
	for idx, rawLine := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		evLoc := fmt.Sprintf("%s:%d", displayPath, lineNum)
		ver := normalizeManifestVersion(trimmed)
		return []inventory.PHPInstall{
			{
				ID:              fmt.Sprintf("path:%s:%d", displayPath, lineNum),
				BinaryPath:      evLoc,
				UpstreamVersion: ver,
				SAPI:            inventory.SAPICLI,
				Source:          inventory.SourcePath,
				Confidence:      inventory.ConfidenceMedium,
				Evidence: []string{
					fmt.Sprintf("%s -> .php-version = %s", evLoc, trimmed),
				},
			},
		}
	}
	return nil
}

func parseToolVersionsBytes(data []byte, displayPath string) []inventory.PHPInstall {
	lines := strings.Split(string(data), "\n")
	var installs []inventory.PHPInstall

	for idx, rawLine := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idxHash := strings.IndexByte(trimmed, '#'); idxHash >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idxHash])
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || fields[0] != "php" {
			continue
		}
		rawVer := fields[1]
		if strings.EqualFold(rawVer, "system") {
			continue
		}
		evLoc := fmt.Sprintf("%s:%d", displayPath, lineNum)
		ver := normalizeManifestVersion(rawVer)
		installs = append(installs, inventory.PHPInstall{
			ID:              fmt.Sprintf("path:%s:%d", displayPath, lineNum),
			BinaryPath:      evLoc,
			UpstreamVersion: ver,
			SAPI:            inventory.SAPICLI,
			Source:          inventory.SourcePath,
			Confidence:      inventory.ConfidenceMedium,
			Evidence: []string{
				fmt.Sprintf("%s -> .tool-versions php %s", evLoc, rawVer),
			},
		})
	}
	return installs
}

// normalizeManifestVersion returns a clean exact version if raw is an exact X.Y.Z PHP version,
// or returns raw unchanged if it is a constraint (^8.2, ~8.3.0, >=8.2) or floating branch (8.3).
func normalizeManifestVersion(raw string) string {
	trimmed := strings.TrimSpace(raw)
	// Do not strip constraint operators (^, ~, >, <, =, *, |, spaces).
	if strings.ContainsAny(trimmed, "^~><=*| ") {
		return trimmed
	}
	cleaned := strings.TrimPrefix(strings.TrimPrefix(trimmed, "php-"), "v")
	if v, err := phpver.Parse(cleaned); err == nil && v.DistroSuffix == "" {
		return cleaned
	}
	return trimmed
}
