package remote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

const (
	// DefaultTimeout is the per-target HTTP request timeout.
	DefaultTimeout = 5 * time.Second
	// DefaultMinInterval is the default rate-limit delay between consecutive remote targets.
	DefaultMinInterval = 200 * time.Millisecond
	// BannerCaveatLabel is the required label noting that remote HTTP banners are low-confidence.
	BannerCaveatLabel = "banner, may be hidden or spoofed"
)

var (
	// ErrUnauthorized is returned when remote scanning is invoked without --authorized.
	ErrUnauthorized = errors.New("remote scan requires explicit --authorized flag")
	// ErrNoTargets is returned when no target URLs are provided.
	ErrNoTargets = errors.New("remote scan requires at least one explicit target URL")

	phpBannerRe = regexp.MustCompile(`(?i)\bPHP/([^\s,;()]+)`)
)

// Options configures passive remote HTTP header inspection.
type Options struct {
	Authorized  bool
	Targets     []string
	Timeout     time.Duration
	MinInterval time.Duration
	Transport   http.RoundTripper
}

// Collector performs passive, header-only remote checks gated by explicit authorization.
type Collector struct {
	opts Options
}

// NewCollector creates a passive remote Collector with the given options.
func NewCollector(opts Options) *Collector {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MinInterval < 0 {
		opts.MinInterval = 0
	} else if opts.MinInterval == 0 {
		opts.MinInterval = DefaultMinInterval
	}
	return &Collector{opts: opts}
}

// Collect sends one passive GET request per target (no query parameters, no request body,
// same-host redirects only, rate-limited across targets) and reads only Server and X-Powered-By headers.
func (c *Collector) Collect(ctx context.Context) ([]inventory.PHPInstall, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !c.opts.Authorized {
		return nil, ErrUnauthorized
	}

	cleanedTargets, err := normalizeTargets(c.opts.Targets)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout:   c.opts.Timeout,
		Transport: c.opts.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			// Same-host redirects only.
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return http.ErrUseLastResponse
			}
			// Never send query parameters even if redirect Location contained them.
			req.URL.RawQuery = ""
			req.URL.ForceQuery = false
			return nil
		},
	}

	installs := make([]inventory.PHPInstall, 0, len(cleanedTargets))
	for i, targetURL := range cleanedTargets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i > 0 && c.opts.MinInterval > 0 {
			timer := time.NewTimer(c.opts.MinInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		inst, reqErr := c.inspectTarget(ctx, client, targetURL)
		if reqErr != nil {
			return nil, reqErr
		}
		installs = append(installs, inst)
	}

	return installs, nil
}

func normalizeTargets(rawTargets []string) ([]string, error) {
	var out []string
	for _, raw := range rawTargets {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid target URL %q: %w", trimmed, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if (scheme != "http" && scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("target URL %q must include http:// or https:// and a host", trimmed)
		}
		// Strip query parameters and fragments per passive safety rules.
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		out = append(out, u.String())
	}
	if len(out) == 0 {
		return nil, ErrNoTargets
	}
	return out, nil
}

func (c *Collector) inspectTarget(ctx context.Context, client *http.Client, targetURL string) (inventory.PHPInstall, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return inventory.PHPInstall{}, fmt.Errorf("build request for %q: %w", targetURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return inventory.PHPInstall{}, fmt.Errorf("request target %q: %w", targetURL, err)
	}
	// Close body immediately; remote inspection is strictly headers-only.
	_ = resp.Body.Close()

	serverHdr := strings.TrimSpace(resp.Header.Get("Server"))
	poweredByHdr := strings.TrimSpace(resp.Header.Get("X-Powered-By"))

	version := extractBannerPHPVersion(poweredByHdr)
	if version == "" {
		version = extractBannerPHPVersion(serverHdr)
	}

	sapi := inferSAPIFromServerHeader(serverHdr)
	evidence := buildBannerEvidence(serverHdr, poweredByHdr)

	return inventory.PHPInstall{
		ID:              "remote:" + targetURL,
		BinaryPath:      targetURL,
		UpstreamVersion: version,
		SAPI:            sapi,
		Source:          inventory.SourceRemote,
		Confidence:      inventory.ConfidenceLow,
		Evidence:        evidence,
	}, nil
}

func extractBannerPHPVersion(hdr string) string {
	if hdr == "" {
		return ""
	}
	m := phpBannerRe.FindStringSubmatch(hdr)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func inferSAPIFromServerHeader(serverHdr string) inventory.SAPI {
	lower := strings.ToLower(serverHdr)
	switch {
	case strings.Contains(lower, "frankenphp"):
		return inventory.SAPIFrankenPHP
	case strings.Contains(lower, "litespeed"):
		return inventory.SAPILiteSpeed
	case strings.Contains(lower, "apache"):
		return inventory.SAPIApache2Handler
	default:
		return inventory.SAPIUnknown
	}
}

func buildBannerEvidence(serverHdr, poweredByHdr string) []string {
	var ev []string
	if poweredByHdr != "" {
		ev = append(ev, fmt.Sprintf("X-Powered-By: %s (%s)", poweredByHdr, BannerCaveatLabel))
	}
	if serverHdr != "" {
		ev = append(ev, fmt.Sprintf("Server: %s (%s)", serverHdr, BannerCaveatLabel))
	}
	if len(ev) == 0 {
		ev = append(ev, fmt.Sprintf("no Server or X-Powered-By PHP banner exposed (%s)", BannerCaveatLabel))
	}
	return ev
}
