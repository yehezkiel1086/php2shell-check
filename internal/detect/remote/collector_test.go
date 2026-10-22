package remote

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

func TestCollectRequiresAuthorizationAndTargets(t *testing.T) {
	t.Parallel()

	col := NewCollector(Options{
		Authorized: false,
		Targets:    []string{"https://example.com"},
	})
	if _, err := col.Collect(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Collect without Authorized error = %v, want %v", err, ErrUnauthorized)
	}

	colNoTargets := NewCollector(Options{
		Authorized: true,
		Targets:    nil,
	})
	if _, err := colNoTargets.Collect(context.Background()); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("Collect without Targets error = %v, want %v", err, ErrNoTargets)
	}
}

func TestCollectSinglePassiveGETNoBodyNoPayloadHeaders(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	var gotMethod string
	var gotRawQuery string
	var gotBodyLen int
	var gotHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		gotMethod = r.Method
		gotRawQuery = r.URL.RawQuery
		bodyBytes, _ := io.ReadAll(r.Body)
		gotBodyLen = len(bodyBytes)
		gotHeaders = r.Header.Clone()

		w.Header().Set("Server", "Apache/2.4.58 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Header().Set("X-Ignored-Custom", "PHP/7.4.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>body should be ignored</html>"))
	}))
	defer srv.Close()

	// Include query params and fragment in input to verify they are stripped before sending.
	col := NewCollector(Options{
		Authorized:  true,
		Targets:     []string{srv.URL + "/index.php?foo=bar&baz=1#frag"},
		Timeout:     2 * time.Second,
		MinInterval: 1 * time.Millisecond,
	})

	installs, err := col.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect unexpected error: %v", err)
	}

	if got := requestCount.Load(); got != 1 {
		t.Fatalf("requestCount = %d, want 1", got)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("request Method = %q, want %q", gotMethod, http.MethodGet)
	}
	if gotRawQuery != "" {
		t.Errorf("request RawQuery = %q, want empty string", gotRawQuery)
	}
	if gotBodyLen != 0 {
		t.Errorf("request body length = %d, want 0", gotBodyLen)
	}

	// Assert no payload headers (only standard net/http User-Agent and Accept-Encoding are allowed).
	for k := range gotHeaders {
		lower := strings.ToLower(k)
		if lower != "user-agent" && lower != "accept-encoding" {
			t.Errorf("unexpected header sent in passive remote mode: %s: %v", k, gotHeaders[k])
		}
	}

	if len(installs) != 1 {
		t.Fatalf("len(installs) = %d, want 1", len(installs))
	}
	inst := installs[0]
	if inst.UpstreamVersion != "8.3.10" {
		t.Errorf("UpstreamVersion = %q, want %q", inst.UpstreamVersion, "8.3.10")
	}
	if inst.SAPI != inventory.SAPIApache2Handler {
		t.Errorf("SAPI = %q, want %q", inst.SAPI, inventory.SAPIApache2Handler)
	}
	if inst.Source != inventory.SourceRemote {
		t.Errorf("Source = %q, want %q", inst.Source, inventory.SourceRemote)
	}
	if inst.Confidence != inventory.ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", inst.Confidence, inventory.ConfidenceLow)
	}
	if len(inst.Evidence) == 0 || !strings.Contains(inst.Evidence[0], BannerCaveatLabel) {
		t.Errorf("Evidence = %v, want %q label", inst.Evidence, BannerCaveatLabel)
	}
}

func TestCollectSameHostRedirectOnlyAndRateLimit(t *testing.T) {
	t.Parallel()

	var crossHostHit atomic.Int32
	crossHostSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		crossHostHit.Add(1)
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer crossHostSrv.Close()

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.26.0")
		w.Header().Set("Location", crossHostSrv.URL+"/redirected")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "FrankenPHP/1.2 PHP/8.3.36")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	interval := 40 * time.Millisecond
	col := NewCollector(Options{
		Authorized:  true,
		Targets:     []string{srv1.URL, srv2.URL},
		Timeout:     2 * time.Second,
		MinInterval: interval,
	})

	start := time.Now()
	installs, err := col.Collect(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Collect unexpected error: %v", err)
	}

	if crossHostHit.Load() != 0 {
		t.Errorf("crossHostHit = %d, want 0 (cross-host redirect must not be followed)", crossHostHit.Load())
	}
	if elapsed < interval {
		t.Errorf("elapsed = %v, expected >= %v rate limit across 2 targets", elapsed, interval)
	}
	if len(installs) != 2 {
		t.Fatalf("len(installs) = %d, want 2", len(installs))
	}
	if installs[0].UpstreamVersion != "" {
		t.Errorf("installs[0].UpstreamVersion = %q, want empty (unexposed banner)", installs[0].UpstreamVersion)
	}
	if installs[1].UpstreamVersion != "8.3.36" {
		t.Errorf("installs[1].UpstreamVersion = %q, want %q", installs[1].UpstreamVersion, "8.3.36")
	}
	if installs[1].SAPI != inventory.SAPIFrankenPHP {
		t.Errorf("installs[1].SAPI = %q, want %q", installs[1].SAPI, inventory.SAPIFrankenPHP)
	}
}
