package tester

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	xserial "github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/EEvanescence/4Diana/internal/converter"
)

type Result struct {
	Link    string
	DelayMs int
	ExitIP string
}

const (
	exitIPURL     = "http://www.cloudflare.com/cdn-cgi/trace"
	exitIPTimeout = 4 * time.Second

	// wgSettleDelay is how long a WireGuard test waits after cancelling the
	// request and closing its connections before closing the Xray instance.
	// xray-core v1.260327.0's wireguard netBind.Close() is not idempotent
	// (it closes a channel without a guard), and the dispatch goroutine
	// closes the bind again on its error path; closing the instance while
	// that goroutine is still tearing down panics the whole run with
	// "close of closed channel". The settle delay lets the goroutine
	// finish first. It only applies to WireGuard tests.
	wgSettleDelay = 300 * time.Millisecond

	// wgDNSResolveTimeout bounds the endpoint pre-resolution below.
	wgDNSResolveTimeout = 3 * time.Second
)

// isWGLink reports whether the link uses the WireGuard outbound.
func isWGLink(link string) bool {
	return strings.HasPrefix(link, "wireguard://") || strings.HasPrefix(link, "warp://")
}

// wgConcurrency caps how many WireGuard instances may be tested at once.
// Each WG test builds a full netstack device, and hundreds of them at
// once (the general worker pool defaults to 400) exhaust file
// descriptors and DNS capacity, which makes xray-core's device setup
// fail — the exact path that double-closes the bind and panics.
// Override with ROSE_WG_CONCURRENCY.
func wgConcurrency() int {
	if v := os.Getenv("ROSE_WG_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return 4
}

// wgEndpointResolvable pre-resolves a WireGuard peer endpoint host.
// Configs whose endpoint does not resolve would fail inside xray-core's
// device setup, whose error path double-closes the bind and panics the
// whole process (see wgSettleDelay). Failing them here keeps that buggy
// path unreachable; the outcome is the same failed test.
func wgEndpointResolvable(ctx context.Context, link string) bool {
	cfg, err := converter.ParseWG(link)
	if err != nil {
		return false
	}
	if net.ParseIP(cfg.Host) != nil {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, wgDNSResolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, cfg.Host)
	return err == nil && len(addrs) > 0
}

func TestAll(ctx context.Context, links []string, testURL string, timeoutSec, concurrent int, onPass func(Result)) []Result {
	timeout := time.Duration(timeoutSec) * time.Second

	results := make([]Result, len(links))
	for i, l := range links {
		results[i] = Result{Link: l, DelayMs: -1}
	}

	sem := make(chan struct{}, concurrent)
	wgSem := make(chan struct{}, wgConcurrency())
	var wg sync.WaitGroup
	var done, working atomic.Int64
	total := int64(len(links))

	log.Printf("Testing %d config(s) with %d concurrent workers...", total, concurrent)

	for i, link := range links {
		if ctx.Err() != nil {
			log.Printf("  Cancelled: stopping after %d/%d tested, %d working",
				done.Load(), total, working.Load())
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, l string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results[idx].DelayMs = -1
				}
			}()

			if isWGLink(l) {
				wgSem <- struct{}{}
				defer func() { <-wgSem }()
			}

			delay, exitIP := testOne(ctx, l, testURL, timeout)
			results[idx].DelayMs = delay
			results[idx].ExitIP = exitIP

			d := done.Add(1)
			if delay >= 0 {
				working.Add(1)
				if onPass != nil {
					onPass(results[idx])
				}
			}
			if d%500 == 0 || d == total {
				log.Printf("  Progress: %d/%d tested, %d working", d, total, working.Load())
			}
		}(i, link)
	}

	wg.Wait()
	return results
}

func testOne(ctx context.Context, link, testURL string, timeout time.Duration) (int, string) {
	isWG := isWGLink(link)
	if isWG && !wgEndpointResolvable(ctx, link) {
		return -1, ""
	}

	outbound, err := converter.ConvertLink(link)
	if err != nil {
		return -1, ""
	}

	fullConfig := converter.M{
		"log": converter.M{"loglevel": "none"},
		"outbounds": []converter.M{
			outbound,
			{"protocol": "freedom", "tag": "direct"},
		},
	}

	jsonBytes, err := json.Marshal(fullConfig)
	if err != nil {
		return -1, ""
	}

	cfg, err := xserial.LoadJSONConfig(bytes.NewReader(jsonBytes))
	if err != nil {
		return -1, ""
	}

	instance, err := xcore.New(cfg)
	if err != nil {
		return -1, ""
	}
	if err := instance.Start(); err != nil {
		return -1, ""
	}

	var (
		cancel  context.CancelFunc
		client  *http.Client
		connsMu sync.Mutex
		conns   []net.Conn
	)

	// shutdown tears the instance down in an order that keeps xray-core's
	// WireGuard handler from double-closing its bind (see wgSettleDelay):
	// cancel the request, close every dialed connection, give the
	// dispatch goroutine a moment to finish, then close the instance.
	// The recover guards this goroutine's own close path; the settle
	// delay is what protects the dispatch goroutine, which no recover
	// here could catch.
	shutdown := func() {
		if cancel != nil {
			cancel()
		}
		if client != nil {
			client.CloseIdleConnections()
		}
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
		if isWG {
			time.Sleep(wgSettleDelay)
		}
		func() {
			defer func() { _ = recover() }()
			_ = instance.Close()
		}()
	}
	defer shutdown()

	dialer := func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := net.LookupPort(network, portStr)
		if err != nil {
			return nil, err
		}
		dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
		conn, err := xcore.Dial(dialCtx, instance, dest)
		if err == nil {
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
		}
		return conn, err
	}

	client = &http.Client{
		Transport: &http.Transport{
			DialContext:       dialer,
			DisableKeepAlives: true,
		},
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqCtx, cancelFn := context.WithTimeout(ctx, timeout)
	cancel = cancelFn

	req, err := http.NewRequestWithContext(reqCtx, "GET", testURL, nil)
	if err != nil {
		return -1, ""
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, ""
	}
	defer resp.Body.Close()
	delay := int(time.Since(start).Milliseconds())

	// Drain the body so the transport finishes with the connection
	// deterministically instead of leaving the dispatch goroutine
	// mid-teardown when the instance closes.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return delay, fetchExitIP(ctx, client)
	}
	return -1, ""
}

func fetchExitIP(ctx context.Context, client *http.Client) string {
	ctx, cancel := context.WithTimeout(ctx, exitIPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", exitIPURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
				return ip.String()
			}
			return ""
		}
	}
	return ""
}
