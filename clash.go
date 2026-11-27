package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/EEvanescence/4Diana/internal/converter"
	"github.com/EEvanescence/4Diana/internal/tester"
)

// Clash (Meta) output.
//
// Clash.yaml is a complete, ready-to-import Clash Meta configuration:
// the live-tested proxies plus a single url-test group that health-checks
// them and routes everything through the fastest one. There are no
// routing rules beyond the final MATCH — the point is a clean config the
// client can auto-select from, not a rule set.
//
// Only vmess, vless, trojan and hysteria2 are converted. Shadowsocks,
// WireGuard/WARP and configs fronted by Cloudflare IPs are deliberately
// left out (they are the weakest of the set in practice), as are
// transports Clash Meta cannot speak (kcp, quic, vless encryption).

const (
	clashFileName   = "Clash.yaml"
	clashGroupName  = "Rose Auto"
	clashTestURL    = "http://www.gstatic.com/generate_204"
	clashInterval   = 300 // seconds between url-test rounds
	clashTolerance  = 50  // ms of hysteresis before switching proxies
	clashMaxProxies = 500 // fastest (by live-test delay) proxies kept
)

// clashKV is one ordered key/value pair of a Clash proxy mapping. The
// value is a string, int, bool, []string, or []clashKV for a nested map.
type clashKV struct {
	k string
	v any
}

type clashEntry struct {
	name   string
	delay  int
	fields []clashKV
}

type clashStats struct {
	Included       int
	SkippedProto   int
	SkippedCF      int
	SkippedConvert int
	Capped         int
}

func writeClashFile(results []tester.Result, named []string) {
	content, stats := buildClashYAML(results, named, loadCloudflareRanges())
	if stats.Included == 0 {
		fmt.Println("  clash: no convertible configs, skipping Clash.yaml")
		return
	}
	if err := os.WriteFile(clashFileName, []byte(content), 0644); err != nil {
		fmt.Printf("Error writing clash file: %v\n", err)
		return
	}
	fmt.Printf("  clash: %d proxies in %s (skipped: %d protocol, %d cloudflare, %d unconvertible, %d over cap)\n",
		stats.Included, clashFileName, stats.SkippedProto, stats.SkippedCF, stats.SkippedConvert, stats.Capped)
}

// buildClashYAML converts the live-tested results (zipped with their
// standardized-name lines, same order) into a Clash Meta config.
func buildClashYAML(results []tester.Result, named []string, cfRanges []*net.IPNet) (string, clashStats) {
	var stats clashStats
	var entries []clashEntry

	n := len(results)
	if len(named) < n {
		n = len(named)
	}
	for i := 0; i < n; i++ {
		line := named[i]
		proto := protocolOf(line)
		switch proto {
		case "vmess", "vless", "trojan", "hy2", "hysteria2":
		default:
			stats.SkippedProto++
			continue
		}

		if len(cfRanges) > 0 {
			host, _ := getHostPort(line, proto)
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ipInRanges(ip, cfRanges) {
				stats.SkippedCF++
				continue
			}
		}

		fields, err := clashFields(line, proto)
		if err != nil {
			stats.SkippedConvert++
			continue
		}
		entries = append(entries, clashEntry{
			name:   clashName(line, proto, i+1),
			delay:  results[i].DelayMs,
			fields: fields,
		})
	}

	// Fastest first, so the cap keeps the best of the set. The url-test
	// group re-measures locally on the client anyway; this only chooses
	// which proxies make the cut.
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].delay < entries[b].delay })
	if len(entries) > clashMaxProxies {
		stats.Capped = len(entries) - clashMaxProxies
		entries = entries[:clashMaxProxies]
	}

	// Clash requires unique proxy names.
	seen := make(map[string]int, len(entries))
	for i := range entries {
		name := entries[i].name
		if count, dup := seen[name]; dup {
			seen[name] = count + 1
			entries[i].name = fmt.Sprintf("%s (%d)", name, count+1)
		} else {
			seen[name] = 1
		}
	}
	stats.Included = len(entries)

	var b strings.Builder
	b.WriteString("# Rose — Clash Meta configuration (auto-generated, do not edit)\n")
	b.WriteString("# Live-tested proxies with a single url-test group: the client\n")
	b.WriteString("# health-checks them and uses the fastest. No routing rules\n")
	b.WriteString("# beyond the final MATCH.\n\n")
	b.WriteString("mixed-port: 7890\n")
	b.WriteString("allow-lan: true\n")
	b.WriteString("mode: rule\n")
	b.WriteString("log-level: warning\n")
	b.WriteString("ipv6: true\n\n")

	b.WriteString("proxies:\n")
	for _, e := range entries {
		writeClashProxy(&b, e)
	}

	b.WriteString("\nproxy-groups:\n")
	b.WriteString("  - name: " + yamlQuote(clashGroupName) + "\n")
	b.WriteString("    type: url-test\n")
	b.WriteString("    proxies:\n")
	for _, e := range entries {
		b.WriteString("      - " + yamlQuote(e.name) + "\n")
	}
	b.WriteString("    url: " + yamlQuote(clashTestURL) + "\n")
	fmt.Fprintf(&b, "    interval: %d\n", clashInterval)
	fmt.Fprintf(&b, "    tolerance: %d\n", clashTolerance)
	b.WriteString("    lazy: true\n")

	b.WriteString("\nrules:\n")
	b.WriteString("  - MATCH," + clashGroupName + "\n")
	return b.String(), stats
}

func ipInRanges(ip net.IP, ranges []*net.IPNet) bool {
	for _, r := range ranges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// clashName extracts the standardized display name from a named line:
// the vmess "ps" field, or the URL fragment for the other protocols.
func clashName(line, proto string, index int) string {
	fallback := fmt.Sprintf("Rose | %s | %d", strings.ToUpper(proto), index)
	if proto == "vmess" {
		decoded, err := decodeBase64([]byte(strings.TrimPrefix(line, "vmess://")))
		if err != nil {
			return fallback
		}
		var data map[string]any
		if err := json.Unmarshal([]byte(decoded), &data); err != nil {
			return fallback
		}
		if ps, _ := data["ps"].(string); strings.TrimSpace(ps) != "" {
			return ps
		}
		return fallback
	}
	hi := strings.Index(line, "#")
	if hi < 0 || hi == len(line)-1 {
		return fallback
	}
	name, err := url.PathUnescape(line[hi+1:])
	if err != nil || strings.TrimSpace(name) == "" {
		return fallback
	}
	return name
}

// clashFields converts one named link into Clash proxy fields (without
// the name, which the caller supplies).
func clashFields(line, proto string) ([]clashKV, error) {
	switch proto {
	case "vmess":
		return clashVMess(line)
	case "vless":
		return clashVLESS(line)
	case "trojan":
		return clashTrojan(line)
	case "hy2", "hysteria2":
		return clashHy2(line)
	}
	return nil, fmt.Errorf("unsupported protocol %q", proto)
}

func clashVMess(line string) ([]clashKV, error) {
	decoded, err := decodeBase64([]byte(strings.TrimPrefix(line, "vmess://")))
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(decoded), &d); err != nil {
		return nil, err
	}

	addr := jsonStr(d, "add")
	id := jsonStr(d, "id")
	port, err := jsonPort(d, "port")
	if addr == "" || id == "" || err != nil {
		return nil, fmt.Errorf("vmess missing add/id/port")
	}
	aid, _ := jsonPort(d, "aid") // missing aid means 0
	cipher := jsonStr(d, "scy")
	if cipher == "" {
		cipher = jsonStr(d, "security")
	}
	cipher = clashVMessCipher(cipher)
	network := strings.ToLower(jsonStr(d, "net"))
	if network == "" {
		network = "tcp"
	}
	host := jsonStr(d, "host")
	path := jsonStr(d, "path")

	fields := []clashKV{
		{"type", "vmess"},
		{"server", addr},
		{"port", port},
		{"uuid", id},
		{"alterId", aid},
		{"cipher", cipher},
		{"udp", true},
	}
	if strings.EqualFold(jsonStr(d, "tls"), "tls") {
		fields = append(fields, clashKV{"tls", true})
		sni := jsonStr(d, "sni")
		if sni == "" {
			sni = host
		}
		if sni != "" {
			fields = append(fields, clashKV{"servername", sni})
		}
		if v := jsonStr(d, "alpn"); v != "" {
			fields = append(fields, clashKV{"alpn", splitCSV(v)})
		}
		if v := jsonStr(d, "fp"); v != "" {
			fields = append(fields, clashKV{"client-fingerprint", v})
		}
	}

	switch network {
	case "tcp", "raw":
		// Plain TCP; Clash's default. HTTP header obfuscation (type=http)
		// is not converted.
	case "ws", "websocket":
		fields = append(fields, clashKV{"network", "ws"})
		ws := []clashKV{}
		if path != "" {
			ws = append(ws, clashKV{"path", path})
		}
		if host != "" {
			ws = append(ws, clashKV{"headers", []clashKV{{"Host", host}}})
		}
		if len(ws) > 0 {
			fields = append(fields, clashKV{"ws-opts", ws})
		}
	case "grpc":
		fields = append(fields, clashKV{"network", "grpc"})
		if path != "" {
			fields = append(fields, clashKV{"grpc-opts", []clashKV{{"grpc-service-name", path}}})
		}
	case "h2", "http":
		fields = append(fields, clashKV{"network", "h2"})
		h2 := []clashKV{}
		if host != "" {
			h2 = append(h2, clashKV{"host", splitCSV(host)})
		}
		if path != "" {
			h2 = append(h2, clashKV{"path", path})
		}
		if len(h2) > 0 {
			fields = append(fields, clashKV{"h2-opts", h2})
		}
	case "xhttp", "splithttp":
		fields = append(fields, clashKV{"network", "xhttp"})
		x := []clashKV{}
		if path != "" {
			x = append(x, clashKV{"path", path})
		}
		if host != "" {
			x = append(x, clashKV{"host", host})
		}
		if v := jsonStr(d, "mode"); v != "" {
			x = append(x, clashKV{"mode", v})
		}
		if len(x) > 0 {
			fields = append(fields, clashKV{"xhttp-opts", x})
		}
	default:
		return nil, fmt.Errorf("vmess network %q not supported by Clash", network)
	}
	return fields, nil
}

func clashVLESS(line string) ([]clashKV, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	port, err := clashPort(u.Port())
	if err != nil {
		return nil, err
	}
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if uuid == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("vless missing uuid/host")
	}
	if enc := params.Get("encryption"); enc != "" && enc != "none" {
		return nil, fmt.Errorf("vless encryption not supported by Clash")
	}

	fields := []clashKV{
		{"type", "vless"},
		{"server", u.Hostname()},
		{"port", port},
		{"uuid", uuid},
		{"udp", true},
	}
	if flow := params.Get("flow"); flow != "" {
		fields = append(fields, clashKV{"flow", flow})
	}

	security := strings.ToLower(params.Get("security"))
	switch security {
	case "tls", "reality":
		fields = append(fields, clashKV{"tls", true})
		if v := params.Get("sni"); v != "" {
			fields = append(fields, clashKV{"servername", v})
		}
		if v := params.Get("fp"); v != "" {
			fields = append(fields, clashKV{"client-fingerprint", v})
		}
		if v := params.Get("alpn"); v != "" {
			fields = append(fields, clashKV{"alpn", splitCSV(v)})
		}
		if clashInsecure(params) {
			fields = append(fields, clashKV{"skip-cert-verify", true})
		}
		if security == "reality" {
			ro := []clashKV{}
			if v := params.Get("pbk"); v != "" {
				ro = append(ro, clashKV{"public-key", v})
			}
			if v := params.Get("sid"); v != "" {
				ro = append(ro, clashKV{"short-id", v})
			}
			if len(ro) == 0 {
				return nil, fmt.Errorf("reality without public-key")
			}
			fields = append(fields, clashKV{"reality-opts", ro})
		}
	case "", "none":
	default:
		return nil, fmt.Errorf("vless security %q not supported by Clash", security)
	}

	network := strings.ToLower(params.Get("type"))
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "tcp", "raw":
	case "ws", "websocket":
		fields = append(fields, clashKV{"network", "ws"})
		ws := []clashKV{}
		if v := params.Get("path"); v != "" {
			ws = append(ws, clashKV{"path", unescape(v)})
		}
		if v := params.Get("host"); v != "" {
			ws = append(ws, clashKV{"headers", []clashKV{{"Host", v}}})
		}
		if len(ws) > 0 {
			fields = append(fields, clashKV{"ws-opts", ws})
		}
	case "grpc":
		fields = append(fields, clashKV{"network", "grpc"})
		if v := params.Get("serviceName"); v != "" {
			fields = append(fields, clashKV{"grpc-opts", []clashKV{{"grpc-service-name", v}}})
		}
	case "xhttp", "splithttp":
		fields = append(fields, clashKV{"network", "xhttp"})
		x := []clashKV{}
		if v := params.Get("path"); v != "" {
			x = append(x, clashKV{"path", unescape(v)})
		}
		if v := params.Get("host"); v != "" {
			x = append(x, clashKV{"host", v})
		}
		if v := params.Get("mode"); v != "" {
			x = append(x, clashKV{"mode", v})
		}
		if len(x) > 0 {
			fields = append(fields, clashKV{"xhttp-opts", x})
		}
	case "httpupgrade":
		fields = append(fields, clashKV{"network", "ws"})
		ws := []clashKV{{"v2ray-http-upgrade", true}}
		if v := params.Get("path"); v != "" {
			ws = append(ws, clashKV{"path", unescape(v)})
		}
		if v := params.Get("host"); v != "" {
			ws = append(ws, clashKV{"headers", []clashKV{{"Host", v}}})
		}
		fields = append(fields, clashKV{"ws-opts", ws})
	default:
		return nil, fmt.Errorf("vless network %q not supported by Clash", network)
	}
	return fields, nil
}

func clashTrojan(line string) ([]clashKV, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	port, err := clashPort(u.Port())
	if err != nil {
		return nil, err
	}
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("trojan missing password/host")
	}

	fields := []clashKV{
		{"type", "trojan"},
		{"server", u.Hostname()},
		{"port", port},
		{"password", password},
		{"udp", true},
	}
	sni := params.Get("sni")
	if sni == "" {
		sni = params.Get("peer")
	}
	if sni != "" {
		fields = append(fields, clashKV{"sni", sni})
	}
	if clashInsecure(params) {
		fields = append(fields, clashKV{"skip-cert-verify", true})
	}
	if v := params.Get("alpn"); v != "" {
		fields = append(fields, clashKV{"alpn", splitCSV(v)})
	}
	if v := params.Get("fp"); v != "" {
		fields = append(fields, clashKV{"client-fingerprint", v})
	}

	network := strings.ToLower(params.Get("type"))
	switch network {
	case "", "tcp", "raw":
	case "ws", "websocket":
		fields = append(fields, clashKV{"network", "ws"})
		ws := []clashKV{}
		if v := params.Get("path"); v != "" {
			ws = append(ws, clashKV{"path", unescape(v)})
		}
		if v := params.Get("host"); v != "" {
			ws = append(ws, clashKV{"headers", []clashKV{{"Host", v}}})
		}
		if len(ws) > 0 {
			fields = append(fields, clashKV{"ws-opts", ws})
		}
	case "grpc":
		fields = append(fields, clashKV{"network", "grpc"})
		if v := params.Get("serviceName"); v != "" {
			fields = append(fields, clashKV{"grpc-opts", []clashKV{{"grpc-service-name", v}}})
		}
	default:
		return nil, fmt.Errorf("trojan network %q not supported by Clash", network)
	}
	return fields, nil
}

func clashHy2(line string) ([]clashKV, error) {
	cfg, err := converter.ParseHy2(line)
	if err != nil {
		return nil, err
	}
	fields := []clashKV{
		{"type", "hysteria2"},
		{"server", cfg.Host},
	}
	if cfg.Ports != "" {
		fields = append(fields, clashKV{"ports", cfg.Ports})
	} else {
		fields = append(fields, clashKV{"port", cfg.Port})
	}
	fields = append(fields, clashKV{"password", cfg.Auth})
	if cfg.SNI != "" {
		fields = append(fields, clashKV{"sni", cfg.SNI})
	}
	if cfg.Insecure {
		fields = append(fields, clashKV{"skip-cert-verify", true})
	}
	if cfg.ObfsType != "" {
		fields = append(fields, clashKV{"obfs", cfg.ObfsType})
		fields = append(fields, clashKV{"obfs-password", cfg.ObfsPassword})
	}
	if cfg.PinSHA256 != "" {
		fields = append(fields, clashKV{"fingerprint", cfg.PinSHA256})
	}
	if cfg.ALPN != "" {
		fields = append(fields, clashKV{"alpn", splitCSV(cfg.ALPN)})
	}
	if cfg.Up != "" {
		fields = append(fields, clashKV{"up", clashBandwidth(cfg.Up)})
	}
	if cfg.Down != "" {
		fields = append(fields, clashKV{"down", clashBandwidth(cfg.Down)})
	}
	if cfg.HopInterval != "" {
		if secs, err := strconv.Atoi(cfg.HopInterval); err == nil && secs > 0 {
			fields = append(fields, clashKV{"hop-interval", secs})
		}
	}
	return fields, nil
}

// clashBandwidth normalizes a bare Mbps number to Clash's "N Mbps" form.
func clashBandwidth(v string) string {
	if _, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		return strings.TrimSpace(v) + " Mbps"
	}
	return v
}

func clashInsecure(params url.Values) bool {
	for _, key := range []string{"insecure", "allowInsecure", "allow_insecure", "allow-insecure", "allowinsecure", "skip-cert-verify", "skipCertVerify", "skip_cert_verify", "skipcertverify", "noverify"} {
		switch strings.ToLower(strings.TrimSpace(params.Get(key))) {
		case "1", "true", "yes", "y", "t", "on":
			return true
		}
	}
	return false
}

func clashPort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

func jsonStr(d map[string]any, key string) string {
	v, _ := d[key].(string)
	// Some VMess generators serialize unset fields as the literal string
	// "null" instead of omitting them or using JSON null. Treat it as
	// empty everywhere, or it leaks into the Clash config (e.g. a cipher
	// of "null", which Clash Meta rejects on import).
	if strings.EqualFold(strings.TrimSpace(v), "null") {
		return ""
	}
	return v
}

// clashVMessCipher normalizes a VMess cipher to the set Clash Meta
// accepts; anything else (including "null" and "") becomes "auto", the
// same fallback Xray uses for an unset cipher.
func clashVMessCipher(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
		return strings.ToLower(strings.TrimSpace(c))
	}
	return "auto"
}

func jsonPort(d map[string]any, key string) (int, error) {
	switch v := d[key].(type) {
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(v))
	}
	return 0, fmt.Errorf("missing %s", key)
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func unescape(v string) string {
	if u, err := url.QueryUnescape(v); err == nil {
		return u
	}
	return v
}

// --- minimal ordered YAML emission -------------------------------------
//
// The config is emitted by hand instead of with a YAML library so the
// output stays deterministic (stable key order, stable quoting) and no
// new dependency is needed. All strings are double-quoted; control
// characters are stripped because YAML double-quoted scalars cannot
// carry them in Go's escape spelling.

func yamlQuote(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strconv.Quote(cleaned)
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case string:
		return yamlQuote(t)
	case int:
		return strconv.Itoa(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []string:
		parts := make([]string, len(t))
		for i, s := range t {
			parts[i] = yamlQuote(s)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return yamlQuote(fmt.Sprint(v))
}

func writeClashProxy(b *strings.Builder, e clashEntry) {
	b.WriteString("  - name: " + yamlQuote(e.name) + "\n")
	writeClashKVs(b, "    ", e.fields)
}

func writeClashKVs(b *strings.Builder, indent string, kvs []clashKV) {
	for _, kv := range kvs {
		if nested, ok := kv.v.([]clashKV); ok {
			b.WriteString(indent + kv.k + ":\n")
			writeClashKVs(b, indent+"  ", nested)
			continue
		}
		b.WriteString(indent + kv.k + ": " + yamlScalar(kv.v) + "\n")
	}
}
