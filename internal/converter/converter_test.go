package converter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func hy2Finalmask(t *testing.T, link string) M {
	t.Helper()
	out, err := ConvertLink(link)
	if err != nil {
		t.Fatalf("ConvertLink(%q): %v", link, err)
	}
	stream, ok := out["streamSettings"].(M)
	if !ok {
		t.Fatalf("streamSettings missing in %v", out)
	}
	fm, _ := stream["finalmask"].(M)
	return fm
}

func TestHy2SalamanderAliases(t *testing.T) {
	for _, key := range []string{"obfs-password", "obfs_password", "obfsPassword", "obfs-pass"} {
		link := "hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&" + key + "=pw123"
		fm := hy2Finalmask(t, link)
		udp, ok := fm["udp"].([]M)
		if !ok || len(udp) != 1 {
			t.Fatalf("%s: finalmask.udp = %v, want one salamander entry", key, fm)
		}
		if udp[0]["type"] != "salamander" {
			t.Fatalf("%s: type = %v", key, udp[0]["type"])
		}
		settings, _ := udp[0]["settings"].(M)
		if settings["password"] != "pw123" {
			t.Fatalf("%s: password = %v", key, settings["password"])
		}
	}
}

func TestHy2ObfsWithoutPasswordIsError(t *testing.T) {
	if _, err := ConvertLink("hysteria2://secret@example.com:443?obfs=salamander"); err == nil {
		t.Fatal("expected error for salamander without password")
	}
}

func TestHy2GeckoIsExplicitError(t *testing.T) {
	if _, err := ConvertLink("hysteria2://secret@example.com:443?obfs=gecko&obfs-password=pw"); err == nil {
		t.Fatal("expected explicit error for unsupported gecko obfs")
	}
}

func TestHy2UserpassAuthPreserved(t *testing.T) {
	cfg, err := ParseHy2("hysteria2://alice:secret@example.com:443?sni=example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth != "alice:secret" {
		t.Fatalf("auth = %q, want alice:secret", cfg.Auth)
	}
}

func TestHy2AuthPlusNotTurnedIntoSpace(t *testing.T) {
	cfg, err := ParseHy2("hysteria2://a+b@example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth != "a+b" {
		t.Fatalf("auth = %q, want a+b", cfg.Auth)
	}
}

func TestHy2DefaultPort(t *testing.T) {
	cfg, err := ParseHy2("hy2://secret@example.com?sni=example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 443 {
		t.Fatalf("port = %d, want 443", cfg.Port)
	}
}

func TestHy2MportBecomesUDPHop(t *testing.T) {
	fm := hy2Finalmask(t, "hysteria2://secret@example.com:443?mport=20000-30000")
	qp, ok := fm["quicParams"].(M)
	if !ok {
		t.Fatalf("quicParams missing in %v", fm)
	}
	hop, ok := qp["udpHop"].(M)
	if !ok || hop["ports"] != "20000-30000" {
		t.Fatalf("udpHop = %v", qp)
	}
}

func TestHy2AuthorityMultiPort(t *testing.T) {
	cfg, err := ParseHy2("hysteria2://secret@example.com:443,20000-30000?sni=example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 443 || cfg.Ports != "443,20000-30000" {
		t.Fatalf("port=%d ports=%q", cfg.Port, cfg.Ports)
	}
}

func TestHy2InsecureAliases(t *testing.T) {
	for _, key := range []string{"insecure", "allow_insecure", "allowInsecure", "allow-insecure", "skip-cert-verify"} {
		cfg, err := ParseHy2("hysteria2://secret@example.com:443?" + key + "=1")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Insecure {
			t.Fatalf("%s=1: insecure = false", key)
		}
	}
}

func TestNormalizeHy2LinkCanonical(t *testing.T) {
	out, err := NormalizeHysteria2Link("hy2://secret@example.com:443?obfs=salamander&obfsPassword=pw123&allow_insecure=1&sni=example.com", "My Name")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "hysteria2://") {
		t.Fatalf("scheme not normalized: %s", out)
	}
	for _, want := range []string{"obfs=salamander", "obfs-password=pw123", "insecure=1", "sni=example.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("normalized link %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "obfsPassword") || strings.Contains(out, "allow_insecure") {
		t.Fatalf("alias spelling survived normalization: %s", out)
	}
	// Round-trip: the canonical link must parse to the same obfs password.
	cfg, err := ParseHy2(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ObfsPassword != "pw123" || !cfg.Insecure {
		t.Fatalf("round-trip cfg = %+v", cfg)
	}
}

func TestHy2IdentitySchemeIndependentAndObfsSensitive(t *testing.T) {
	a, err := Hy2Identity("hy2://secret@example.com:443?obfs=salamander&obfs-password=one&sni=example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hy2Identity("hysteria2://secret@example.com:443?sni=example.com&obfs-password=one&obfs=salamander")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("hy2 and hysteria2 spellings differ:\n%s\n%s", a, b)
	}
	c, err := Hy2Identity("hysteria2://secret@example.com:443?obfs=salamander&obfs-password=two&sni=example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("different obfs passwords must not share an identity")
	}
}

// --- WireGuard / WARP ---

const wgExample = "wireguard://%2BMsibTXXhNxwHMxAf4ar6vom%2F0NE3UOW2xbT6sV9ck4%3D@8.6.112.5:7559?address=172.16.0.2/32,2606:4700:110:81cf:afd6:7564:e1f3:2827/128&reserved=76,114,121&publickey=bmXOC%2BF1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=&dns=1.1.1.1,8.8.8.8,208.67.222.222,2606:4700:4700::1111&mtu=1300#NiREvil-1"

func TestWGExampleParses(t *testing.T) {
	cfg, err := ParseWG(wgExample)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecretKey != "+MsibTXXhNxwHMxAf4ar6vom/0NE3UOW2xbT6sV9ck4=" {
		t.Fatalf("secretKey = %q", cfg.SecretKey)
	}
	if cfg.Host != "8.6.112.5" || cfg.Port != 7559 {
		t.Fatalf("endpoint = %s:%d", cfg.Host, cfg.Port)
	}
	if cfg.PublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Fatalf("publicKey = %q", cfg.PublicKey)
	}
	if len(cfg.Address) != 2 || cfg.Address[0] != "172.16.0.2/32" {
		t.Fatalf("address = %v", cfg.Address)
	}
	if len(cfg.Reserved) != 3 || cfg.Reserved[0] != 76 || cfg.Reserved[1] != 114 || cfg.Reserved[2] != 121 {
		t.Fatalf("reserved = %v", cfg.Reserved)
	}
	if cfg.MTU != 1300 {
		t.Fatalf("mtu = %d", cfg.MTU)
	}
	if len(cfg.DNS) != 4 {
		t.Fatalf("dns = %v", cfg.DNS)
	}
}

func TestWGConvertToXray(t *testing.T) {
	out, err := ConvertLink(wgExample)
	if err != nil {
		t.Fatal(err)
	}
	if out["protocol"] != "wireguard" {
		t.Fatalf("protocol = %v", out["protocol"])
	}
	if _, ok := out["streamSettings"]; ok {
		t.Fatal("wireguard outbound must not carry streamSettings")
	}
	settings, ok := out["settings"].(M)
	if !ok {
		t.Fatalf("settings = %v", out["settings"])
	}
	if settings["noKernelTun"] != true {
		t.Fatalf("noKernelTun = %v, want true for concurrent tester", settings["noKernelTun"])
	}
	peers, ok := settings["peers"].([]M)
	if !ok || len(peers) != 1 {
		t.Fatalf("peers = %v", settings["peers"])
	}
	if peers[0]["endpoint"] != "8.6.112.5:7559" {
		t.Fatalf("endpoint = %v", peers[0]["endpoint"])
	}
	reserved, ok := settings["reserved"].([]int)
	if !ok || len(reserved) != 3 {
		t.Fatalf("reserved = %v", settings["reserved"])
	}
	remoteDNS, ok := settings["remoteDNS"].([]string)
	if !ok || len(remoteDNS) != 4 {
		t.Fatalf("remoteDNS = %v", settings["remoteDNS"])
	}
}

func TestWGInvalidKeyAndReserved(t *testing.T) {
	if _, err := ParseWG("wireguard://not-a-key@example.com:51820?publickey=bmXOC%2BF1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="); err == nil {
		t.Fatal("expected error for invalid secret key")
	}
	bad := "wireguard://%2BMsibTXXhNxwHMxAf4ar6vom%2F0NE3UOW2xbT6sV9ck4%3D@8.6.112.5:7559?publickey=bmXOC%2BF1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=&reserved=1,2"
	if _, err := ParseWG(bad); err == nil {
		t.Fatal("expected error for reserved with 2 bytes")
	}
}

func TestNormalizeWGLinkRoundTrip(t *testing.T) {
	out, err := NormalizeWGLink(wgExample, "Rose | US | WIREGUARD | 1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "wireguard://") {
		t.Fatalf("scheme = %s", out)
	}
	for _, want := range []string{"publickey=", "reserved=", "mtu=1300", "address="} {
		if !strings.Contains(out, want) {
			t.Fatalf("normalized %q missing %q", out, want)
		}
	}
	cfg, err := ParseWG(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecretKey != "+MsibTXXhNxwHMxAf4ar6vom/0NE3UOW2xbT6sV9ck4=" || cfg.Port != 7559 || len(cfg.Reserved) != 3 {
		t.Fatalf("round-trip cfg = %+v", cfg)
	}
}

func TestWGIdentitySchemeIndependent(t *testing.T) {
	a, err := WGIdentity(wgExample)
	if err != nil {
		t.Fatal(err)
	}
	warp := "warp://" + wgExample[len("wireguard://"):]
	b, err := WGIdentity(warp)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("wireguard and warp spellings differ:\n%s\n%s", a, b)
	}
	if GetProtocol(warp) != "wireguard" || GetProtocol(wgExample) != "wireguard" {
		t.Fatal("warp:// and wireguard:// must both map to wireguard protocol")
	}
}

// --- CoreIdentity (dedup) ---

func mustIdentity(t *testing.T, link string) string {
	t.Helper()
	id, err := CoreIdentity(link)
	if err != nil {
		t.Fatalf("CoreIdentity(%q): %v", link, err)
	}
	return id
}

func TestCoreIdentityVLESSDistinctParams(t *testing.T) {
	base := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&pbk=AAA&sid=01&sni=example.com&type=tcp#One"
	otherPBK := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&pbk=BBB&sid=01&sni=example.com&type=tcp#Two"
	otherPath := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws&path=/a&host=cdn.example.com#Three"
	if mustIdentity(t, base) == mustIdentity(t, otherPBK) {
		t.Fatal("different Reality pbk must not share identity")
	}
	if mustIdentity(t, base) == mustIdentity(t, otherPath) {
		t.Fatal("different transport/path must not share identity")
	}
	// Same config, different name, param order, host case, default type.
	same := "vless://11111111-2222-3333-4444-555555555555@EXAMPLE.com:443?sni=example.com&sid=01&pbk=AAA&security=reality#Renamed"
	if mustIdentity(t, base) != mustIdentity(t, same) {
		t.Fatalf("spelling variants differ:\n%s\n%s", mustIdentity(t, base), mustIdentity(t, same))
	}
}

func vmessLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func TestCoreIdentityVMessDistinctUUID(t *testing.T) {
	a := vmessLink(t, map[string]any{"v": "2", "ps": "A", "add": "1.2.3.4", "port": "443", "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "example.com"})
	b := vmessLink(t, map[string]any{"v": "2", "ps": "B", "add": "1.2.3.4", "port": "443", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "example.com"})
	c := vmessLink(t, map[string]any{"v": "2", "ps": "Renamed", "add": "1.2.3.4", "port": 443, "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "example.com"})
	if mustIdentity(t, a) == mustIdentity(t, b) {
		t.Fatal("different vmess UUID on same host:port must not share identity")
	}
	if mustIdentity(t, a) != mustIdentity(t, c) {
		t.Fatal("vmess ps/port-type variants of same config must share identity")
	}
}

func TestCoreIdentityTrojanDistinctPassword(t *testing.T) {
	a := "trojan://pass-one@example.com:443?sni=example.com#One"
	b := "trojan://pass-two@example.com:443?sni=example.com#Two"
	c := "trojan://pass-one@EXAMPLE.com:443?sni=example.com&security=tls#Renamed"
	if mustIdentity(t, a) == mustIdentity(t, b) {
		t.Fatal("different trojan password on same host:port must not share identity")
	}
	if mustIdentity(t, a) != mustIdentity(t, c) {
		t.Fatal("trojan spelling variants must share identity")
	}
}

func TestCoreIdentitySSLegacyVsSIP002(t *testing.T) {
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@example.com:8388")) + "#Legacy"
	sip002 := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@example.com:8388#SIP002"
	other := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:other")) + "@example.com:8388#Other"
	if mustIdentity(t, legacy) != mustIdentity(t, sip002) {
		t.Fatalf("legacy and SIP002 spellings differ:\n%s\n%s", mustIdentity(t, legacy), mustIdentity(t, sip002))
	}
	if mustIdentity(t, legacy) == mustIdentity(t, other) {
		t.Fatal("different SS password on same host:port must not share identity")
	}
}

func TestCoreIdentityTUICDistinctUUID(t *testing.T) {
	a := "tuic://11111111-2222-3333-4444-555555555555:pass@example.com:443?sni=example.com&alpn=h3#One"
	b := "tuic://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:pass@example.com:443?sni=example.com&alpn=h3#Two"
	if mustIdentity(t, a) == mustIdentity(t, b) {
		t.Fatal("different TUIC UUID on same host:port must not share identity")
	}
}
