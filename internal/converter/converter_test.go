package converter

import (
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
