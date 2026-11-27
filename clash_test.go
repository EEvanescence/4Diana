package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/EEvanescence/4Diana/internal/tester"
)

func vmessLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

func TestBuildClashYAML(t *testing.T) {
	vmess := vmessLink(t, map[string]any{
		"v": "2", "ps": "Rose | VMESS | 1", "add": "vm.example.com", "port": "443",
		"id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "cdn.example.com", "path": "/vm",
		"tls": "tls", "sni": "cdn.example.com",
	})
	vlessReality := "vless://11111111-2222-3333-4444-555555555555@vl.example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBLICKEY123&sid=abcd&flow=xtls-rprx-vision&type=tcp#Rose%20%7C%20VLESS%20%7C%202"
	trojan := "trojan://pass123@tr.example.com:443?sni=tr.example.com&type=ws&host=tr.example.com&path=%2Ftr#Rose%20%7C%20TROJAN%20%7C%203"
	hy2 := "hysteria2://authpass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=obfspass&insecure=1#Rose%20%7C%20HY2%20%7C%204"
	ss := "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@ss.example.com:8388#Rose%20%7C%20SS%20%7C%205"
	wg := "wireguard://cHJpdmF0ZWtleQ%3D%3D@wg.example.com:2408?publickey=cHVibGlja2V5&address=172.16.0.2%2F32#Rose%20%7C%20WARP%20%7C%206"
	cfVless := "vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443?security=tls&sni=cf.example.com&type=ws&host=cf.example.com&path=%2F#Rose%20%7C%20VLESS%20%7C%207"

	named := []string{vmess, vlessReality, trojan, hy2, ss, wg, cfVless}
	results := make([]tester.Result, len(named))
	for i, l := range named {
		results[i] = tester.Result{Link: l, DelayMs: 100 + i}
	}

	_, cfRange, err := net.ParseCIDR("104.16.0.0/13")
	if err != nil {
		t.Fatal(err)
	}
	out, stats := buildClashYAML(results, named, []*net.IPNet{cfRange})

	if stats.Included != 4 {
		t.Fatalf("Included = %d, want 4 (stats %+v)", stats.Included, stats)
	}
	if stats.SkippedProto != 2 {
		t.Errorf("SkippedProto = %d, want 2 (ss + wireguard)", stats.SkippedProto)
	}
	if stats.SkippedCF != 1 {
		t.Errorf("SkippedCF = %d, want 1", stats.SkippedCF)
	}

	for _, want := range []string{
		"type: url-test",
		"- MATCH,Rose Auto",
		"type: \"vmess\"",
		"type: \"vless\"",
		"type: \"trojan\"",
		"type: \"hysteria2\"",
		"reality-opts:",
		"public-key: \"PUBLICKEY123\"",
		"short-id: \"abcd\"",
		"flow: \"xtls-rprx-vision\"",
		"ws-opts:",
		"path: \"/vm\"",
		"Host: \"cdn.example.com\"",
		"obfs: \"salamander\"",
		"obfs-password: \"obfspass\"",
		"skip-cert-verify: true",
		"alterId: 0",
		"servername: \"cdn.example.com\"",
		"password: \"pass123\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	for _, unwanted := range []string{"ss.example.com", "wg.example.com", "104.16.0.1", "type: \"ss\"", "wireguard"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output should not contain %q", unwanted)
		}
	}
	if strings.Contains(out, "\t") {
		t.Error("output contains tab characters (invalid YAML indentation)")
	}
	// Every proxy name must appear once in proxies: and once in the group.
	if got := strings.Count(out, "\"Rose | VMESS | 1\""); got != 2 {
		t.Errorf("vmess name appears %d times, want 2 (proxy + group)", got)
	}
}

func TestBuildClashYAMLUniqueNames(t *testing.T) {
	link := "trojan://pass@a.example.com:443?sni=a.example.com#Same%20Name"
	named := []string{link, link}
	results := []tester.Result{{Link: link, DelayMs: 10}, {Link: link, DelayMs: 20}}
	out, stats := buildClashYAML(results, named, nil)
	if stats.Included != 2 {
		t.Fatalf("Included = %d, want 2", stats.Included)
	}
	if !strings.Contains(out, "\"Same Name (2)\"") {
		t.Errorf("duplicate name was not made unique:\n%s", out)
	}
}

func TestClashFieldsRejectsUnsupported(t *testing.T) {
	cases := []string{
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=tls&type=kcp#x",
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?security=reality&type=tcp#x", // no pbk
		"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?encryption=mlkem768x25519plus&type=tcp#x",
		"trojan://@a.example.com:443#x",
	}
	for _, link := range cases {
		proto := protocolOf(link)
		if _, err := clashFields(link, proto); err == nil {
			t.Errorf("clashFields(%q) succeeded, want error", link)
		}
	}
}
