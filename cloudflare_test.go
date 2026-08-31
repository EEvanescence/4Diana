package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCloudflareFile(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)

	os.WriteFile(cloudflareIPsFile, []byte("104.16.0.0/13\n172.64.0.0/13\n"), 0644)
	os.MkdirAll("By-protocol", 0755)

	writeCloudflareFile([]string{
		"vless://uuid@104.17.2.3:443?type=ws#cf", // CF IP -> in
		"vless://uuid@8.8.8.8:443#not-cf",        // non-CF IP -> out
		"trojan://pw@some-domain.com:443#domain", // domain, not resolved -> out
	})

	raw, err := os.ReadFile(filepath.Join("By-protocol", "cloudflare.txt"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	got := strings.TrimSpace(string(dec))
	if got != "vless://uuid@104.17.2.3:443?type=ws#cf" {
		t.Fatalf("cloudflare.txt = %q", got)
	}
}
