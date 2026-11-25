package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	cloudflareIPsURL  = "https://raw.githubusercontent.com/radioactiveAHM/cf-scanner/refs/heads/main/ipv4.txt"
	cloudflareIPsFile = "cloudflare-ips.txt"
)

const (
	cfCipherSuites = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

	cfFinalMask = `{
  "tcp": [
    {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},
    {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}
  ]
}`
)

func loadCloudflareRanges() []*net.IPNet {
	var data []byte
	client := &http.Client{Timeout: 30 * time.Second}
	if resp, err := client.Get(cloudflareIPsURL); err == nil {
		if resp.StatusCode == http.StatusOK {
			data, _ = io.ReadAll(resp.Body)
		}
		resp.Body.Close()
	}
	if len(data) > 0 {
		os.WriteFile(cloudflareIPsFile, data, 0644)
	} else {
		data, _ = os.ReadFile(cloudflareIPsFile)
	}
	if len(data) == 0 {
		fmt.Println("Warning: no Cloudflare IP ranges available, skipping CF separation")
		return nil
	}

	var ranges []*net.IPNet
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		if _, cidr, err := net.ParseCIDR(line); err == nil {
			ranges = append(ranges, cidr)
		}
	}
	return ranges
}

func injectCFParams(link string) string {
	link = strings.TrimSpace(link)
	if link == "" {
		return link
	}

	// The fp/cs/fm parameters are TCP/TLS (Xray stream) settings. Adding
	// them to UDP-based or non-TLS links (Hy2/TUIC/SS/SSR/WARP) only
	// corrupts those links, so leave them unchanged.
	for _, p := range []string{"hy2://", "hysteria2://", "hysteria://", "tuic://", "ss://", "ssr://", "warp://"} {
		if strings.HasPrefix(link, p) {
			return link
		}
	}

	if strings.HasPrefix(link, "vmess://") {
		raw := strings.TrimPrefix(link, "vmess://")
		decoded, err := decodeBase64([]byte(raw))
		if err != nil {
			return link
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(decoded), &data); err != nil {
			return link
		}

		data["fp"] = "unsafe"
		data["cs"] = cfCipherSuites
		data["fm"] = cfFinalMask

		updated, err := json.Marshal(data)
		if err != nil {
			return link
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(updated)
	}

	u, err := url.Parse(link)
	if err != nil {
		return link
	}

	q := u.Query()

	q.Set("fp", "unsafe")
	q.Set("cs", cfCipherSuites)
	q.Set("fm", cfFinalMask)

	u.RawQuery = q.Encode()
	return u.String()
}

func writeCloudflareFile(configs []string) {
	ranges := loadCloudflareRanges()
	if len(ranges) == 0 {
		return
	}

	var cf []string
	for _, c := range configs {
		proto, _, _ := strings.Cut(c, "://")
		host, _ := getHostPort(c, proto)
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			continue
		}
		for _, cidr := range ranges {
			if cidr.Contains(ip) {
				modified := injectCFParams(c)
				cf = append(cf, modified)
				break
			}
		}
	}

	path := filepath.Join("By-protocol", "cloudflare.txt")
	content := base64.StdEncoding.EncodeToString([]byte(strings.Join(cf, "\n")))
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Printf("Error writing cloudflare file: %v\n", err)
		return
	}
	fmt.Printf("  cloudflare: %d configs behind Cloudflare IPs (with Iran optimizations)\n", len(cf))
}
