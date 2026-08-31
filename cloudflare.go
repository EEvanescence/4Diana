package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	cloudflareIPsURL  = "https://raw.githubusercontent.com/radioactiveAHM/cf-scanner/refs/heads/main/ipv4.txt"
	cloudflareIPsFile = "cloudflare-ips.txt"
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
				cf = append(cf, c)
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
	fmt.Printf("  cloudflare: %d configs behind Cloudflare IPs\n", len(cf))
}
