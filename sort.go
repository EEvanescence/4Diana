package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var sortProtocols = []string{"vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp"}

func sortConfigs(configs []string) {
	fmt.Println("Starting protocol-based config sorting...")

	protocolDir := "By-protocol"
	if err := os.MkdirAll(protocolDir, 0755); err != nil {
		fmt.Printf("Error creating protocol directory: %v\n", err)
		return
	}

	byProtocol := make(map[string][]string)
	unknownCount := 0
	for _, line := range configs {
		matched := false
		for _, protocol := range sortProtocols {
			if strings.HasPrefix(line, protocol+"://") {
				byProtocol[protocol] = append(byProtocol[protocol], line)
				matched = true
				break
			}
		}
		if !matched {
			unknownCount++
		}
	}

	fmt.Println("\nProtocol sorting completed!")
	fmt.Println("Configuration counts:")
	for _, protocol := range sortProtocols {
		lines := byProtocol[protocol]
		content := strings.Join(lines, "\n")
		if protocol != "vmess" {
			content = base64.StdEncoding.EncodeToString([]byte(content))
		}
		path := filepath.Join(protocolDir, protocol+".txt")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			fmt.Printf("Error writing %s file: %v\n", protocol, err)
			return
		}
		fmt.Printf("  %s: %d configs\n", protocol, len(lines))
	}
	if unknownCount > 0 {
		fmt.Printf("  Unknown/Other: %d configs\n", unknownCount)
	}
}
