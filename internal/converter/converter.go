package converter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type M = map[string]any

var protocolPrefixes = []struct {
	prefix string
	name   string
}{
	{"vless://", "vless"},
	{"vmess://", "vmess"},
	{"ss://", "ss"},
	{"trojan://", "trojan"},
	{"hysteria2://", "hysteria2"},
	{"hy2://", "hysteria2"},
	{"wireguard://", "wireguard"},
	{"warp://", "wireguard"},
}

func validURLHost(h string) bool {
	u, err := url.Parse("https://" + h + "/")
	return err == nil && u.Host == h
}

func GetProtocol(link string) string {
	link = strings.TrimSpace(link)
	for _, p := range protocolPrefixes {
		if strings.HasPrefix(link, p.prefix) {
			return p.name
		}
	}
	return "unknown"
}

func ConvertLink(link string) (M, error) {
	link = strings.TrimSpace(link)
	switch GetProtocol(link) {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "ss":
		return parseSS(link)
	case "trojan":
		return parseTrojan(link)
	case "hysteria2":
		return parseHysteria2(link)
	case "wireguard":
		return parseWireGuard(link)
	default:
		return nil, fmt.Errorf("unsupported protocol")
	}
}

func parseVLESS(link string) (M, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)

	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("missing UUID")
	}

	user := M{
		"id":         uuid,
		"encryption": firstOr(params, "none", "encryption"),
	}
	if flow := first(params, "flow"); flow != "" {
		user["flow"] = flow
	}

	return M{
		"protocol": "vless",
		"tag":      "proxy",
		"settings": M{
			"vnext": []M{{
				"address": u.Hostname(),
				"port":    port,
				"users":   []M{user},
			}},
		},
		"streamSettings": buildStreamSettings(params),
	}, nil
}

func parseVMess(link string) (M, error) {
	raw := link[len("vmess://"):]
	decoded, err := b64DecodeSafe(raw)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var d map[string]any
	if err := json.Unmarshal(decoded, &d); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	var port int
	switch v := d["port"].(type) {
	case float64:
		port = int(v)
	case string:
		port, err = strconv.Atoi(v)
		if err != nil || port <= 0 {
			return nil, fmt.Errorf("invalid port: %v", v)
		}
	default:
		return nil, fmt.Errorf("missing/invalid port")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range")
	}

	id, _ := d["id"].(string)
	addr, _ := d["add"].(string)
	if id == "" || addr == "" {
		return nil, fmt.Errorf("missing id or add")
	}

	scy, _ := d["scy"].(string)
	if scy == "" {
		scy, _ = d["security"].(string)
	}
	if scy == "" {
		scy = "auto"
	}

	net_, _ := d["net"].(string)
	if net_ == "" {
		net_ = "tcp"
	}
	tls_, _ := d["tls"].(string)
	if tls_ == "" {
		tls_ = "none"
	}

	params := url.Values{}
	params.Set("type", net_)
	params.Set("security", tls_)

	if v, _ := d["sni"].(string); v != "" {
		params.Set("sni", v)
	}
	if v, _ := d["fp"].(string); v != "" {
		params.Set("fp", v)
	}
	if v, _ := d["alpn"].(string); v != "" {
		params.Set("alpn", v)
	}

	switch net_ {
	case "ws", "websocket", "httpupgrade":
		if v, _ := d["host"].(string); v != "" {
			params.Set("host", v)
		}
		if v, _ := d["path"].(string); v != "" {
			params.Set("path", v)
		}
	case "grpc":
		if v, _ := d["path"].(string); v != "" {
			params.Set("serviceName", v)
		}
		if v, _ := d["host"].(string); v != "" {
			params.Set("authority", v)
		}
		if t, _ := d["type"].(string); t == "multi" {
			params.Set("mode", "multi")
		}
	case "xhttp", "splithttp":
		if v, _ := d["host"].(string); v != "" {
			params.Set("host", v)
		}
		if v, _ := d["path"].(string); v != "" {
			params.Set("path", v)
		}
		if v, _ := d["mode"].(string); v != "" {
			params.Set("mode", v)
		}
	case "tcp", "raw":
		if v, _ := d["type"].(string); v != "" && v != "none" {
			params.Set("headerType", v)
		}
		if v, _ := d["host"].(string); v != "" {
			params.Set("host", v)
		}
	}

	return M{
		"protocol": "vmess",
		"tag":      "proxy",
		"settings": M{
			"vnext": []M{{
				"address": addr,
				"port":    port,
				"users": []M{{
					"id":       id,
					"security": scy,
				}},
			}},
		},
		"streamSettings": buildStreamSettings(params),
	}, nil
}

func parseSS(link string) (M, error) {
	raw := link[len("ss://"):]

	if i := strings.LastIndex(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}

	var method, password, host string
	var port int
	var err error

	if i := strings.LastIndex(raw, "@"); i >= 0 {
		userinfoPart := raw[:i]
		serverPart := raw[i+1:]

		var userinfo string
		if b, decErr := b64DecodeSafe(userinfoPart); decErr == nil {
			userinfo = string(b)
		} else {
			userinfo, err = url.QueryUnescape(userinfoPart)
			if err != nil {
				return nil, fmt.Errorf("invalid userinfo")
			}
		}
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid userinfo: no ':'")
		}
		method, password = parts[0], parts[1]
		host, port, err = splitHostPort(serverPart)
	} else {
		b, decErr := b64DecodeSafe(raw)
		if decErr != nil {
			return nil, fmt.Errorf("base64 decode: %w", decErr)
		}
		s := string(b)
		i := strings.LastIndex(s, "@")
		if i < 0 {
			return nil, fmt.Errorf("legacy SS: no '@'")
		}
		mp := s[:i]
		serverPart := s[i+1:]
		parts := strings.SplitN(mp, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("legacy SS: no ':'")
		}
		method, password = parts[0], parts[1]
		host, port, err = splitHostPort(serverPart)
	}
	if err != nil {
		return nil, err
	}

	return M{
		"protocol": "shadowsocks",
		"tag":      "proxy",
		"settings": M{
			"servers": []M{{
				"address":  host,
				"port":     port,
				"method":   method,
				"password": password,
			}},
		},
		"streamSettings": M{"network": "tcp", "security": "none"},
	}, nil
}

func parseTrojan(link string) (M, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	password := userinfoAuth(u)
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}
	if params.Get("security") == "" {
		params.Set("security", "tls")
	}
	return M{
		"protocol": "trojan",
		"tag":      "proxy",
		"settings": M{
			"servers": []M{{
				"address":  u.Hostname(),
				"port":     port,
				"password": password,
			}},
		},
		"streamSettings": buildStreamSettings(params),
	}, nil
}

// Hy2Config is the normalized form of a Hysteria2 share link. The tester
// (Xray JSON) and the published link are both built from this model so they
// cannot drift apart: a link that passes the live test is published in the
// canonical spelling clients understand.
type Hy2Config struct {
	Auth        string
	Host        string
	Port        int
	Ports       string // port-hopping range/list, e.g. "20000-30000" or "443,8443"
	SNI         string
	Insecure    bool
	ObfsType    string // "" or "salamander"
	ObfsPassword string
	PinSHA256   string
	ALPN        string
	Fingerprint string
	ECH         string
	Up          string
	Down        string
	HopInterval string
	VerifyName  string
}

// ParseHy2 parses a hysteria2:// or hy2:// link, accepting the alias
// spellings used by common sources/clients. It returns an explicit error
// for a required-but-unsupported obfuscation instead of silently testing
// the server without it.
func ParseHy2(link string) (*Hy2Config, error) {
	link = strings.TrimSpace(link)
	rewritten, authorityPorts := normalizeHy2Authority(link)
	u, err := url.Parse(rewritten)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)

	auth := userinfoAuth(u)
	if auth == "" {
		auth = firstAlias(params, "auth", "password")
	}
	if auth == "" {
		return nil, fmt.Errorf("missing auth")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port := 443
	if ps := u.Port(); ps != "" {
		p, err := parsePort(ps)
		if err != nil {
			return nil, err
		}
		port = p
	}
	ports := firstAlias(params, "mport", "ports", "server_ports", "serverPorts")
	if ports == "" {
		ports = authorityPorts
	}
	if ports != "" && !validPorts(ports) {
		ports = ""
	}

	obfsType := strings.ToLower(strings.TrimSpace(firstAlias(params, "obfs", "obfs-type", "obfs_type", "obfsType")))
	obfsPass := firstAlias(params, "obfs-password", "obfs_password", "obfsPassword", "obfs-pass", "obfs_pass", "obfsPass")
	if obfsType == "none" || obfsType == "0" || obfsType == "false" {
		obfsType = ""
		obfsPass = ""
	}
	if obfsType == "" && obfsPass != "" {
		obfsType = "salamander"
	}
	if obfsType == "gecko" {
		return nil, fmt.Errorf("unsupported obfs type: gecko")
	}
	if obfsType != "" && obfsType != "salamander" {
		return nil, fmt.Errorf("unsupported obfs type: %s", obfsType)
	}
	if obfsType == "salamander" && obfsPass == "" {
		return nil, fmt.Errorf("obfs salamander requires obfs-password")
	}

	return &Hy2Config{
		Auth:         auth,
		Host:         host,
		Port:         port,
		Ports:        ports,
		SNI:          firstAlias(params, "sni", "peer", "serverName", "servername", "server_name"),
		Insecure:     parseInsecureParam(params),
		ObfsType:     obfsType,
		ObfsPassword: obfsPass,
		PinSHA256:    firstAlias(params, "pinSHA256", "pinsha256", "pin_sha256", "pcs"),
		ALPN:         firstAlias(params, "alpn"),
		Fingerprint:  firstAlias(params, "fp", "fingerprint"),
		ECH:          firstAlias(params, "ech", "echConfigList"),
		Up:           firstAlias(params, "up", "upmbps", "up_mbps", "upMbps"),
		Down:         firstAlias(params, "down", "downmbps", "down_mbps", "downMbps"),
		HopInterval:  firstAlias(params, "hop-interval", "hop_interval", "hopInterval", "mportHopInt", "portHopInt"),
		VerifyName:   firstAlias(params, "vcn"),
	}, nil
}

func parseHysteria2(link string) (M, error) {
	cfg, err := ParseHy2(link)
	if err != nil {
		return nil, err
	}

	tlsSettings := M{}
	if cfg.SNI != "" && validURLHost(cfg.SNI) {
		tlsSettings["serverName"] = cfg.SNI
	} else if validURLHost(cfg.Host) {
		tlsSettings["serverName"] = cfg.Host
	}
	if cfg.Fingerprint != "" {
		tlsSettings["fingerprint"] = cfg.Fingerprint
	}
	if cfg.ALPN != "" {
		tlsSettings["alpn"] = strings.Split(cfg.ALPN, ",")
	}
	if cfg.PinSHA256 != "" {
		tlsSettings["pinnedPeerCertSha256"] = cfg.PinSHA256
	}
	if cfg.VerifyName != "" {
		tlsSettings["verifyPeerCertByName"] = cfg.VerifyName
	}
	if cfg.ECH != "" {
		tlsSettings["echConfigList"] = cfg.ECH
	}
	if cfg.Insecure {
		tlsSettings["allowInsecure"] = true
	}

	stream := M{
		"network":  "hysteria",
		"security": "tls",
		"hysteriaSettings": M{
			"version": 2,
			"auth":    cfg.Auth,
		},
	}
	if len(tlsSettings) > 0 {
		stream["tlsSettings"] = tlsSettings
	}

	finalmask := M{}
	if cfg.ObfsType == "salamander" {
		finalmask["udp"] = []M{
			{
				"type": "salamander",
				"settings": M{
					"password": cfg.ObfsPassword,
				},
			},
		}
	}
	if cfg.Ports != "" {
		hop := cfg.HopInterval
		if hop == "" {
			hop = "5-10"
		}
		finalmask["quicParams"] = M{
			"udpHop": M{
				"ports":    cfg.Ports,
				"interval": hop,
			},
		}
	}
	if len(finalmask) > 0 {
		stream["finalmask"] = finalmask
	}

	return M{
		"protocol": "hysteria",
		"tag":      "proxy",
		"settings": M{
			"version": 2,
			"address": cfg.Host,
			"port":    cfg.Port,
		},
		"streamSettings": stream,
	}, nil
}

// NormalizeHysteria2Link rebuilds a Hy2 link in canonical form:
// hysteria2://<auth>@host:port/?sni=...&insecure=1&obfs=salamander&
// obfs-password=...&mport=...&pinSHA256=...#name
// Alias spellings from the source (obfsPassword, allow_insecure, ...) are
// rewritten to the official names so clients that only understand the
// official URI scheme see the obfs parameters.
func NormalizeHysteria2Link(link, name string) (string, error) {
	cfg, err := ParseHy2(link)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	if cfg.SNI != "" {
		q.Set("sni", cfg.SNI)
	}
	if cfg.Insecure {
		q.Set("insecure", "1")
	}
	if cfg.ObfsType != "" {
		q.Set("obfs", cfg.ObfsType)
		q.Set("obfs-password", cfg.ObfsPassword)
	}
	if cfg.Ports != "" {
		q.Set("mport", cfg.Ports)
	}
	if cfg.HopInterval != "" {
		q.Set("hop-interval", cfg.HopInterval)
	}
	if cfg.PinSHA256 != "" {
		q.Set("pinSHA256", cfg.PinSHA256)
	}
	if cfg.ALPN != "" {
		q.Set("alpn", cfg.ALPN)
	}
	if cfg.Fingerprint != "" {
		q.Set("fp", cfg.Fingerprint)
	}
	if cfg.ECH != "" {
		q.Set("ech", cfg.ECH)
	}
	if cfg.Up != "" {
		q.Set("up", cfg.Up)
	}
	if cfg.Down != "" {
		q.Set("down", cfg.Down)
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(cfg.Auth),
		Host:     net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String(), nil
}

// Hy2Identity is the deduplication identity for a Hy2 link. It is built
// from the normalized model, so hy2:// and hysteria2:// spellings of the
// same server collide, while servers differing in obfs password, SNI,
// port hopping or TLS settings do not.
func Hy2Identity(link string) (string, error) {
	cfg, err := ParseHy2(link)
	if err != nil {
		return "", err
	}
	parts := []string{
		"hysteria2", cfg.Auth, cfg.Host, strconv.Itoa(cfg.Port), cfg.Ports,
		cfg.SNI, strconv.FormatBool(cfg.Insecure), cfg.ObfsType,
		cfg.ObfsPassword, cfg.PinSHA256,
	}
	return strings.Join(parts, "|"), nil
}

func normalizeHy2Authority(link string) (string, string) {
	schemeEnd := strings.Index(link, "://")
	if schemeEnd < 0 {
		return link, ""
	}
	rest := link[schemeEnd+3:]
	authEnd := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' || rest[i] == '?' || rest[i] == '#' {
			authEnd = i
			break
		}
	}
	authority := rest[:authEnd]
	suffix := rest[authEnd:]
	userinfo := ""
	hostport := authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo = authority[:at+1]
		hostport = authority[at+1:]
	}
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end < 0 || end+1 >= len(hostport) || hostport[end+1] != ':' {
			return link, ""
		}
		portSpec := hostport[end+2:]
		if !strings.ContainsAny(portSpec, ",-") {
			return link, ""
		}
		first := firstPortOf(portSpec)
		if first == "" {
			return link, ""
		}
		return link[:schemeEnd+3] + userinfo + hostport[:end+1] + ":" + first + suffix, portSpec
	}
	colon := strings.LastIndex(hostport, ":")
	if colon < 0 {
		return link, ""
	}
	portSpec := hostport[colon+1:]
	if !strings.ContainsAny(portSpec, ",-") {
		return link, ""
	}
	first := firstPortOf(portSpec)
	if first == "" {
		return link, ""
	}
	return link[:schemeEnd+3] + userinfo + hostport[:colon+1] + first + suffix, portSpec
}

func firstPortOf(spec string) string {
	first := strings.Split(spec, ",")[0]
	first = strings.Split(first, "-")[0]
	first = strings.TrimSpace(first)
	if first == "" {
		return ""
	}
	for _, r := range first {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return first
}

func validPorts(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != ',' && r != '-' {
			return false
		}
	}
	return s[0] >= '0' && s[0] <= '9'
}

func userinfoAuth(u *url.URL) string {
	if u == nil || u.User == nil {
		return ""
	}
	user := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		return user + ":" + pw
	}
	return user
}

func firstAlias(p url.Values, keys ...string) string {
	for _, k := range keys {
		if v := p.Get(k); v != "" {
			return v
		}
	}
	for _, k := range keys {
		for pk, vals := range p {
			if strings.EqualFold(pk, k) && len(vals) > 0 && vals[0] != "" {
				return vals[0]
			}
		}
	}
	return ""
}

func parseBoolValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "t", "on":
		return true
	}
	return false
}

func parseInsecureParam(p url.Values) bool {
	v := firstAlias(p, "insecure", "allowInsecure", "allow_insecure", "allow-insecure", "allowinsecure", "skip-cert-verify", "skipCertVerify", "skip_cert_verify", "skipcertverify", "noverify")
	return parseBoolValue(v)
}

// WGConfig is the normalized form of a wireguard:// (or warp://) share
// link, e.g. the Cloudflare WARP configs published as wireguard:// links.
// The tester (Xray JSON) and the published link are both built from this
// model so they cannot drift apart.
type WGConfig struct {
	SecretKey    string
	Host         string
	Port         int
	Address      []string
	PublicKey    string
	PreSharedKey string
	Reserved     []int // nil, or exactly 3 bytes
	MTU          int
	DNS          []string
	AllowedIPs   []string
	KeepAlive    int
	FinalMask    string
}

// ParseWG parses a wireguard:// or warp:// link. The private key is the
// userinfo (percent-encoded base64); the peer public key, local addresses
// and WARP reserved bytes come from the query parameters.
func ParseWG(link string) (*WGConfig, error) {
	link = strings.TrimSpace(link)
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	params, _ := url.ParseQuery(u.RawQuery)

	secret := ""
	if u.User != nil {
		secret = u.User.Username()
		if pw, ok := u.User.Password(); ok && pw != "" {
			secret = secret + ":" + pw
		}
	}
	if secret == "" {
		secret = firstAlias(params, "privatekey", "privateKey", "secretkey", "secretKey")
	}
	if secret == "" {
		return nil, fmt.Errorf("missing secret key")
	}
	if !validWGKey(secret) {
		return nil, fmt.Errorf("invalid secret key")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port := 51820
	if ps := u.Port(); ps != "" {
		p, err := parsePort(ps)
		if err != nil {
			return nil, err
		}
		port = p
	}
	pub := firstAlias(params, "publickey", "publicKey", "peerPublicKey", "peerpublickey")
	if pub == "" {
		return nil, fmt.Errorf("missing public key")
	}
	if !validWGKey(pub) {
		return nil, fmt.Errorf("invalid public key")
	}
	psk := firstAlias(params, "presharedkey", "preSharedKey", "presharedKey", "psk")
	if psk != "" && !validWGKey(psk) {
		return nil, fmt.Errorf("invalid pre-shared key")
	}

	var address []string
	if raw := firstAlias(params, "address", "localAddress", "localaddress", "ip", "ips"); raw != "" {
		for _, a := range strings.Split(raw, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(a); err != nil && net.ParseIP(a) == nil {
				return nil, fmt.Errorf("invalid address: %s", a)
			}
			address = append(address, a)
		}
	}

	var reserved []int
	if raw := strings.TrimSpace(firstAlias(params, "reserved")); raw != "" {
		r, err := parseReserved(raw)
		if err != nil {
			return nil, err
		}
		reserved = r
	}

	mtu := 0
	if raw := firstAlias(params, "mtu"); raw != "" {
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || v < 0 || v > 9000 {
			return nil, fmt.Errorf("invalid mtu: %s", raw)
		}
		mtu = v
	}

	var dns []string
	if raw := firstAlias(params, "dns", "remoteDNS", "remotedns"); raw != "" {
		for _, d := range strings.Split(raw, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				dns = append(dns, d)
			}
		}
	}

	var allowed []string
	if raw := firstAlias(params, "allowedips", "allowedIPs", "allowedIps"); raw != "" {
		for _, a := range strings.Split(raw, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(a); err != nil && net.ParseIP(a) == nil {
				return nil, fmt.Errorf("invalid allowed IP: %s", a)
			}
			allowed = append(allowed, a)
		}
	}

	keepAlive := 0
	if raw := firstAlias(params, "keepalive", "keepAlive", "persistentKeepalive", "persistentkeepalive"); raw != "" {
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid keepalive: %s", raw)
		}
		keepAlive = v
	}

	return &WGConfig{
		SecretKey:    secret,
		Host:         host,
		Port:         port,
		Address:      address,
		PublicKey:    pub,
		PreSharedKey: psk,
		Reserved:     reserved,
		MTU:          mtu,
		DNS:          dns,
		AllowedIPs:   allowed,
		KeepAlive:    keepAlive,
		FinalMask:    firstAlias(params, "fm", "finalmask", "finalMask"),
	}, nil
}

func parseWireGuard(link string) (M, error) {
	cfg, err := ParseWG(link)
	if err != nil {
		return nil, err
	}
	allowed := cfg.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	peer := M{
		"publicKey":  cfg.PublicKey,
		"endpoint":   net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		"allowedIPs": allowed,
	}
	if cfg.PreSharedKey != "" {
		peer["preSharedKey"] = cfg.PreSharedKey
	}
	if cfg.KeepAlive > 0 {
		peer["keepAlive"] = cfg.KeepAlive
	}
	settings := M{
		"secretKey":   cfg.SecretKey,
		"peers":       []M{peer},
		"noKernelTun": true,
		"workers":     1,
	}
	if len(cfg.Address) > 0 {
		settings["address"] = cfg.Address
	}
	if cfg.MTU > 0 {
		settings["mtu"] = cfg.MTU
	}
	if len(cfg.Reserved) == 3 {
		settings["reserved"] = cfg.Reserved
	}
	var remoteDNS []string
	for _, d := range cfg.DNS {
		if net.ParseIP(d) != nil {
			remoteDNS = append(remoteDNS, d)
		}
	}
	if len(remoteDNS) > 0 {
		settings["remoteDNS"] = remoteDNS
	}
	return M{
		"protocol": "wireguard",
		"tag":      "proxy",
		"settings": settings,
	}, nil
}

// NormalizeWGLink rebuilds a WireGuard/WARP link in canonical form:
// wireguard://<secret>@host:port?address=...&publickey=...&
// presharedkey=...&reserved=...&mtu=...&dns=...#name
func NormalizeWGLink(link, name string) (string, error) {
	cfg, err := ParseWG(link)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	if len(cfg.Address) > 0 {
		q.Set("address", strings.Join(cfg.Address, ","))
	}
	q.Set("publickey", cfg.PublicKey)
	if cfg.PreSharedKey != "" {
		q.Set("presharedkey", cfg.PreSharedKey)
	}
	if len(cfg.Reserved) == 3 {
		parts := make([]string, 3)
		for i, b := range cfg.Reserved {
			parts[i] = strconv.Itoa(b)
		}
		q.Set("reserved", strings.Join(parts, ","))
	}
	if cfg.MTU > 0 {
		q.Set("mtu", strconv.Itoa(cfg.MTU))
	}
	if len(cfg.DNS) > 0 {
		q.Set("dns", strings.Join(cfg.DNS, ","))
	}
	if len(cfg.AllowedIPs) > 0 {
		q.Set("allowedips", strings.Join(cfg.AllowedIPs, ","))
	}
	if cfg.KeepAlive > 0 {
		q.Set("keepalive", strconv.Itoa(cfg.KeepAlive))
	}
	if cfg.FinalMask != "" {
		q.Set("fm", cfg.FinalMask)
	}
	u := url.URL{
		Scheme:   "wireguard",
		User:     url.User(cfg.SecretKey),
		Host:     net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String(), nil
}

// WGIdentity is the deduplication identity for a WireGuard/WARP link,
// built from the normalized model so wireguard:// and warp:// spellings
// of the same peer collide, while different keys do not.
func WGIdentity(link string) (string, error) {
	cfg, err := ParseWG(link)
	if err != nil {
		return "", err
	}
	reserved := ""
	if len(cfg.Reserved) == 3 {
		reserved = fmt.Sprintf("%d,%d,%d", cfg.Reserved[0], cfg.Reserved[1], cfg.Reserved[2])
	}
	parts := []string{
		"wireguard", cfg.SecretKey, cfg.Host, strconv.Itoa(cfg.Port),
		cfg.PublicKey, cfg.PreSharedKey, strings.Join(cfg.Address, ","),
		reserved, strconv.Itoa(cfg.MTU),
	}
	return strings.Join(parts, "|"), nil
}

func validWGKey(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		ok := true
		for _, r := range s {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	b, err := b64DecodeSafe(s)
	return err == nil && len(b) == 32
}

func parseReserved(raw string) ([]int, error) {
	if strings.Contains(raw, ",") {
		parts := strings.Split(raw, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("reserved must be exactly 3 bytes")
		}
		out := make([]int, 3)
		for i, p := range parts {
			v, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || v < 0 || v > 255 {
				return nil, fmt.Errorf("invalid reserved byte: %s", p)
			}
			out[i] = v
		}
		return out, nil
	}
	if b, err := b64DecodeSafe(raw); err == nil && len(b) == 3 {
		return []int{int(b[0]), int(b[1]), int(b[2])}, nil
	}
	return nil, fmt.Errorf("reserved must be exactly 3 bytes")
}

// CoreIdentity returns the deduplication identity for any supported share
// link. Two links share an identity only when every field that affects
// the connection is the same: credentials, endpoint, transport and
// security parameters. Display names (#fragment, vmess "ps", ssr
// "remarks") are excluded, and host case, default ports and query
// parameter order are normalized so spelling variants of the same
// config still collide.
func CoreIdentity(link string) (string, error) {
	link = strings.TrimSpace(link)
	scheme := ""
	if i := strings.Index(link, "://"); i > 0 {
		scheme = strings.ToLower(link[:i])
	}
	switch scheme {
	case "hysteria2", "hy2", "hysteria":
		return Hy2Identity(link)
	case "wireguard", "warp":
		return WGIdentity(link)
	case "vmess":
		return vmessIdentity(link)
	case "ss":
		return ssIdentity(link)
	case "ssr":
		return ssrIdentity(link)
	case "vless", "trojan", "tuic":
		return urlIdentity(link, scheme)
	default:
		if scheme == "" {
			return "", fmt.Errorf("missing scheme")
		}
		return urlIdentity(link, scheme)
	}
}

func defaultPortFor(proto string) string {
	switch proto {
	case "vless", "trojan", "tuic", "hysteria2", "hy2":
		return "443"
	case "wireguard", "warp":
		return "51820"
	}
	return ""
}

func normalizeHostPort(host, port, defPort string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if port == "" {
		port = defPort
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			port = strconv.Itoa(n)
		}
		return net.JoinHostPort(host, port)
	}
	return host
}

var insecureAliasKeys = map[string]bool{
	"insecure": true, "allowinsecure": true, "allow_insecure": true,
	"allow-insecure": true, "skip-cert-verify": true, "skipcertverify": true,
	"skip_cert_verify": true, "noverify": true,
}

func canonicalQuery(q url.Values) string {
	byKey := make(map[string][]string)
	for k, vals := range q {
		lk := strings.ToLower(k)
		switch lk {
		case "name", "remarks", "ps", "fragment", "tag":
			continue
		case "peer", "servername", "server_name":
			lk = "sni"
		}
		if insecureAliasKeys[lk] {
			for _, v := range vals {
				if parseBoolValue(v) {
					byKey["insecure"] = []string{"1"}
				}
			}
			continue
		}
		for _, v := range vals {
			if (lk == "type" && v == "tcp") || (lk == "security" && v == "none") ||
				(lk == "encryption" && v == "none") || (lk == "headertype" && v == "none") {
				continue
			}
			byKey[lk] = append(byKey[lk], v)
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := byKey[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, k+"="+strconv.Quote(v))
		}
	}
	return strings.Join(parts, "&")
}

func urlIdentity(link, proto string) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("missing host")
	}
	user := userinfoAuth(u)
	if proto == "vless" {
		user = strings.ToLower(user)
	}
	q, _ := url.ParseQuery(u.RawQuery)
	return strings.Join([]string{
		proto, user,
		normalizeHostPort(u.Hostname(), u.Port(), defaultPortFor(proto)),
		canonicalQuery(q),
	}, "|"), nil
}

func vmessStr(d map[string]any, key string) string {
	switch v := d[key].(type) {
	case string:
		return v
	case float64:
		return strconv.Itoa(int(v))
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func vmessIdentity(link string) (string, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	decoded, err := b64DecodeSafe(raw)
	if err != nil {
		return "", err
	}
	var d map[string]any
	if err := json.Unmarshal(decoded, &d); err != nil {
		return "", err
	}
	host := vmessStr(d, "add")
	if host == "" {
		return "", fmt.Errorf("missing add")
	}
	port := vmessStr(d, "port")
	parts := []string{
		"vmess",
		strings.ToLower(vmessStr(d, "id")),
		normalizeHostPort(host, port, ""),
		vmessStr(d, "aid"),
		vmessStr(d, "scy"),
		vmessStr(d, "net"),
		vmessStr(d, "type"),
		vmessStr(d, "host"),
		vmessStr(d, "path"),
		vmessStr(d, "tls"),
		vmessStr(d, "sni"),
		vmessStr(d, "alpn"),
		vmessStr(d, "fp"),
		vmessStr(d, "mode"),
	}
	return strings.Join(parts, "|"), nil
}

func ssIdentity(link string) (string, error) {
	out, err := parseSS(link)
	if err != nil {
		return "", err
	}
	settings, _ := out["settings"].(M)
	servers, _ := settings["servers"].([]M)
	if len(servers) == 0 {
		return "", fmt.Errorf("missing server")
	}
	srv := servers[0]
	method, _ := srv["method"].(string)
	password, _ := srv["password"].(string)
	host, _ := srv["address"].(string)
	port, _ := srv["port"].(int)
	plugin := ""
	if u, err := url.Parse(link); err == nil {
		plugin = u.Query().Get("plugin")
	}
	return strings.Join([]string{
		"ss", strings.ToLower(method), password,
		normalizeHostPort(host, strconv.Itoa(port), ""), plugin,
	}, "|"), nil
}

func ssrIdentity(link string) (string, error) {
	raw := strings.TrimPrefix(link, "ssr://")
	decoded, err := b64DecodeSafe(raw)
	if err != nil {
		return "", err
	}
	s := string(decoded)
	main := s
	params := ""
	if i := strings.Index(s, "/?"); i >= 0 {
		main = s[:i]
		params = s[i+2:]
	}
	fields := strings.Split(main, ":")
	if len(fields) < 6 {
		return "", fmt.Errorf("invalid ssr")
	}
	q, _ := url.ParseQuery(params)
	return strings.Join([]string{
		"ssr",
		normalizeHostPort(fields[0], fields[1], ""),
		fields[2], fields[3], fields[4], fields[5],
		q.Get("obfsparam"), q.Get("protoparam"),
	}, "|"), nil
}

func buildStreamSettings(params url.Values) M {
	network := params.Get("type")
	if network == "" {
		network = "tcp"
	}
	security := params.Get("security")
	if security == "" {
		security = "none"
	}

	stream := M{"network": network, "security": security}

	switch security {
	case "tls":
		tls := M{}
		if v := params.Get("sni"); v != "" && validURLHost(v) {
			tls["serverName"] = v
		}
		if v := params.Get("fp"); v != "" {
			tls["fingerprint"] = v
		}
		if v := params.Get("alpn"); v != "" {
			tls["alpn"] = strings.Split(v, ",")
		}
		if v := firstAlias(params, "pcs", "pinSHA256", "pinsha256"); v != "" {
			tls["pinnedPeerCertSha256"] = v
		}
		if v := params.Get("vcn"); v != "" {
			tls["verifyPeerCertByName"] = v
		}
		if v := firstAlias(params, "ech", "echConfigList"); v != "" {
			tls["echConfigList"] = v
		}
		if parseInsecureParam(params) {
			tls["allowInsecure"] = true
		}
		if len(tls) > 0 {
			stream["tlsSettings"] = tls
		}
	case "reality":
		r := M{}
		if v := params.Get("sni"); v != "" && validURLHost(v) {
			r["serverName"] = v
		}
		if v := params.Get("fp"); v != "" {
			r["fingerprint"] = v
		}
		if v := params.Get("pbk"); v != "" {
			r["publicKey"] = v
		}
		if v := params.Get("sid"); v != "" {
			r["shortId"] = v
		}
		if v := params.Get("spx"); v != "" {
			r["spiderX"], _ = url.QueryUnescape(v)
		}
		if len(r) > 0 {
			stream["realitySettings"] = r
		}
	}

	switch network {
	case "ws", "websocket":
		ws := M{}
		if v := params.Get("path"); v != "" {
			ws["path"], _ = url.QueryUnescape(v)
		}
		if v := params.Get("host"); v != "" {
			ws["host"] = v
		}
		if len(ws) > 0 {
			stream["wsSettings"] = ws
		}
	case "grpc":
		g := M{}
		if v := params.Get("serviceName"); v != "" {
			g["serviceName"] = v
		}
		if v := params.Get("authority"); v != "" {
			g["authority"] = v
		}
		if params.Get("mode") == "multi" {
			g["multiMode"] = true
		}
		if len(g) > 0 {
			stream["grpcSettings"] = g
		}
	case "httpupgrade":
		h := M{}
		if v := params.Get("path"); v != "" {
			h["path"], _ = url.QueryUnescape(v)
		}
		if v := params.Get("host"); v != "" {
			h["host"] = v
		}
		if len(h) > 0 {
			stream["httpupgradeSettings"] = h
		}
	case "xhttp", "splithttp":
		x := M{}
		if v := params.Get("path"); v != "" {
			x["path"], _ = url.QueryUnescape(v)
		}
		if v := params.Get("host"); v != "" && validURLHost(v) {
			x["host"] = v
		}
		if v := params.Get("mode"); v != "" {
			x["mode"] = v
		}
		if len(x) > 0 {
			stream["xhttpSettings"] = x
		}
	case "tcp", "raw":
		if params.Get("headerType") == "http" {
			hosts := strings.Split(params.Get("host"), ",")
			stream["tcpSettings"] = M{
				"header": M{
					"type": "http",
					"request": M{
						"headers": M{"Host": hosts},
					},
				},
			}
		}
	}

	return stream
}

func b64DecodeSafe(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	padLen := (4 - len(s)%4) % 4
	padded := s + strings.Repeat("=", padLen)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("missing port")
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port: %s", s)
	}
	return p, nil
}

func splitHostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end+1 >= len(s) || s[end+1] != ':' {
			return "", 0, fmt.Errorf("invalid IPv6: %s", s)
		}
		host := s[1:end]
		port, err := strconv.Atoi(s[end+2:])
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port")
		}
		return host, port, nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return s[:i], port, nil
}

func first(p url.Values, keys ...string) string {
	for _, k := range keys {
		if v := p.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func firstOr(p url.Values, def string, keys ...string) string {
	if v := first(p, keys...); v != "" {
		return v
	}
	return def
}
