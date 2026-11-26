package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"

	"github.com/EEvanescence/4Diana/internal/converter"
	"github.com/EEvanescence/4Diana/internal/tester"
)

const (
	timeout         = 20 * time.Second
	maxWorkers      = 10
	maxLinesPerFile = 800
	testConcurrency = 400
	testTimeoutSec  = 5
	testURL         = "https://www.gstatic.com/generate_204"
	liveOutputFile = "working-live.txt"
)

var version = "dev"

type options struct {
	inputFile   string
	concurrency int
	timeoutSec  int
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("Rose", flag.ContinueOnError)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Rose %s - aggregate and live-test V2Ray configurations\n\n", version)
		fmt.Fprintf(out, "Collects configs from public subscription sources, verifies each one by\n")
		fmt.Fprintf(out, "passing real traffic through an embedded Xray-core instance, and writes\n")
		fmt.Fprintf(out, "the working ones as subscription files in the current directory.\n\n")
		fmt.Fprintf(out, "Usage:\n  Rose [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nExamples:\n")
		fmt.Fprintf(out, "  Rose                         aggregate from the built-in sources\n")
		fmt.Fprintf(out, "  Rose -input my-configs.txt   test your own list from your own network\n")
		fmt.Fprintf(out, "  Rose -concurrency 200        go easier on a slow or metered connection\n\n")
		fmt.Fprintf(out, "Working configs are streamed to %s as they pass, so an\n", liveOutputFile)
		fmt.Fprintf(out, "interrupted run still leaves behind everything verified up to that point.\n")
	}

	var (
		showVersion = fs.Bool("version", false, "print version and exit")
		inputFile   = fs.String("input", "",
			"read configs from this `file` (plain list or base64 subscription)\ninstead of fetching the built-in sources")
		concurrency = fs.Int("concurrency", envInt("ROSE_TEST_CONCURRENCY", testConcurrency),
			"configs to test in parallel; above ~500 the network saturates and\nworking configs start reading as dead")
		timeoutSec = fs.Int("timeout", envInt("ROSE_TEST_TIMEOUT", testTimeoutSec),
			"seconds to wait for each config to prove it carries traffic")
	)

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if *showVersion {
		fmt.Printf("Rose %s\n", version)
		return options{}, errVersionPrinted
	}
	if *concurrency < 1 {
		return options{}, fmt.Errorf("-concurrency must be at least 1, got %d", *concurrency)
	}
	if *timeoutSec < 1 {
		return options{}, fmt.Errorf("-timeout must be at least 1 second, got %d", *timeoutSec)
	}
	if rest := fs.Args(); len(rest) > 0 {
		return options{}, fmt.Errorf("unexpected argument %q (Rose takes flags only, see -help)", rest[0])
	}

	return options{
		inputFile:   *inputFile,
		concurrency: *concurrency,
		timeoutSec:  *timeoutSec,
	}, nil
}

var errVersionPrinted = errors.New("version printed")

var fixedText = `#profile-title: base64:Um9zZSBDb25maWdz
#profile-update-interval: 6
#support-url: https://github.com/NiREvil/vless
#profile-web-page-url: https://t.me/NiREvil_GP
`
var protocols = []string{"vmess", "vless", "trojan", "ss", "ssr", "hy2", "hysteria", "hysteria2", "tuic", "wireguard", "warp"}

var links = []string{ // Base64
	"http://www.xrayvip.com/free.txt",
	"https://shadowmere.xyz/api/b64sub",
	"https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
	"https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/protocols/vmess_base64.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/protocols/shadowsocks_base64.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/protocols/vless_base64.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/protocols/hysteria2_base64.txt",
	"https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/sub.txt",
	"https://raw.githubusercontent.com/JavidnamanIran-at-Telegram/x-ray_sub/refs/heads/main/x-ray_sub.txt",
	"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/refs/heads/main/subscriptions/v2ray/super-sub.txt",
	"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
	"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
	"https://raw.githubusercontent.com/Pawdroid/Free-servers/main/static/sub_en",
	"https://raw.githubusercontent.com/10ium/free-config/refs/heads/main/HighSpeed.txt",
	"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",
	"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
	"https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64",
	"https://raw.githubusercontent.com/10ium/base64-encoder/main/encoded/10ium_mixed_iran.txt",
	"https://raw.githubusercontent.com/Axiomdeveloper/Axiom-TG-Sub/main/sub/axiom_sub.txt",
	"https://gh-proxy.com/raw.githubusercontent.com/Ruk1ng001/freeSub/main/v2ray",
}

var dirLinks = []string{ // Plain Text
	"https://etoneya.su/1",
	"https://mifa.world/axe",
	"https://etoneya.su/gemini",
	"https://etoneya.su/main.yaml",
	"https://etoneya.su/whitelist",
	"http://www.xrayvip.com/free.txt",
	"https://sub.namazvpn.workers.dev",
	"https://lantern.darkpx.workers.dev/sub",
	"http://66.42.50.118:12580/clash/proxies",
	"https://vip.baidu365.org/api/raw/0nxNK2",
	"https://weoknow.com/data/dayupdate/1/z.txt",
	"https://rahim-mohamadi-2580.pages.dev/api/configs",
	"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
	"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
	"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/shadowsocks.txt",
	"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/hysteria2.txt",
	"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt",
	"https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/subscriptions/subscription-1.txt",
	"https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/separated_by_protocol/vless.txt",
	"https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/separated_by_protocol/vmess.txt",
	"https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/separated_by_protocol/reality.txt",
	"https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/separated_by_protocol/shadowsocks.txt",
	"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/vless.txt",
	"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/vmess.txt",
	"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/trojan.txt",
	"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/hy2.txt",
	"https://raw.githubusercontent.com/liMilCo/v2r/refs/heads/main/pro/hysteria.txt",
	"https://raw.githubusercontent.com/liMilCo/v2r/refs/heads/main/pro/vless.txt",
	"https://raw.githubusercontent.com/liMilCo/v2r/refs/heads/main/pro/ss.txt",
	"https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vless.txt",
	"https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vmess.txt",
	"https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/trojan.txt",
	"https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/shadowsocks.txt",
	"https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt",
	"https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/26.1.txt",
	"https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/26.2.txt",
	"https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/14.2.txt",
	"https://raw.githubusercontent.com/danesh1118/kdpektofuuebfotnjyt9376tehfosngoypwudbhmhosleofuebtlhgpzhegocsksjsss/refs/heads/main/sub",
	"https://raw.githubusercontent.com/BlueKnightNet/blueknight_net-sub-link/refs/heads/blue-knight-net/BlueKnight.txt",
	"https://raw.githubusercontent.com/SeyedNG/proxy/refs/heads/main/configs/proxy_configs_tested.txt",
	"https://raw.githubusercontent.com/SeyedNG/proxy/refs/heads/main/configs/fragment_fingerprint.txt",
	"https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
	"https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub2.txt",
	"https://raw.githubusercontent.com/Created-By/Telegram--Eag1e_YT/refs/heads/main/Hiddify-Next",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
	"https://raw.githubusercontent.com/inaz266/In-az-26/refs/heads/main/filtee.txt",
	"https://raw.githubusercontent.com/SnapdragonLee/SystemProxy/master/dist/clash_config_extra.yaml",
	"https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
	"https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/1.txt",
	"https://raw.githubusercontent.com/blueshekan/tcc/main/sub.html",
	"https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
	"https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
	"https://raw.githubusercontent.com/IranUnlocked/Sub/refs/heads/main/Sub-IranUnlocked.txt",
	"https://raw.githubusercontent.com/v2FreeHub/v2hub-configs/refs/heads/main/Sub-AutoUpdate",
	"https://raw.githubusercontent.com/free1zona/Keyfreetee/refs/heads/main/razlo4ka7",
	"https://raw.githubusercontent.com/PrinceVSFX/Adapt-Configs/main/Configs/Black_list.txt",
	"https://raw.githubusercontent.com/bobrinaw/vlessforu/refs/heads/main/working_configs.txt",
	"https://github.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/raw/refs/heads/main/vpn-lte/WHITELIST-ALL.txt",
	"https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
	"https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
	"https://gitverse.ru/api/repos/MishaLan/MishaLan/raw/branch/master/MishaLan.txt",
	"https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://gitverse.ru/api/repos/flaafix/AetrisVPN_Black_list/raw/branch/master/configs.txt",
	"https://gitverse.ru/api/repos/flaafix/AetrisVPN/raw/branch/master/AetrisVPN.txt",
    "https://gh-proxy.com/raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
	"https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
	"https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
	"https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/SSTime",
	"https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",
	"https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
	"https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/refs/heads/main/output/base64/mix-uri",
	"https://raw.githubusercontent.com/teknovpnhub/v2ray-subscription/refs/heads/main/servers.txt",
	"https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
	"https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
	"https://raw.githubusercontent.com/rango-cfs/NewCollector/refs/heads/main/v2ray_links.txt",
	"https://raw.githubusercontent.com/MrBihal/Hddify/refs/heads/main/HDDIFY",
	"https://rahi-eq3.pages.dev/api/configs?limit=all",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
	"https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
	"https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_base64.txt",
	"https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
	"https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
	"https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/shadowsocks.txt",
	"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2",
	"https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/refs/heads/main/mixed_iran.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/httpupgrade.txt",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/ss.txt",
	"https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/vless.html",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vmess.txt",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
	"https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
	"https://raw.githubusercontent.com/DarknessShade/Sub/main/Ss",
	"https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
	"https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",
	"https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
	"https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vmess_iran.txt",
	"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
	"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
	"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
	"https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/All_Config.txt",
	"https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/Trojan.txt",
	"https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/Hysteria2.txt",
	"https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/ShadowSocks.txt",
	"https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vmess.txt",
	"https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",
	"https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Germany.txt",
	"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
	"https://raw.githubusercontent.com/Stinsonysm/GO_V2rayCollector/refs/heads/main/trojan_iran.txt",
	"https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
	"https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt",
	"https://raw.githubusercontent.com/10ium/V2Hub3/refs/heads/main/Split/Normal/reality",
	"https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Vless.txt",
	"https://raw.githubusercontent.com/mehdi-hexing/Ss/refs/heads/main/Shadow.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/ss.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub2.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub3.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
	"https://raw.githubusercontent.com/ndsphonemy/proxy-sub/refs/heads/main/speed.txt",
	"https://raw.githubusercontent.com/ndsphonemy/proxy-sub/refs/heads/main/hys-tuic.txt",
	"https://raw.githubusercontent.com/Proxydaemitelegram/Proxydaemi44/refs/heads/main/Proxydaemi44",
	"https://raw.githubusercontent.com/Created-By/Telegram-Eag1e_YT/refs/heads/main/%40Eag1e_YT",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub7.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub8.txt",
	"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
	"https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
	"https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
	"https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",
	"https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
	"https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vmess.txt",
	"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
	"https://raw.githubusercontent.com/Kolandone/v2raycollector/refs/heads/main/config.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vmess.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/trojan.txt",
	"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
	"https://raw.githubusercontent.com/shabane/kamaji/refs/heads/master/hub/merged.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
	"https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/v2rayng-wg.txt",
	"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt",
	"https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/wireguard.txt",
	"https://raw.githubusercontent.com/frank-vpl/servers/refs/heads/main/irbox",
	"https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
	"https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
	"https://raw.githubusercontent.com/bskertt-cmd/vpn-has/refs/heads/main/keys.txt",
	"https://raw.githubusercontent.com/miuilore/parsing-vless/refs/heads/main/wln",
	"https://raw.githubusercontent.com/IranUnlocked/Sub/refs/heads/main/Sub-IranUnlocked.txt",
	"https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt",
	"https://raw.githubusercontent.com/free1zona/Keyfreetee/refs/heads/main/razlo4ka7",
	"https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/10.txt",
	"https://raw.githubusercontent.com/bobrinaw/vlessforu/refs/heads/main/working_configs.txt",
	"https://raw.githubusercontent.com/teknovpnhub/v2ray-subscription/refs/heads/main/servers.txt",
	"https://raw.githubusercontent.com/ts-sf/fly/main/v2",
	"https://raw.githubusercontent.com/yebekhe/vpn-fail/refs/heads/main/sub-link",
}

type Result struct {
	URL        string
	Content    string
	StatusCode int
	Error      error
}

var (
	geoDB    *geoip2.Reader
	geoCache sync.Map
)

func main() {
	switch err := run(os.Args[1:]); {
	case err == nil, errors.Is(err, errVersionPrinted), errors.Is(err, flag.ErrHelp):
	default:
		fmt.Fprintf(os.Stderr, "Rose: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	start := time.Now()
	fmt.Println("Starting V2Ray config aggregator...")

	base64Folder, err := ensureDirectoriesExist()
	if err != nil {
		return fmt.Errorf("creating output directories: %w", err)
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var allConfigs, failedLinks []string
	if opts.inputFile != "" {
		allConfigs, err = readConfigsFromFile(opts.inputFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", opts.inputFile, err)
		}
		fmt.Printf("Read %d configurations from %s\n", len(allConfigs), opts.inputFile)
	} else {
		fmt.Println("Fetching configurations from sources...")
		allConfigs, failedLinks = fetchAllConfigs(client, links, dirLinks)
	}
	if len(allConfigs) == 0 {
		return fmt.Errorf("no configurations to process")
	}

	if err := downloadGeoIPDB(); err != nil {
		warnf("could not download GeoIP database: %v", err)
	} else {
		db, err := geoip2.Open("GeoLite2-Country.mmdb")
		if err == nil {
			geoDB = db
			defer geoDB.Close()
		} else {
			warnf("could not open GeoIP database: %v", err)
		}
	}

	fmt.Println("Filtering configurations and removing duplicates...")
	originalCount := len(allConfigs)
	candidates, fstats := filterForProtocols(allConfigs, protocols)

	fmt.Printf("Fetched %d lines: %d protocol-matched & valid, %d invalid/non-matching\n", fstats.Input, fstats.Matched, fstats.Invalid)
	fmt.Printf("Removed %d duplicates -> %d unique configurations\n", fstats.Duplicates, fstats.Unique)
	fmt.Printf("TCP check removed %d unreachable -> %d candidates for live test\n", fstats.TCPFailed, len(candidates))
	working := liveTest(ctx, candidates, opts)
	fmt.Printf("%d/%d configurations passed the live test\n", len(working), len(candidates))

	filteredConfigs, configsByCountry := nameAndGroup(working)

	cleanExistingFiles(base64Folder)

	if err := writeMainConfigFile("AllConfigsSub.txt", filteredConfigs); err != nil {
		return fmt.Errorf("writing main config file: %w", err)
	}

	fmt.Println("Splitting into smaller files...")
	if err := splitIntoFiles(base64Folder, filteredConfigs); err != nil {
		return fmt.Errorf("splitting files: %w", err)
	}

	stats := calculateStats(filteredConfigs)
	fmt.Println("Writing country-specific files...")
	writeCountryFiles(configsByCountry)

	processingTime := time.Since(start).Seconds()
	writeUpdateSummary(len(filteredConfigs), stats, processingTime, originalCount, fstats, failedLinks)
	sortConfigs(filteredConfigs)
	writeCloudflareFile(filteredConfigs)
	writeClashFile(working, filteredConfigs)
	return nil
}

func warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "Rose: warning: "+format+"\n", a...)
}

func readConfigsFromFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(raw)
	if !strings.Contains(content, "://") {
		decoded, err := decodeBase64(raw)
		if err != nil {
			return nil, fmt.Errorf("file is neither plain config links nor valid base64")
		}
		content = decoded
	}

	var configs []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			configs = append(configs, line)
		}
	}
	return configs, nil
}

func ensureDirectoriesExist() (string, error) {
	base64Folder := "Base64"
	if err := os.MkdirAll(base64Folder, 0755); err != nil {
		return "", err
	}

	if err := os.MkdirAll("By-country", 0755); err != nil {
		return "", err
	}

	return base64Folder, nil
}

func fetchAllConfigs(client *http.Client, base64Links, textLinks []string) ([]string, []string) {
	var wg sync.WaitGroup
	resultChan := make(chan Result, len(base64Links)+len(textLinks))
	var failedLinks []string

	semaphore := make(chan struct{}, maxWorkers)

	for _, link := range base64Links {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res := fetchAndDecodeBase64(client, url)
			resultChan <- res
		}(link)
	}

	for _, link := range textLinks {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res := fetchText(client, url)
			resultChan <- res
		}(link)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var allConfigs []string
	for result := range resultChan {
		if result.StatusCode != http.StatusOK || result.Error != nil {
			status := "Error"
			if result.StatusCode > 0 {
				status = fmt.Sprintf("HTTP %d", result.StatusCode)
			}
			failedLinks = append(failedLinks, fmt.Sprintf("%s (%s)", result.URL, status))
			continue
		}

		lines := strings.Split(strings.TrimSpace(result.Content), "\n")
		allConfigs = append(allConfigs, lines...)
	}

	return allConfigs, failedLinks
}

func fetchAndDecodeBase64(client *http.Client, url string) Result {
	res := Result{URL: url}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		res.Error = err
		return res
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err
		return res
	}

	decoded, err := decodeBase64(body)
	if err != nil {
		res.Error = err
		return res
	}

	res.Content = decoded
	return res
}

func fetchText(client *http.Client, url string) Result {
	res := Result{URL: url}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		res.Error = err
		return res
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err
		return res
	}

	res.Content = string(body)
	return res
}

func decodeBase64(encoded []byte) (string, error) {
	s := strings.TrimSpace(string(encoded))
	padLen := (4 - len(s)%4) % 4
	padded := s + strings.Repeat("=", padLen)
	
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, 
		base64.URLEncoding,
		base64.RawStdEncoding, 
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(padded); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("invalid base64")
}

func sanitizeConfig(config string) string {
	config = strings.ReplaceAll(config, "&amp;", "&")
	return config
}

func isValidConfig(config string) bool {
	u, err := url.Parse(config)
	if err != nil {
		return true
	}
	q := u.Query()
	for _, key := range []string{"sni", "path"} {
		for _, r := range q.Get(key) {
			if r > 127 || r == '[' || r == ']' {
				return false
			}
		}
	}

	if host := q.Get("host"); host != "" {
		if _, err := url.Parse("https://" + host + "/"); err != nil {
			return false
		}
	}
	return true
}

type filterStats struct {
	Input      int
	Matched    int // protocol-matched and valid
	Invalid    int // no protocol match or invalid
	Duplicates int
	Unique     int // after dedup, before TCP check
	TCPFailed  int
	Candidates int // after dedup + TCP check
}

func filterForProtocols(data []string, protocols []string) ([]string, filterStats) {
	stats := filterStats{Input: len(data)}

	// Phase 1: deterministic dedup in input order. The first spelling
	// of each distinct config wins, so the result does not depend on
	// worker scheduling.
	seen := make(map[string]bool)
	type uniqueConfig struct {
		line  string
		proto string
	}
	var unique []uniqueConfig
	for _, raw := range data {
		line := strings.TrimSpace(sanitizeConfig(raw))
		if line == "" {
			stats.Invalid++
			continue
		}
		var currentProtocol string
		for _, protocol := range protocols {
			prefix := protocol
			if !strings.HasSuffix(prefix, "://") && protocol != "warp://" {
				prefix += "://"
			}
			if strings.HasPrefix(line, prefix) {
				currentProtocol = protocol
				break
			}
		}
		if currentProtocol == "" || !isValidConfig(line) {
			stats.Invalid++
			continue
		}
		stats.Matched++
		identity := parseCoreIdentity(line, currentProtocol)
		if seen[identity] {
			stats.Duplicates++
			continue
		}
		seen[identity] = true
		unique = append(unique, uniqueConfig{line: line, proto: currentProtocol})
	}
	stats.Unique = len(unique)

	// Phase 2: TCP reachability check on the unique configs only, in
	// parallel, preserving input order in the result.
	type checkResult struct {
		idx int
		ok  bool
	}
	jobs := make(chan int, 100)
	results := make(chan checkResult, 100)
	const numWorkers = 300
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				uc := unique[idx]
				isUDP := uc.proto == "hy2" || uc.proto == "hysteria2" || uc.proto == "hysteria" || uc.proto == "tuic" || uc.proto == "wireguard" || uc.proto == "warp"
				if isUDP {
					results <- checkResult{idx: idx, ok: true}
					continue
				}
				host, port := getHostPort(uc.line, uc.proto)
				results <- checkResult{idx: idx, ok: checkPort(host, port)}
			}
		}()
	}
	go func() {
		for i := range unique {
			jobs <- i
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	passed := make([]bool, len(unique))
	for r := range results {
		passed[r.idx] = r.ok
	}
	var filtered []string
	for i, uc := range unique {
		if passed[i] {
			filtered = append(filtered, uc.line)
		} else {
			stats.TCPFailed++
		}
	}
	stats.Candidates = len(filtered)
	return filtered, stats
}

func nameAndGroup(results []tester.Result) ([]string, map[string][]string) {
	var named []string
	byCountry := make(map[string][]string)

	for _, r := range results {
		protocol := protocolOf(r.Link)
		country := countryOfIP(net.ParseIP(r.ExitIP))
		if country == "" {
			host, _ := getHostPort(r.Link, protocol)
			country = countryOfHost(host)
		}

		line := standardizeName(r.Link, protocol, len(named)+1, country)
		named = append(named, line)

		key := country
		if key == "" {
			key = "Unknown"
		}
		byCountry[key] = append(byCountry[key], line)
	}

	return named, byCountry
}

func protocolOf(line string) string {
	for _, protocol := range protocols {
		prefix := protocol
		if !strings.HasSuffix(prefix, "://") && protocol != "warp://" {
			prefix += "://"
		}
		if strings.HasPrefix(line, prefix) {
			return protocol
		}
	}
	return ""
}

func standardizeName(config string, protocol string, index int, country string) string {
	flag := getFlag(country)
	countryDisplay := ""
	if country != "" {
		if flag != "" {
			countryDisplay = flag + " " + country + " | "
		} else {
			countryDisplay = country + " | "
		}
	}
	newName := fmt.Sprintf("Rose | %s%s | %d", countryDisplay, strings.ToUpper(protocol), index)

	switch protocol {
	case "vmess":
		trimmed := strings.TrimPrefix(config, "vmess://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err != nil {
			return config
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(decoded), &data); err != nil {
			return config
		}
		data["ps"] = newName
		updated, _ := json.Marshal(data)
		return "vmess://" + base64.StdEncoding.EncodeToString(updated)

	case "ssr":
		trimmed := strings.TrimPrefix(config, "ssr://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err != nil {
			return config
		}
		
		parts := strings.Split(decoded, "/?")
		if len(parts) < 1 {
			return config
		}

		mainInfo := parts[0]
		params := ""
		if len(parts) > 1 {
			params = parts[1]
		}

		paramList := strings.Split(params, "&")
		newParamList := []string{}
		remarksFound := false
		encodedName := strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(newName)), "=", "")

		for _, p := range paramList {
			if strings.HasPrefix(p, "remarks=") {
				newParamList = append(newParamList, "remarks="+encodedName)
				remarksFound = true
			} else if p != "" {
				newParamList = append(newParamList, p)
			}
		}
		if !remarksFound {
			newParamList = append(newParamList, "remarks="+encodedName)
		}

		updatedDecoded := mainInfo + "/?" + strings.Join(newParamList, "&")
		return "ssr://" + strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(updatedDecoded)), "=", "")

	case "hy2", "hysteria2", "hysteria":
		if normalized, err := converter.NormalizeHysteria2Link(config, newName); err == nil {
			return normalized
		}
		var body string
		if hi := strings.Index(config, "#"); hi >= 0 {
			body = config[:hi]
		} else {
			body = config
		}
		body = strings.TrimRight(body, " \t")
		return body + "#" + url.PathEscape(newName)

	case "wireguard", "warp":
		if normalized, err := converter.NormalizeWGLink(config, newName); err == nil {
			return normalized
		}
		var body string
		if hi := strings.Index(config, "#"); hi >= 0 {
			body = config[:hi]
		} else {
			body = config
		}
		body = strings.TrimRight(body, " \t")
		return body + "#" + url.PathEscape(newName)

	default:
		var body string
		if hi := strings.Index(config, "#"); hi >= 0 {
			body = config[:hi]
		} else {
			body = config
		}
		body = strings.TrimRight(body, " \t")
		result := body + "#" + url.PathEscape(newName)
		return result
	}
}

func parseCoreIdentity(config string, protocol string) string {
	config = strings.TrimSpace(config)

	// Full identity: credentials + endpoint + transport/security
	// parameters. The old host:port-only identity collapsed distinct
	// configs that share an endpoint (different UUID/password, SNI,
	// path, Reality keys, ...), keeping an arbitrary one of them.
	if id, err := converter.CoreIdentity(config); err == nil {
		return id
	}

	// Fallback for links the identity parser cannot handle: use the
	// whole link without its display name, so at least exact
	// duplicates still collide.
	if hi := strings.Index(config, "#"); hi >= 0 {
		return config[:hi]
	}
	return config
}

func countryOfIP(ip net.IP) string {
	if geoDB == nil || ip == nil {
		return ""
	}
	record, err := geoDB.Country(ip)
	if err != nil {
		return ""
	}
	return record.Country.IsoCode
}

func countryOfHost(host string) string {
	if geoDB == nil || host == "" {
		return ""
	}
	if val, ok := geoCache.Load(host); ok {
		return val.(string)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}

	code := countryOfIP(ip)
	geoCache.Store(host, code)
	return code
}

func getFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	return string(rune(code[0])+127397) + string(rune(code[1])+127397)
}

func downloadGeoIPDB() error {
	dbPath := "GeoLite2-Country.mmdb"
	if _, err := os.Stat(dbPath); err == nil {
		return nil
	}

	fmt.Println("Downloading GeoIP database...")
	url := "https://raw.githubusercontent.com/6Kmfi6HP/maxmind/main/GeoLite2-Country.mmdb"

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dbPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func cleanExistingFiles(base64Folder string) {
	os.Remove("AllConfigsSub.txt")
	os.Remove("All_Configs_base64_Sub.txt")

	for i := 0; i < 20; i++ {
		os.Remove(fmt.Sprintf("Sub%d.txt", i))
		os.Remove(filepath.Join(base64Folder, fmt.Sprintf("Sub%d_base64.txt", i)))
	}

	files, err := os.ReadDir("By-country")
	if err == nil {
		for _, f := range files {
			os.Remove(filepath.Join("By-country", f.Name()))
		}
	}
}

func writeCountryFiles(configsByCountry map[string][]string) {
	countryDir := "By-country"
	for country, configs := range configsByCountry {
		filename := filepath.Join(countryDir, country+".txt")
		file, err := os.Create(filename)
		if err != nil {
			continue
		}

		writer := bufio.NewWriter(file)
		for _, config := range configs {
			writer.WriteString(config + "\n")
		}
		writer.Flush()
		file.Close()
	}
}

func writeMainConfigFile(filename string, configs []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	if _, err := writer.WriteString(fixedText); err != nil {
		return err
	}

	for _, config := range configs {
		if _, err := writer.WriteString(config + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func splitIntoFiles(base64Folder string, configs []string) error {
	numFiles := (len(configs) + maxLinesPerFile - 1) / maxLinesPerFile

	reversedConfigs := make([]string, len(configs))
	for i, config := range configs {
		reversedConfigs[len(configs)-1-i] = config
	}

	for i := 0; i < numFiles; i++ {
		profileTitle := fmt.Sprintf("GitHub:NiREvil| Sub%d 🩶", i+1)
		encodedTitle := base64.StdEncoding.EncodeToString([]byte(profileTitle))
		customFixedText := fmt.Sprintf(`#profile-title: base64:%s
#profile-update-interval: 6
#support-url: https://github.com/NiREvil/vless
#profile-web-page-url: https://t.me/s/NiREvil_GP
`, encodedTitle)

		start := i * maxLinesPerFile
		end := start + maxLinesPerFile
		if end > len(reversedConfigs) {
			end = len(reversedConfigs)
		}

		filename := fmt.Sprintf("Sub%d.txt", i+1)
		if err := writeSubFile(filename, customFixedText, reversedConfigs[start:end]); err != nil {
			return err
		}

		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}

		base64Filename := filepath.Join(base64Folder, fmt.Sprintf("Sub%d_base64.txt", i+1))
		encodedContent := base64.StdEncoding.EncodeToString(content)
		if err := os.WriteFile(base64Filename, []byte(encodedContent), 0644); err != nil {
			return err
		}
	}

	return nil
}

func writeSubFile(filename, header string, configs []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	if _, err := writer.WriteString(header); err != nil {
		return err
	}
	
	for _, config := range configs {
		if _, err := writer.WriteString(config + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func calculateStats(configs []string) map[string]int {
	stats := make(map[string]int)

	for _, config := range configs {
		protocol := protocolOf(strings.TrimSpace(config))

		switch protocol {
		case "hysteria", "hysteria2", "hy2":
			stats["hy2"]++
		case "vmess", "vless", "trojan", "ss", "ssr", "tuic":
			stats[protocol]++
		case "warp", "wireguard", "warp://":
			stats["warp"]++
		}
	}

	return stats
}

func percentOf(part, whole int) float64 {
	if whole <= 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}

func writeUpdateSummary(total int, stats map[string]int, duration float64, originalTotal int, fstats filterStats, failedLinks []string) {
	summaryPath := "UPDATE_SUMMARY.md"

	file, err := os.Create(summaryPath)
	if err != nil {
		fmt.Printf("Error creating summary file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.WriteString("# V2Ray Config Update Summary\n")
	writer.WriteString(fmt.Sprintf("Generated on: %s\n\n", time.Now().Format("2006-01-02 15:04:05 MST")))

	writer.WriteString("## Configuration Statistics\n")
	writer.WriteString(fmt.Sprintf("- Total unique configurations: %d\n", total))
	writer.WriteString("- Protocol breakdown:\n")

	for _, p := range []string{"vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp"} {
		writer.WriteString(fmt.Sprintf("  - %s: %d configs\n", p, stats[p]))
	}

	writer.WriteString("\n## Performance\n")
	writer.WriteString(fmt.Sprintf("- Processing time: %.2f seconds\n", duration))
	if originalTotal > 0 {
		writer.WriteString(fmt.Sprintf("- Fetched lines: %d\n", originalTotal))
		writer.WriteString(fmt.Sprintf("- Protocol-matched & valid: %d (invalid/non-matching: %d)\n", fstats.Matched, fstats.Invalid))
		if fstats.Matched > 0 {
			writer.WriteString(fmt.Sprintf("- Duplicates removed: %d (%.1f%% of matched)\n", fstats.Duplicates, float64(fstats.Duplicates)/float64(fstats.Matched)*100))
		}
		writer.WriteString(fmt.Sprintf("- Unique configurations after dedup: %d\n", fstats.Unique))
		writer.WriteString(fmt.Sprintf("- TCP unreachable removed: %d\n", fstats.TCPFailed))
		writer.WriteString(fmt.Sprintf("- Candidates sent to live test: %d\n", fstats.Candidates))
		writer.WriteString(fmt.Sprintf("- Passed live test: %d (%.2f%% of fetched, %.1f%% of candidates)\n", total, float64(total)/float64(originalTotal)*100, percentOf(total, fstats.Candidates)))
	}

	if len(failedLinks) > 0 {
		writer.WriteString("\n## ⚠️ Failed Links (404 or Errors)\n")
		writer.WriteString("The following sources could not be reached or returned no data:\n")
		for _, link := range failedLinks {
			writer.WriteString(fmt.Sprintf("- %s\n", link))
		}
	} else {
		writer.WriteString("\n##✔️ All Sources Successful\n")
		writer.WriteString("All configured sources were reached successfully.\n")
	}
}

func checkPort(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func envInt(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func liveTest(ctx context.Context, configs []string, opts options) []tester.Result {
	if len(configs) == 0 {
		return nil
	}

	concurrent, timeoutSec := opts.concurrency, opts.timeoutSec

	debug.SetMaxThreads(10000 + 10*concurrent)

	var liveMu sync.Mutex
	onPass := func(r tester.Result) {}
	if f, err := os.Create(liveOutputFile); err != nil {
		fmt.Printf("Warning: could not open %s: %v\n", liveOutputFile, err)
	} else {
		defer f.Close()
		fmt.Printf("Streaming working configs to %s as they are found\n", liveOutputFile)
		onPass = func(r tester.Result) {
			liveMu.Lock()
			defer liveMu.Unlock()
			fmt.Fprintln(f, r.Link)
		}
	}

	kept := make([]tester.Result, 0, len(configs))
	for _, r := range tester.TestAll(ctx, configs, testURL, timeoutSec, concurrent, onPass) {
		if r.DelayMs >= 0 {
			kept = append(kept, r)
		}
	}
	return kept
}

func getHostPort(config, protocol string) (string, string) {
	switch protocol {
	case "vmess":
		trimmed := strings.TrimPrefix(config, "vmess://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err == nil {
			var data struct {
				Add  string      `json:"add"`
				Port interface{} `json:"port"`
			}
			json.Unmarshal([]byte(decoded), &data)
			return data.Add, fmt.Sprintf("%v", data.Port)
		}
	case "ssr":
		trimmed := strings.TrimPrefix(config, "ssr://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err == nil {
			parts := strings.Split(decoded, ":")
			if len(parts) >= 2 {
				return parts[0], parts[1]
			}
		}
	default:
		u, err := url.Parse(config)
		if err == nil {
			port := u.Port()
			if i := strings.IndexAny(port, ",-"); i >= 0 {
				port = port[:i]
			}
			return u.Hostname(), port
		}
	}
	return "", ""
}
