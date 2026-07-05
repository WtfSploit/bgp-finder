package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	asn := flag.String("asn", "", "ASN number (e.g. 13335) or full name (AS13335)")
	org := flag.String("org", "", "Organization name to search ASN for")
	cidr := flag.String("cidr", "", "CIDR range directly (e.g. 192.168.0.0/24)")
	cidrFile := flag.String("cidr-file", "", "File with CIDR ranges (one per line)")
	dork := flag.String("dork", "", "Keyword for dork search")
	useInternetDB := flag.Bool("internetdb", false, "Use Shodan InternetDB as primary source")
	ports := flag.String("ports", "80,443,8080,8443,3000,9090,9000,9443", "Ports to scan")
	concurrency := flag.Int("c", 100, "Concurrent workers")
	timeout := flag.Int("timeout", 5, "TCP connect timeout in seconds")
	maxIPs := flag.Int("max-ips", 10000, "Maximum IPs to scan (0 = unlimited)")
	output := flag.String("o", "", "Output file (default: stdout)")
	jsonOutput := flag.Bool("json", false, "JSON output")
	noBanner := flag.Bool("no-banner", false, "Suppress banner")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `bgp_finder — поиск сервисов через BGP записи, дорки и InternetDB

Источники:
  - RIPEStat API    — получение префиксов ASN
  - Shodan InternetDB — база открытых портов и сервисов (без API-ключа)
  - crt.sh          — поиск по SSL-сертификатам
  - PTR/rDNS        — обратные DNS-записи
  - WHOIS           — данные о сетях и ASN

Режимы:
  bgp_finder -asn 24961                                      # сканировать ASN
  bgp_finder -asn 24961 -internetdb                          # InternetDB
  bgp_finder -asn 24961 -dork gitea                          # PTR-дорк
  bgp_finder -asn 24961 -dork gitea -internetdb              # InternetDB-дорк
  bgp_finder -dork gitea                                     # глобальный поиск (crt.sh)
  bgp_finder -cidr 192.168.0.0/24 -dork zabbix -internetdb  # InternetDB на диапазоне

-dork + -internetdb: ищет ключевое слово в hostname/cpe/tag из InternetDB
-dork без -internetdb: ищет в PTR/rDNS на IP диапазона

Параметры:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	if !*noBanner {
		fmt.Fprintln(os.Stderr, banner)
	}

	scanCfg := ScanConfig{
		Ports:       parsePorts(*ports),
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeout) * time.Second,
		Verbose:     *verbose,
		OutputJSON:  *jsonOutput,
		Dork:        *dork,
	}

	var w *bufio.Writer
	if *output != "" {
		os.MkdirAll(filepath.Dir(*output), 0755)
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = bufio.NewWriter(f)
		defer w.Flush()
	} else {
		w = bufio.NewWriter(os.Stdout)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nInterrupted")
		os.Exit(1)
	}()

	// --- Глобальный dork (без ASN/CIDR) — crt.sh + WHOIS ---
	if *dork != "" && *asn == "" && *org == "" && *cidr == "" && *cidrFile == "" {
		runGlobalDork(*dork, scanCfg, *maxIPs, w)
		return
	}

	// --- Режим с диапазонами ---
	ranges, err := resolveRanges(*asn, *org, *cidr, *cidrFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving ranges: %v\n", err)
		os.Exit(1)
	}
	if len(ranges) == 0 {
		fmt.Fprintln(os.Stderr, "No ranges to scan")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Targets: %d CIDR ranges\n", len(ranges))

	ips := expandRanges(ranges, *maxIPs, *verbose)
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "No IPs to scan (empty ranges)")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "IPs: %d\n", len(ips))

	switch {
	case *dork != "" && *useInternetDB:
		fmt.Fprintf(os.Stderr, "Mode: InternetDB dork for %q\n", *dork)
		runInternetDBDork(ips, *dork, scanCfg, w)
	case *dork != "":
		fmt.Fprintf(os.Stderr, "Mode: PTR dork for %q\n", *dork)
		scanCfg.Dork = *dork
		RunScanner(ips, scanCfg, w)
	case *useInternetDB:
		fmt.Fprintf(os.Stderr, "Mode: InternetDB scan\n")
		runInternetDBDork(ips, "", scanCfg, w)
	default:
		fmt.Fprintf(os.Stderr, "Ports: %d\n", len(scanCfg.Ports))
		RunScanner(ips, scanCfg, w)
	}
}

func runGlobalDork(keyword string, cfg ScanConfig, maxIPs int, w *bufio.Writer) {
	fmt.Fprintf(os.Stderr, "[dork] Global search for %q (crt.sh + WHOIS)...\n", keyword)
	var allIPs []string

	domains, err := dorkCRTSH(keyword, cfg.Verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[dork] crt.sh: %v\n", err)
	} else if len(domains) > 0 {
		fmt.Fprintf(os.Stderr, "[dork] Resolving %d domains...\n", len(domains))
		allIPs = append(allIPs, resolveDomains(domains, cfg.Concurrency, cfg.Verbose)...)
	}

	asns, _ := dorkWHOIS(keyword, cfg.Verbose)
	for _, as := range asns {
		fmt.Fprintf(os.Stderr, "[dork] AS%s via PTR...\n", as)
		ranges, err := fetchPrefixesRIPE(as)
		if err != nil {
			continue
		}
		expanded := expandRanges(ranges, maxIPs, cfg.Verbose)
		for _, m := range dorkPTRInRange(expanded, keyword, cfg.Concurrency, cfg.Timeout, cfg.Verbose) {
			allIPs = append(allIPs, m.IP)
		}
	}

	if len(allIPs) == 0 {
		fmt.Fprintf(os.Stderr, "[dork] No targets found for %q\n", keyword)
		os.Exit(1)
	}

	seen := map[string]bool{}
	unique := make([]net.IP, 0, len(allIPs))
	for _, s := range allIPs {
		if !seen[s] {
			seen[s] = true
			if ip := net.ParseIP(s); ip != nil {
				unique = append(unique, ip)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[dork] Unique IPs: %d\n", len(unique))
	RunScanner(unique, cfg, w)
}

func runInternetDBDork(ips []net.IP, keyword string, cfg ScanConfig, w *bufio.Writer) {
	fmt.Fprintf(os.Stderr, "Querying Shodan InternetDB (%d IPs)...\n", len(ips))

	entries := dorkInternetDB(ips, keyword, cfg.Concurrency, cfg.Verbose)
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "No matches from InternetDB\n")
		return
	}

	fmt.Fprintf(os.Stderr, "InternetDB matches: %d\n", len(entries))
	for _, e := range entries {
		hostnames := strings.Join(e.Hostnames, ", ")
		if len(hostnames) > 80 {
			hostnames = hostnames[:80] + "..."
		}
		tags := strings.Join(e.Tags, ",")
		if tags == "" {
			tags = "-"
		}
		ports := intsJoin(e.Ports, ",")

		if cfg.OutputJSON {
			fmt.Fprintf(w, `{"ip":"%s","ports":[%s],"hostnames":%q,"tags":%q}`+"\n",
				e.IP, ports, hostnames, tags)
		} else {
			line := fmt.Sprintf("%s ports=%-30s tags=%-15s %s",
				e.IP, ports, tags, hostnames)
			w.WriteString(line + "\n")
		}
	}
}

func intsJoin(v []int, sep string) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, sep)
}

func resolveRanges(asn, org, cidr, cidrFile string) ([]string, error) {
	if cidr != "" {
		return []string{cidr}, nil
	}
	if cidrFile != "" {
		return readLines(cidrFile)
	}
	if asn != "" {
		asn = strings.TrimPrefix(asn, "AS")
		return fetchPrefixesRIPE(asn)
	}
	if org != "" {
		asnList, err := resolveOrgToASN(org)
		if err != nil {
			return nil, fmt.Errorf("org -> ASN: %v", err)
		}
		if len(asnList) == 0 {
			return nil, fmt.Errorf("no ASNs found for org %q", org)
		}
		fmt.Fprintf(os.Stderr, "Found ASNs: %v\n", asnList)
		var all []string
		for _, a := range asnList {
			p, err := fetchPrefixesRIPE(a)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: AS%s: %v\n", a, err)
				continue
			}
			all = append(all, p...)
		}
		return all, nil
	}
	return nil, fmt.Errorf("specify -asn, -org, -cidr, or -cidr-file")
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, s.Err()
}

func parsePorts(s string) []int {
	parts := strings.Split(s, ",")
	var res []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			pr := strings.SplitN(p, "-", 2)
			lo, hi := atoi(pr[0]), atoi(pr[1])
			for i := lo; i <= hi; i++ {
				res = append(res, i)
			}
		} else {
			res = append(res, atoi(p))
		}
	}
	return res
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func expandRanges(ranges []string, maxIPs int, verbose bool) []net.IP {
	var ips []net.IP
	limitReached := false
	for _, r := range ranges {
		if limitReached {
			break
		}
		_, cidrNet, err := net.ParseCIDR(r)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "Skipping invalid CIDR %q: %v\n", r, err)
			}
			continue
		}
		_, bits := cidrNet.Mask.Size()
		if bits == 128 {
			if verbose {
				fmt.Fprintf(os.Stderr, "Skipping IPv6 %s\n", r)
			}
			continue
		}

		var ipsInRange []net.IP
		for ip := cidrNet.IP.Mask(cidrNet.Mask); cidrNet.Contains(ip); incIP(ip) {
			dst := make(net.IP, len(ip))
			copy(dst, ip)
			if !isBroadcast(dst, cidrNet) {
				ipsInRange = append(ipsInRange, dst)
			}
		}

		if len(ipsInRange) == 0 {
			continue
		}

		remaining := maxIPs - len(ips)
		if maxIPs > 0 && remaining <= 0 {
			limitReached = true
			break
		}
		if maxIPs > 0 && len(ipsInRange) > remaining {
			if verbose {
				fmt.Fprintf(os.Stderr, "Truncating %s (%d IPs) to %d\n", r, len(ipsInRange), remaining)
			}
			ipsInRange = ipsInRange[:remaining]
		}

		ips = append(ips, ipsInRange...)
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, netw *net.IPNet) bool {
	if ip.To4() == nil {
		return false
	}
	last := make(net.IP, len(netw.IP))
	copy(last, netw.IP)
	for i := range last {
		last[i] |= ^netw.Mask[i]
	}
	return ip.Equal(last)
}

const banner = `  ╔══════════════════════════════════════════╗
  ║   BGP Finder — service discovery      ║
  ║   BGP / InternetDB / crt.sh / PTR     ║
  ╚══════════════════════════════════════════╝
`
