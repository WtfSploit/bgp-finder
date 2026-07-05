package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type crtEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func dorkCRTSH(keyword string, verbose bool) ([]string, error) {
	keyword = url.QueryEscape(keyword)
	url := fmt.Sprintf("https://crt.sh/?q=%s&identity=%s&output=json", keyword, keyword)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgents[0])
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("crt.sh read: %v", err)
	}

	// crt.sh may return HTML error page instead of JSON
	if len(body) == 0 || body[0] != '[' {
		return nil, fmt.Errorf("crt.sh returned non-JSON (likely rate-limited)")
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh parse: %v", err)
	}

	domainSet := map[string]bool{}
	for _, e := range entries {
		domains := strings.Split(e.NameValue, "\n")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			d = strings.TrimPrefix(d, "*.")
			d = strings.TrimPrefix(d, "www.")
			d = strings.ToLower(d)
			if !strings.Contains(d, keywordLower(keyword)) {
				continue
			}
			if isLikelyDomain(d) {
				domainSet[d] = true
			}
		}
	}

	var domains []string
	for d := range domainSet {
		domains = append(domains, d)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "crt.sh: found %d unique domains for %q\n", len(domains), keyword)
	}

	return domains, nil
}

func keywordLower(k string) string {
	return strings.ToLower(k)
}

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$`)

func isLikelyDomain(s string) bool {
	return domainRe.MatchString(s) && strings.Count(s, ".") >= 1
}

func dorkWHOIS(keyword string, verbose bool) ([]string, error) {
	cmd := exec.Command("whois", "-h", "whois.radb.net", fmt.Sprintf("-i origin %s", keyword))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	asnRe := regexp.MustCompile(`(?i)origin:\s*AS(\d+)`)
	matches := asnRe.FindAllStringSubmatch(string(out), -1)
	seen := map[string]bool{}
	var asns []string
	for _, m := range matches {
		as := m[1]
		if !seen[as] {
			seen[as] = true
			asns = append(asns, as)
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "WHOIS dork: found ASNs %v for %q\n", asns, keyword)
	}

	return asns, nil
}

func dorkPTRInRange(ips []net.IP, keyword string, concurrency int, timeout time.Duration, verbose bool) []PTRMatch {
	keywordLower := strings.ToLower(keyword)
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var matches []PTRMatch

	resolver := &net.Resolver{}
	ctx := context.Background()

	for _, ip := range ips {
		sem <- struct{}{}
		go func(ipStr string) {
			defer func() { <-sem }()
			names, err := resolver.LookupAddr(ctx, ipStr)
			if err != nil || len(names) == 0 {
				return
			}
			hostname := strings.ToLower(names[0])
			if strings.Contains(hostname, keywordLower) {
				ptr := strings.TrimSuffix(names[0], ".")
				mu.Lock()
				matches = append(matches, PTRMatch{IP: ipStr, PTR: ptr})
				mu.Unlock()
				if verbose {
					fmt.Fprintf(os.Stderr, "\n[PTR] %s -> %s\n", ipStr, ptr)
				}
			}
		}(ip.String())
	}

	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	return matches
}

type PTRMatch struct {
	IP  string
	PTR string
}

func resolveDomains(domains []string, concurrency int, verbose bool) []string {
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var ips []string
	seen := map[string]bool{}

	resolver := &net.Resolver{}
	ctx := context.Background()

	for _, domain := range domains {
		sem <- struct{}{}
		go func(d string) {
			defer func() { <-sem }()
			addrs, err := resolver.LookupIPAddr(ctx, d)
			if err != nil || len(addrs) == 0 {
				if verbose {
					fmt.Fprintf(os.Stderr, "  [dns] %s -> unresolved\n", d)
				}
				return
			}
			for _, a := range addrs {
				ip := a.IP.String()
				if a.IP.To4() == nil {
					continue
				}
				mu.Lock()
				if !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
				mu.Unlock()
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "  [dns] %s -> %s\n", d, addrs[0].IP)
			}
		}(domain)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	return ips
}

// --- InternetDB (Shodan.io) ---

type internetDBEntry struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	CPEs      []string `json:"cpes"`
	Vulns     []string `json:"vulns"`
}

func dorkInternetDB(ips []net.IP, keyword string, concurrency int, verbose bool) []internetDBEntry {
	keywordLower := strings.ToLower(keyword)
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var matches []internetDBEntry

	client := &http.Client{Timeout: 10 * time.Second}

	for _, ip := range ips {
		sem <- struct{}{}
		go func(ipStr string) {
			defer func() { <-sem }()
			url := fmt.Sprintf("https://internetdb.shodan.io/%s", ipStr)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", userAgents[0])

			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != 200 {
				return
			}
			defer resp.Body.Close()

			var entry internetDBEntry
			if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
				return
			}

			// Check if keyword matches any field
			for _, h := range entry.Hostnames {
				if strings.Contains(strings.ToLower(h), keywordLower) {
					mu.Lock()
					matches = append(matches, entry)
					mu.Unlock()
					if verbose {
						fmt.Fprintf(os.Stderr, "[internetdb] %s (%s) hostname match: %s\n", ipStr, keyword, h)
					}
					return
				}
			}
			for _, c := range entry.CPEs {
				if strings.Contains(strings.ToLower(c), keywordLower) {
					mu.Lock()
					matches = append(matches, entry)
					mu.Unlock()
					if verbose {
						fmt.Fprintf(os.Stderr, "[internetdb] %s (%s) cpe match: %s\n", ipStr, keyword, c)
					}
					return
				}
			}
			for _, t := range entry.Tags {
				if strings.Contains(strings.ToLower(t), keywordLower) {
					mu.Lock()
					matches = append(matches, entry)
					mu.Unlock()
					if verbose {
						fmt.Fprintf(os.Stderr, "[internetdb] %s (%s) tag match: %s\n", ipStr, keyword, t)
					}
					return
				}
			}
		}(ip.String())
	}

	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	return matches
}
