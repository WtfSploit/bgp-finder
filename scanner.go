package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ScanConfig struct {
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	Verbose     bool
	OutputJSON  bool
	Dork        string
}

type ScanResult struct {
	IP      string
	Port    int
	Service string
	Details map[string]string
	PTR     string
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
}

func RunScanner(ips []net.IP, cfg ScanConfig, w *bufio.Writer) {
	totalIPs := int64(len(ips))
	totalTargets := totalIPs * int64(len(cfg.Ports))
	var scannedTargets atomic.Int64
	var found atomic.Int64
	var matched atomic.Int64
	start := time.Now()

	sem := make(chan struct{}, cfg.Concurrency)
	var mu sync.Mutex

	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			Dial: (&net.Dialer{Timeout: cfg.Timeout}).Dial,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resolver := &net.Resolver{}

	for _, ip := range ips {
		ipStr := ip.String()
		sem <- struct{}{}
		go func(ipStr string) {
			defer func() { <-sem }()

			// --- PTR dork stage ---
			if cfg.Dork != "" {
				names, err := resolver.LookupAddr(context.Background(), ipStr)
				if err != nil || len(names) == 0 {
					scannedTargets.Add(int64(len(cfg.Ports)))
					return
				}
				hostname := strings.ToLower(names[0])
				dorkLower := strings.ToLower(cfg.Dork)
				if !strings.Contains(hostname, dorkLower) {
					scannedTargets.Add(int64(len(cfg.Ports)))
					return
				}
				matched.Add(1)
				ptr := strings.TrimSuffix(names[0], ".")

				// --- Port scan + HTTP fingerprint for matching IPs ---
				for _, port := range cfg.Ports {
					addr := net.JoinHostPort(ipStr, fmt.Sprint(port))
					conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
					if err != nil {
						scannedTargets.Add(1)
						continue
					}
					conn.Close()

					service, details := fingerprintHTTP(httpClient, ipStr, port)
					if service == "" {
						mu.Lock()
						fmt.Fprintf(os.Stderr, "\r[PTR] %s (%s) port %d open — unknown service\n", ipStr, ptr, port)
						mu.Unlock()
					}

					if service != "" {
						found.Add(1)
						result := ScanResult{
							IP:      ipStr,
							Port:    port,
							Service: service,
							Details: details,
							PTR:     ptr,
						}
						mu.Lock()
						outputDorkResult(result, cfg.OutputJSON, w)
						mu.Unlock()
					}
					scannedTargets.Add(1)
				}
			} else {
				// --- Normal mode: scan all ports, HTTP fingerprint ---
				for _, port := range cfg.Ports {
					addr := net.JoinHostPort(ipStr, fmt.Sprint(port))
					conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
					if err != nil {
						scannedTargets.Add(1)
						continue
					}
					conn.Close()

					service, details := fingerprintHTTP(httpClient, ipStr, port)
					if service != "" {
						found.Add(1)
						result := ScanResult{IP: ipStr, Port: port, Service: service, Details: details}
						mu.Lock()
						outputResult(result, cfg.OutputJSON, w)
						mu.Unlock()
					}
					scannedTargets.Add(1)
				}
			}

			s := scannedTargets.Load()
			if s%1000 == 0 && cfg.Verbose {
				elapsed := time.Since(start)
				pct := float64(s) / float64(totalTargets) * 100
				m := matched.Load()
				f := found.Load()
				dorkInfo := ""
				if cfg.Dork != "" {
					dorkInfo = fmt.Sprintf(" | PTR matched: %d", m)
				}
				fmt.Fprintf(os.Stderr, "\rProgress: %.1f%% (%d/%d) | Found: %d%s | %s",
					pct, s, totalTargets, f, dorkInfo, elapsed.Round(time.Second))
			}
		}(ipStr)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	elapsed := time.Since(start)
	f := found.Load()
	m := matched.Load()
	stats := ""
	if cfg.Dork != "" {
		stats = fmt.Sprintf(", PTR matched: %d", m)
	}
	fmt.Fprintf(os.Stderr, "\rDone in %s — scanned %d targets, found %d services%s\n",
		elapsed.Round(time.Second), totalTargets, f, stats)
}

func fingerprintHTTP(client *http.Client, ip string, port int) (string, map[string]string) {
	proto := "http"
	if port == 443 || port == 8443 || port == 9443 {
		proto = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", proto, ip, port)
	ua := userAgents[time.Now().UnixNano()%int64(len(userAgents))]

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		if proto == "https" {
			req2, _ := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/", ip, port), nil)
			if req2 != nil {
				req2.Header.Set("User-Agent", ua)
				req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				resp, err = client.Do(req2)
				if err != nil {
					return "", nil
				}
			} else {
				return "", nil
			}
		} else {
			return "", nil
		}
	}
	if resp == nil {
		return "", nil
	}
	defer resp.Body.Close()

	bodyBytes := make([]byte, 65536)
	n, _ := io.ReadFull(resp.Body, bodyBytes)
	body := string(bodyBytes[:n])

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	title := extractTitle(body)
	service, details := identifyService(headers, body, title, resp.StatusCode)

	if service != "" {
		if details == nil {
			details = make(map[string]string)
		}
		if title != "" {
			if _, ok := details["title"]; !ok {
				details["title"] = title
			}
		}
		details["status"] = fmt.Sprint(resp.StatusCode)
		if h, ok := headers["server"]; ok {
			details["server"] = h
		}
	}

	return service, details
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	start = strings.Index(body[start:], ">")
	if start == -1 {
		return ""
	}
	start += 1
	end := strings.Index(body[start:], "</title>")
	if end == -1 {
		return ""
	}
	t := body[start : start+end]
	t = strings.TrimSpace(t)
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func outputResult(r ScanResult, jsonOut bool, w *bufio.Writer) {
	if jsonOut {
		fmt.Fprintf(w, `{"ip":"%s","port":%d,"service":"%s","details":%s}`+"\n",
			r.IP, r.Port, r.Service, mapToJSON(r.Details))
	} else {
		details := ""
		if r.Details != nil {
			if t, ok := r.Details["title"]; ok && t != "" {
				details = fmt.Sprintf(" [%s]", t)
			}
			if v, ok := r.Details["version"]; ok && v != "" {
				details += fmt.Sprintf(" v%s", v)
			}
		}
		line := fmt.Sprintf("%s:%-5d %s%s", r.IP, r.Port, r.Service, details)
		w.WriteString(line + "\n")
	}
}

func outputDorkResult(r ScanResult, jsonOut bool, w *bufio.Writer) {
	if jsonOut {
		details := ""
		if r.Details != nil {
			details = mapToJSON(r.Details)
		}
		fmt.Fprintf(w, `{"ip":"%s","port":%d,"service":"%s","ptr":"%s","details":%s}`+"\n",
			r.IP, r.Port, r.Service, r.PTR, details)
	} else {
		details := ""
		if r.Details != nil {
			if t, ok := r.Details["title"]; ok && t != "" {
				details = fmt.Sprintf(" [%s]", t)
			}
			if v, ok := r.Details["version"]; ok && v != "" {
				details += fmt.Sprintf(" v%s", v)
			}
		}
		line := fmt.Sprintf("%s:%-5d %-15s %s%s", r.IP, r.Port, r.Service, r.PTR, details)
		w.WriteString(line + "\n")
	}
}

func mapToJSON(m map[string]string) string {
	if m == nil {
		return "{}"
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		v = strings.ReplaceAll(v, "\\", "\\\\")
		v = strings.ReplaceAll(v, "\"", "\\\"")
		parts = append(parts, fmt.Sprintf("%q:%q", k, v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
