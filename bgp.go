package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

type ripeResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
	Status string `json:"status"`
}

func fetchPrefixesRIPE(asn string) ([]string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ripe request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ripe read: %v", err)
	}

	var data ripeResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("ripe parse: %v", err)
	}

	if data.Status != "ok" {
		return nil, fmt.Errorf("ripe status: %s", data.Status)
	}

	var v4 []string
	for _, p := range data.Data.Prefixes {
		if !strings.Contains(p.Prefix, ":") {
			v4 = append(v4, p.Prefix)
		}
	}

	if len(v4) == 0 {
		return nil, fmt.Errorf("no IPv4 prefixes found for AS%s", asn)
	}

	return v4, nil
}

var knownOrgs = map[string][]string{
	"cloudflare":     {"13335"},
	"gtt":            {"3257", "5580", "15395"},
	"ovh":            {"16276", "35540"},
	"hetzner":        {"24961"},
	"digitalocean":   {"14061"},
	"linode":         {"63949"},
	"vultr":          {"20473"},
	"aws":            {"16509", "14618", "8987"},
	"amazon":         {"16509", "14618", "8987"},
	"google":         {"15169", "396982", "36384"},
	"microsoft":      {"8075", "12076"},
	"azure":          {"8075", "12076"},
	"oracle":         {"31898"},
	"gcore":          {"199524"},
	"selectel":       {"49505"},
	"timeweb":        {"9123"},
	"ddos-guard":     {"57724"},
	"mts":            {"8359"},
	"beeline":        {"8342"},
	"megafon":        {"31246"},
	"yandex":         {"200350", "43313"},
	"mail.ru":        {"47764"},
	"vkontakte":      {"47539"},
	"telegram":       {"62041", "44907"},
	"contabo":        {"51167", "58057"},
	"scaleway":       {"12876"},
	"leaseweb":       {"16190", "39603", "39604"},
}

var asnRe = regexp.MustCompile(`(?i)origin:\s+AS(\d+)`)

func resolveOrgToASN(org string) ([]string, error) {
	orgLower := strings.ToLower(org)

	if asns, ok := knownOrgs[orgLower]; ok {
		return asns, nil
	}

	seen := map[string]bool{}
	var results []string

	cmd := exec.Command("whois", "-h", "whois.radb.net", fmt.Sprintf("-i origin %s", org))
	out, err := cmd.Output()
	if err == nil {
		matches := asnRe.FindAllStringSubmatch(string(out), -1)
		for _, m := range matches {
			as := m[1]
			if !seen[as] {
				seen[as] = true
				results = append(results, as)
			}
		}
	}

	if len(results) == 0 {
		cmd := exec.Command("whois", org)
		out, err := cmd.Output()
		if err == nil {
			asnMatch := regexp.MustCompile(`(?i)AS(\d{4,})`).FindAllStringSubmatch(string(out), -1)
			for _, m := range asnMatch {
				as := m[1]
				if !seen[as] {
					seen[as] = true
					results = append(results, as)
				}
			}
		}
	}

	return results, nil
}
