<div align="center">

# bgp-finder

**BGP-based service discovery** — Find Gitea, Grafana, Zabbix, Jenkins, GitLab and 50+ services across any ASN using Shodan InternetDB, PTR dorks, crt.sh and HTTP fingerprinting.

No API keys required. No Shodan/Censys accounts.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/WtfSploit/bgp-finder/pulls)

</div>

---

## Features

- **4 data sources** in one tool: Shodan InternetDB, PTR/rDNS, crt.sh, HTTP fingerprinting
- **50+ service fingerprints** — Gitea, Forgejo, Grafana, Zabbix, Jenkins, GitLab, Prometheus, Kibana, Elasticsearch, Jupyter, phpMyAdmin, SonarQube, MinIO, Harbor, ArgoCD, Airflow, Netdata, Portainer, WordPress, and many more
- **BGP integration** — resolve any ASN to IP prefixes via RIPEStat API
- **InternetDB mode** — zero-scan intelligence. Query Shodan InternetDB for open ports, hostnames, tags, and CPEs
- **Dork modes** — PTR dork, crt.sh dork, WHOIS dork, InternetDB dork
- **No API keys** — all sources are free and public
- **Concurrent** — high-performance async scanner with configurable concurrency

## Installation

```bash
# Go install
go install github.com/WtfSploit/bgp-finder@latest

# Or download binary from releases
# Or build from source
git clone https://github.com/WtfSploit/bgp-finder.git
cd bgp-finder
go build -o bgp-finder .
```

## Usage

### Scan all IPs in an ASN

```bash
# Scan Hetzner (AS24961) on common web ports
./bgp-finder -asn 24961 -ports 80,443,3000,8080,8443,9090

# Output: IP:port  Service [Title]
# 5.75.128.1:443  Grafana
# 5.75.128.2:3000 Gitea
# 5.75.128.3:8080 Jenkins
```

### Scan with Shodan InternetDB (fastest)

```bash
# No port scanning — uses Shodan's pre-scanned data
./bgp-finder -asn 24961 -internetdb

# Output: IP  ports=80,443  tags=cdn  hostname.example.com
```

### Dork within an ASN

```bash
# Find IPs with "gitea" in Shodan's hostname/CPE/tag
./bgp-finder -asn 24961 -internetdb -dork gitea

# Find IPs with "grafana" in PTR (reverse DNS) records
./bgp-finder -asn 24961 -dork grafana

# Find IPs with "zabbix" in hostname
./bgp-finder -asn 24961 -internetdb -dork zabbix
```

### Global search (no ASN required)

```bash
# Search via crt.sh SSL certificates + WHOIS
./bgp-finder -dork gitea

# Resolves domains → DNS → HTTP fingerprinting
```

### By organization name

```bash
./bgp-finder -org Hetzner -dork nginx -internetdb
./bgp-finder -org "DigitalOcean" -ports 3000
```

### Custom CIDR range

```bash
./bgp-finder -cidr 192.168.0.0/24 -dork jenkins -internetdb
./bgp-finder -cidr-file ranges.txt -ports 80,443
```

## Data Sources

| Source | Type | Auth | Description |
|---|---|---|---|
| [RIPEStat](https://stat.ripe.net/) | BGP | None | Resolve ASN → IP prefixes |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Ports/Services | None | Open ports, hostnames, tags, CPEs |
| [crt.sh](https://crt.sh/) | Certificates | None | SSL certificate transparency search |
| PTR/rDNS | DNS | None | Reverse DNS lookups |
| HTTP fingerprinting | Web | None | 50+ service signatures |

## Detected Services

```
Gitea / Forgejo    Grafana              Zabbix
Jenkins            GitLab               Prometheus
Kibana             Elasticsearch        Jupyter
phpMyAdmin         SonarQube            MinIO
Harbor             ArgoCD               Airflow
Superset           Metabase             Redmine
Netdata            Portainer            Traefik
Nginx Proxy Mgr    Home Assistant       Nextcloud
ownCloud           WordPress            Cockpit
pgAdmin            Uptime Kuma          Node-RED
WeKan              Mattermost           Rocket.Chat
Sentry             CouchDB              Consul
Vault              K8s Dashboard        Docker Registry
Nexus Repository   RabbitMQ             Pi-hole
AdGuard Home       Rundeck              Moodle
Drupal             Joomla               MediaWiki
Wiki.js            BookStack            Ghost
Discourse          NocoDB               Directus
Strapi             Nomad                phpBB
Adminer            OpenProject          Mongo Express
VictoriaMetrics    Hasura
```

## Examples

```bash
# Quick recon of a hosting provider
./bgp-finder -asn 24961 -internetdb -max-ips 5000

# Find vulnerable Grafana instances
./bgp-finder -asn 16276 -internetdb -dork grafana

# Full scan with HTTP fingerprinting
./bgp-finder -asn 13335 -ports 80,443,3000,8080,8443,9090 -c 200 -max-ips 10000

# JSON output, save to file
./bgp-finder -asn 24961 -internetdb -dork gitea -json -o results.json

# Global certificate search
./bgp-finder -dork gitea -ports 3000
```

## How It Works

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│  RIPEStat   │    │  InternetDB  │    │   crt.sh    │
│  (prefixes) │    │  (services)  │    │  (certs)    │
└──────┬──────┘    └──────┬───────┘    └──────┬──────┘
       │                  │                   │
       ▼                  ▼                   ▼
   ┌───────────────────────────────────────────────┐
   │              IP Targets                        │
   └──────────────────┬────────────────────────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
    ┌────▼────┐              ┌─────▼─────┐
    │ PTR/rDNS│              │  InternetDB │
    │ + filter│              │  + filter   │
    └────┬────┘              └─────┬───────┘
         │                         │
         └──────────┬──────────────┘
                    ▼
         ┌────────────────────┐
         │  HTTP Fingerprint  │
         │  (50+ signatures)  │
         └────────┬───────────┘
                  ▼
           ┌──────────┐
           │  Results  │
           └──────────┘
```

## License

MIT
