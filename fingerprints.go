package main

import (
	"regexp"
	"strings"
)

type Fingerprint struct {
	Name  string
	Check func(headers map[string]string, body string, title string, status int) (string, map[string]string)
}

var fingerprints = []Fingerprint{
	{
		Name: "Gitea",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if v, ok := h["x-gitea-version"]; ok {
				return "Gitea", map[string]string{"version": v}
			}
			if strings.Contains(h["set-cookie"], "i_like_gitea") {
				return "Gitea", nil
			}
			if strings.Contains(body, "gitea") || strings.Contains(body, "Gitea") {
				return "Gitea", nil
			}
			return "", nil
		},
	},
	{
		Name: "Forgejo",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if v, ok := h["x-forgejo-version"]; ok {
				return "Forgejo", map[string]string{"version": v}
			}
			if strings.Contains(body, "forgejo") || strings.Contains(body, "Forgejo") {
				return "Forgejo", nil
			}
			return "", nil
		},
	},
	{
		Name: "Grafana",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if _, ok := h["x-grafana-login"]; ok {
				return "Grafana", nil
			}
			if title == "Grafana" {
				return "Grafana", nil
			}
			if strings.Contains(body, "grafana") && (strings.Contains(body, "app") || strings.Contains(body, "login")) {
				return "Grafana", nil
			}
			return "", nil
		},
	},
	{
		Name: "Zabbix",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "zbx_sessionid") || strings.Contains(body, "zabbix.php") {
				return "Zabbix", nil
			}
			if title == "Zabbix" || strings.HasPrefix(title, "Zabbix ") {
				return "Zabbix", nil
			}
			return "", nil
		},
	},
	{
		Name: "Jenkins",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if _, ok := h["x-jenkins"]; ok {
				return "Jenkins", nil
			}
			if title == "Jenkins" || strings.Contains(title, "Jenkins") {
				return "Jenkins", nil
			}
			return "", nil
		},
	},
	{
		Name: "GitLab",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(h["set-cookie"], "_gitlab_session") {
				return "GitLab", nil
			}
			if strings.Contains(body, "GitLab") || strings.Contains(body, "gitlab") {
				return "GitLab", nil
			}
			if title == "GitLab" || strings.Contains(title, "GitLab") {
				return "GitLab", nil
			}
			return "", nil
		},
	},
	{
		Name: "Prometheus",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Prometheus Time Series Collection and Processing Server" {
				return "Prometheus", nil
			}
			if strings.Contains(body, "prometheus") && (strings.Contains(body, "/graph") || strings.Contains(body, "/alerts")) {
				return "Prometheus", nil
			}
			return "", nil
		},
	},
	{
		Name: "Kibana",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if v, ok := h["kbn-name"]; ok {
				return "Kibana", map[string]string{"kbn": v}
			}
			if v, ok := h["kbn-version"]; ok {
				return "Kibana", map[string]string{"version": v}
			}
			if title == "Kibana" || strings.Contains(title, "Kibana") {
				return "Kibana", nil
			}
			return "", nil
		},
	},
	{
		Name: "Elasticsearch",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "cluster_name") && strings.Contains(body, "cluster_uuid") {
				return "Elasticsearch", nil
			}
			return "", nil
		},
	},
	{
		Name: "Jupyter",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Jupyter Notebook" || title == "JupyterLab" {
				return "Jupyter", nil
			}
			if strings.Contains(body, "jupyter") || strings.Contains(body, "Jupyter") {
				return "Jupyter", nil
			}
			return "", nil
		},
	},
	{
		Name: "phpMyAdmin",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "phpMyAdmin" {
				return "phpMyAdmin", nil
			}
			if strings.Contains(body, "phpMyAdmin") || strings.Contains(body, "phpmyadmin") {
				return "phpMyAdmin", nil
			}
			return "", nil
		},
	},
	{
		Name: "SonarQube",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "SonarQube" || strings.Contains(body, "SonarQube") {
				return "SonarQube", nil
			}
			return "", nil
		},
	},
	{
		Name: "MinIO",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if h["server"] == "MinIO" {
				return "MinIO", nil
			}
			if strings.Contains(body, "MinIO Console") || strings.Contains(body, "minio") {
				return "MinIO", nil
			}
			return "", nil
		},
	},
	{
		Name: "Harbor",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Harbor" || strings.Contains(body, "harbor") {
				return "Harbor", nil
			}
			return "", nil
		},
	},
	{
		Name: "ArgoCD",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Argo CD" || strings.Contains(body, "argo-cd") || strings.Contains(body, "argocd") {
				return "ArgoCD", nil
			}
			return "", nil
		},
	},
	{
		Name: "Airflow",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Airflow" || strings.Contains(body, "Apache Airflow") || strings.Contains(body, "airflow") {
				return "Airflow", nil
			}
			return "", nil
		},
	},
	{
		Name: "Superset",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Apache Superset") || strings.Contains(body, "superset") {
				return "Superset", nil
			}
			return "", nil
		},
	},
	{
		Name: "Metabase",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Metabase") || strings.Contains(body, "metabase") {
				return "Metabase", nil
			}
			return "", nil
		},
	},
	{
		Name: "Redmine",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Redmine" || strings.Contains(body, "Redmine") {
				return "Redmine", nil
			}
			return "", nil
		},
	},
	{
		Name: "Netdata",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if h["server"] == "Netdata" {
				return "Netdata", nil
			}
			if strings.Contains(body, "netdata") || strings.Contains(body, "Netdata") {
				return "Netdata", nil
			}
			return "", nil
		},
	},
	{
		Name: "Portainer",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Portainer" || strings.Contains(body, "Portainer") {
				return "Portainer", nil
			}
			return "", nil
		},
	},
	{
		Name: "Traefik",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(strings.ToLower(h["server"]), "traefik") {
				return "Traefik", nil
			}
			if strings.HasPrefix(h["x-traefik-"], "/") {
				return "Traefik", nil
			}
			return "", nil
		},
	},
	{
		Name: "NPM",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Nginx Proxy Manager" || strings.Contains(body, "Nginx Proxy Manager") {
				return "Nginx Proxy Manager", nil
			}
			return "", nil
		},
	},
	{
		Name: "HomeAssistant",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Home Assistant" || strings.Contains(body, "Home Assistant") {
				return "Home Assistant", nil
			}
			if strings.Contains(body, "/frontend_latest/") && strings.Contains(body, "hass") {
				return "Home Assistant", nil
			}
			return "", nil
		},
	},
	{
		Name: "Nextcloud",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Nextcloud" || strings.Contains(body, "Nextcloud") {
				if !strings.Contains(body, "ownCloud") {
					return "Nextcloud", nil
				}
			}
			return "", nil
		},
	},
	{
		Name: "ownCloud",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "ownCloud" || strings.Contains(body, "ownCloud") {
				if !strings.Contains(body, "Nextcloud") {
					return "ownCloud", nil
				}
			}
			return "", nil
		},
	},
	{
		Name: "WordPress",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "/wp-content/") || strings.Contains(body, "/wp-includes/") {
				return "WordPress", nil
			}
			if strings.Contains(body, "wp-json") {
				return "WordPress", nil
			}
			return "", nil
		},
	},
	{
		Name: "Cockpit",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Cockpit" || strings.Contains(body, "Cockpit") {
				return "Cockpit", nil
			}
			return "", nil
		},
	},
	{
		Name: "pgAdmin",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "pgAdmin" || strings.Contains(body, "pgAdmin") {
				return "pgAdmin", nil
			}
			return "", nil
		},
	},
	{
		Name: "UptimeKuma",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Uptime Kuma" || strings.Contains(body, "Uptime Kuma") {
				return "Uptime Kuma", nil
			}
			return "", nil
		},
	},
	{
		Name: "NodeRED",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Node-RED" || strings.Contains(body, "Node-RED") {
				return "Node-RED", nil
			}
			return "", nil
		},
	},
	{
		Name: "WeKan",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "WeKan") || strings.Contains(body, "wekan") {
				return "WeKan", nil
			}
			return "", nil
		},
	},
	{
		Name: "Mattermost",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Mattermost" || strings.Contains(body, "Mattermost") {
				return "Mattermost", nil
			}
			return "", nil
		},
	},
	{
		Name: "RocketChat",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Rocket.Chat") || strings.Contains(body, "rocketchat") {
				return "Rocket.Chat", nil
			}
			return "", nil
		},
	},
	{
		Name: "Sentry",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Sentry" || strings.Contains(body, "Sentry") {
				return "Sentry", nil
			}
			return "", nil
		},
	},
	{
		Name: "CouchDB",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			s := h["server"]
			if s == "CouchDB" || strings.HasPrefix(s, "CouchDB/") {
				return "CouchDB", nil
			}
			return "", nil
		},
	},
	{
		Name: "Consul",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Consul" || strings.Contains(body, "consul") {
				return "Consul", nil
			}
			return "", nil
		},
	},
	{
		Name: "Vault",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "vault") && strings.Contains(body, "token") {
				return "Vault", nil
			}
			return "", nil
		},
	},
	{
		Name: "K8sDashboard",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Kubernetes Dashboard" || strings.Contains(body, "kubernetes-dashboard") {
				return "Kubernetes Dashboard", nil
			}
			return "", nil
		},
	},
	{
		Name: "DockerRegistry",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if h["docker-distribution-api-version"] != "" {
				return "Docker Registry", nil
			}
			if strings.Contains(body, "docker_distribution") || strings.Contains(body, "\"docker-registry\"") {
				return "Docker Registry", nil
			}
			return "", nil
		},
	},
	{
		Name: "Nexus",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Nexus Repository" || strings.Contains(body, "Nexus Repository") {
				return "Nexus Repository", nil
			}
			return "", nil
		},
	},
	{
		Name: "RabbitMQ",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "RabbitMQ Management" || strings.Contains(body, "RabbitMQ") {
				return "RabbitMQ Management", nil
			}
			return "", nil
		},
	},
	{
		Name: "PiHole",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Pi-hole" || strings.Contains(body, "Pi-hole") || strings.Contains(body, "pihole") {
				return "Pi-hole", nil
			}
			return "", nil
		},
	},
	{
		Name: "AdGuardHome",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "AdGuard Home" || strings.Contains(body, "AdGuard Home") {
				return "AdGuard Home", nil
			}
			return "", nil
		},
	},
	{
		Name: "Rundeck",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Rundeck" || strings.Contains(body, "Rundeck") {
				return "Rundeck", nil
			}
			return "", nil
		},
	},
	{
		Name: "Moodle",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Moodle") || strings.Contains(body, "moodle") {
				return "Moodle", nil
			}
			return "", nil
		},
	},
	{
		Name: "Drupal",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Drupal") || strings.Contains(body, "drupal") {
				return "Drupal", nil
			}
			return "", nil
		},
	},
	{
		Name: "Joomla",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Joomla!") || strings.Contains(body, "joomla") {
				return "Joomla", nil
			}
			return "", nil
		},
	},
	{
		Name: "MediaWiki",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "MediaWiki") || strings.Contains(body, "mediawiki") {
				return "MediaWiki", nil
			}
			return "", nil
		},
	},
	{
		Name: "WikiJS",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Wiki.js") || strings.Contains(body, "wiki.js") {
				return "Wiki.js", nil
			}
			return "", nil
		},
	},
	{
		Name: "BookStack",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "BookStack" || strings.Contains(body, "BookStack") {
				return "BookStack", nil
			}
			return "", nil
		},
	},
	{
		Name: "Ghost",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Ghost") && strings.Contains(body, "content") {
				return "Ghost", nil
			}
			return "", nil
		},
	},
	{
		Name: "Discourse",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Discourse") || strings.Contains(body, "discourse") {
				return "Discourse", nil
			}
			return "", nil
		},
	},
	{
		Name: "NocoDB",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "NocoDB") || strings.Contains(body, "nocodb") {
				return "NocoDB", nil
			}
			return "", nil
		},
	},
	{
		Name: "Directus",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Directus") || strings.Contains(body, "directus") {
				return "Directus", nil
			}
			return "", nil
		},
	},
	{
		Name: "Strapi",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Strapi") || strings.Contains(body, "strapi") {
				return "Strapi", nil
			}
			return "", nil
		},
	},
	{
		Name: "Nomad",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Nomad") && strings.Contains(body, "allocation") {
				return "Nomad", nil
			}
			return "", nil
		},
	},
	{
		Name: "phpBB",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "phpBB") || strings.Contains(body, "phpbb") {
				return "phpBB", nil
			}
			return "", nil
		},
	},
	{
		Name: "Adminer",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Adminer") || strings.Contains(body, "adminer") {
				return "Adminer", nil
			}
			return "", nil
		},
	},
	{
		Name: "OpenProject",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "OpenProject" || strings.Contains(body, "OpenProject") {
				return "OpenProject", nil
			}
			return "", nil
		},
	},
	{
		Name: "MongoExpress",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if title == "Mongo Express" || strings.Contains(body, "Mongo Express") {
				return "Mongo Express", nil
			}
			return "", nil
		},
	},
	{
		Name: "VictoriaMetrics",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "VictoriaMetrics") || strings.Contains(body, "victoriametrics") {
				return "VictoriaMetrics", nil
			}
			return "", nil
		},
	},
	{
		Name: "Hasura",
		Check: func(h map[string]string, body, title string, status int) (string, map[string]string) {
			if strings.Contains(body, "Hasura") || strings.Contains(body, "hasura") {
				return "Hasura", nil
			}
			return "", nil
		},
	},
}

var versionPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	{re: regexp.MustCompile(`v?(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)`)},
	{re: regexp.MustCompile(`v?(\d+\.\d+[a-zA-Z0-9.-]*)`)},
}

func identifyService(headers map[string]string, body string, title string, status int) (string, map[string]string) {
	for _, fp := range fingerprints {
		service, details := fp.Check(headers, body, title, status)
		if service != "" {
			if details == nil {
				details = make(map[string]string)
			}
			if _, ok := details["version"]; !ok {
				if v := extractVersion(headers, body); v != "" {
					details["version"] = v
				}
			}
			return service, details
		}
	}

	if isCommonWebServer(headers) {
		return "WebServer", map[string]string{
			"server": headers["server"],
		}
	}

	return "", nil
}

func extractVersion(headers map[string]string, body string) string {
	for k, v := range headers {
		key := strings.ToLower(k)
		if strings.Contains(key, "version") {
			if ver := extractSemver(v); ver != "" {
				return ver
			}
		}
	}
	limit := len(body)
	if limit > 4096 {
		limit = 4096
	}
	if ver := extractSemver(body[:limit]); ver != "" {
		return ver
	}
	return ""
}

func extractSemver(s string) string {
	re := regexp.MustCompile(`(\d+\.\d+\.\d+[a-zA-Z0-9._-]*)`)
	m := re.FindString(s)
	if m != "" && len(m) < 20 {
		return m
	}
	re2 := regexp.MustCompile(`(\d+\.\d+[a-zA-Z0-9._-]*)`)
	m2 := re2.FindString(s)
	if m2 != "" && len(m2) < 15 {
		return m2
	}
	return ""
}

func isCommonWebServer(headers map[string]string) bool {
	server := strings.ToLower(headers["server"])
	common := []string{"nginx", "apache", "iis", "caddy", "lighttpd", "openresty", "tengine", "tomcat"}
	for _, c := range common {
		if strings.Contains(server, c) {
			return true
		}
	}
	return headers["content-type"] != "" || headers["x-powered-by"] != ""
}
