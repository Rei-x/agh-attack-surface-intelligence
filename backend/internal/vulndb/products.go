package vulndb

import "strings"

// ProductDef maps a product Dzięcioł fingerprints to its NVD CPE vendor:product pairs.
type ProductDef struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// CPEs are "part:vendor:product" prefixes queried on NVD (virtualMatchString).
	CPEs []string `json:"cpes"`
	// Aliases are lower-case product / technology names as the scanner reports them
	// (nmap -sV product strings, signature technology names, header tokens).
	Aliases []string `json:"aliases"`
	// FullParts is how many numeric components a complete version has (OpenSSH "8.9" = 2,
	// nginx "1.18.0" = 3). Fewer observed components make the match "possible".
	FullParts int `json:"full_parts"`
}

// Catalog lists the fingerprinted products the snapshot covers. Hikvision is left out on
// purpose: its CVEs are per camera model firmware, which a discovery scan does not identify.
var Catalog = []ProductDef{
	{Key: "nginx", Name: "nginx", CPEs: []string{"a:f5:nginx", "a:nginx:nginx", "a:f5:nginx_open_source"}, Aliases: []string{"nginx"}, FullParts: 3},
	{Key: "apache-httpd", Name: "Apache httpd", CPEs: []string{"a:apache:http_server"}, Aliases: []string{"apache httpd", "apache http server", "apache"}, FullParts: 3},
	{Key: "openssh", Name: "OpenSSH", CPEs: []string{"a:openbsd:openssh"}, Aliases: []string{"openssh"}, FullParts: 2},
	{Key: "php", Name: "PHP", CPEs: []string{"a:php:php"}, Aliases: []string{"php"}, FullParts: 3},
	{Key: "wordpress", Name: "WordPress", CPEs: []string{"a:wordpress:wordpress"}, Aliases: []string{"wordpress"}, FullParts: 2},
	{Key: "drupal", Name: "Drupal", CPEs: []string{"a:drupal:drupal"}, Aliases: []string{"drupal"}, FullParts: 2},
	{Key: "joomla", Name: "Joomla", CPEs: []string{`a:joomla:joomla\!`}, Aliases: []string{"joomla", "joomla!"}, FullParts: 3},
	{Key: "jenkins", Name: "Jenkins", CPEs: []string{"a:jenkins:jenkins"}, Aliases: []string{"jenkins"}, FullParts: 2},
	{Key: "grafana", Name: "Grafana", CPEs: []string{"a:grafana:grafana"}, Aliases: []string{"grafana"}, FullParts: 3},
	{Key: "gitlab", Name: "GitLab", CPEs: []string{"a:gitlab:gitlab"}, Aliases: []string{"gitlab"}, FullParts: 3},
	{Key: "gitea", Name: "Gitea", CPEs: []string{"a:gitea:gitea"}, Aliases: []string{"gitea"}, FullParts: 3},
	{Key: "phpmyadmin", Name: "phpMyAdmin", CPEs: []string{"a:phpmyadmin:phpmyadmin"}, Aliases: []string{"phpmyadmin"}, FullParts: 3},
	{Key: "adminer", Name: "Adminer", CPEs: []string{"a:adminer:adminer"}, Aliases: []string{"adminer"}, FullParts: 3},
	{Key: "tomcat", Name: "Apache Tomcat", CPEs: []string{"a:apache:tomcat"}, Aliases: []string{"apache tomcat"}, FullParts: 3},
	{Key: "iis", Name: "Microsoft IIS", CPEs: []string{"a:microsoft:internet_information_services", "a:microsoft:iis"}, Aliases: []string{"microsoft iis httpd", "microsoft iis", "microsoft-iis"}, FullParts: 2},
	{Key: "exim", Name: "Exim", CPEs: []string{"a:exim:exim"}, Aliases: []string{"exim smtpd", "exim"}, FullParts: 2},
	{Key: "postfix", Name: "Postfix", CPEs: []string{"a:postfix:postfix"}, Aliases: []string{"postfix smtpd", "postfix"}, FullParts: 3},
	{Key: "dovecot", Name: "Dovecot", CPEs: []string{"a:dovecot:dovecot"}, Aliases: []string{"dovecot imapd", "dovecot pop3d", "dovecot"}, FullParts: 3},
	{Key: "vsftpd", Name: "vsftpd", CPEs: []string{"a:beasts:vsftpd", "a:vsftpd_project:vsftpd"}, Aliases: []string{"vsftpd"}, FullParts: 3},
	{Key: "proftpd", Name: "ProFTPD", CPEs: []string{"a:proftpd:proftpd", "a:proftpd_project:proftpd"}, Aliases: []string{"proftpd"}, FullParts: 3},
	{Key: "redis", Name: "Redis", CPEs: []string{"a:redis:redis", "a:redislabs:redis"}, Aliases: []string{"redis key-value store", "redis"}, FullParts: 3},
	{Key: "postgresql", Name: "PostgreSQL", CPEs: []string{"a:postgresql:postgresql"}, Aliases: []string{"postgresql db", "postgresql"}, FullParts: 2},
	{Key: "mysql", Name: "MySQL", CPEs: []string{"a:oracle:mysql", "a:oracle:mysql_server"}, Aliases: []string{"mysql"}, FullParts: 3},
	{Key: "mariadb", Name: "MariaDB", CPEs: []string{"a:mariadb:mariadb"}, Aliases: []string{"mariadb"}, FullParts: 3},
	{Key: "rabbitmq", Name: "RabbitMQ", CPEs: []string{"a:vmware:rabbitmq", "a:pivotal_software:rabbitmq", "a:broadcom:rabbitmq_server"}, Aliases: []string{"rabbitmq", "rabbitmq management"}, FullParts: 3},
	{Key: "traefik", Name: "Traefik", CPEs: []string{"a:traefik:traefik", "a:containous:traefik"}, Aliases: []string{"traefik"}, FullParts: 3},
	{Key: "elasticsearch", Name: "Elasticsearch", CPEs: []string{"a:elastic:elasticsearch", "a:elasticsearch:elasticsearch"}, Aliases: []string{"elasticsearch", "elasticsearch rest api"}, FullParts: 3},
	{Key: "kibana", Name: "Kibana", CPEs: []string{"a:elastic:kibana", "a:elasticsearch:kibana"}, Aliases: []string{"kibana"}, FullParts: 3},
	{Key: "zabbix", Name: "Zabbix", CPEs: []string{"a:zabbix:zabbix"}, Aliases: []string{"zabbix"}, FullParts: 3},
	{Key: "keycloak", Name: "Keycloak", CPEs: []string{"a:redhat:keycloak", "a:keycloak:keycloak"}, Aliases: []string{"keycloak"}, FullParts: 3},
	{Key: "spring-boot", Name: "Spring Boot", CPEs: []string{"a:vmware:spring_boot", "a:pivotal_software:spring_boot"}, Aliases: []string{"spring boot"}, FullParts: 3},
	{Key: "routeros", Name: "MikroTik RouterOS", CPEs: []string{"o:mikrotik:routeros"}, Aliases: []string{"mikrotik routeros", "mikrotik routeros api", "routeros"}, FullParts: 2},
	{Key: "synology-dsm", Name: "Synology DSM", CPEs: []string{"o:synology:diskstation_manager", "a:synology:diskstation_manager"}, Aliases: []string{"synology dsm", "synology diskstation manager"}, FullParts: 2},
	{Key: "idrac", Name: "Dell iDRAC", CPEs: []string{"o:dell:idrac9_firmware", "o:dell:idrac8_firmware", "o:dell:integrated_dell_remote_access_controller_9_firmware"}, Aliases: []string{"dell idrac", "idrac", "idrac9", "idrac8"}, FullParts: 3},
}

// lookupDef maps a reported product or technology name to its catalog entry: an exact
// alias first, then the longest alias that prefixes the name ("Apache Tomcat/Coyote JSP
// engine" -> Apache Tomcat).
func lookupDef(name string) *ProductDef {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return nil
	}
	var best *ProductDef
	bestLen := 0
	for i := range Catalog {
		for _, a := range Catalog[i].Aliases {
			if n == a {
				return &Catalog[i]
			}
			if len(a) > bestLen && len(a) >= 4 && strings.HasPrefix(n, a) && len(n) > len(a) && strings.ContainsRune(" /(", rune(n[len(a)])) {
				best, bestLen = &Catalog[i], len(a)
			}
		}
	}
	return best
}

func defByKey(key string) *ProductDef {
	for i := range Catalog {
		if Catalog[i].Key == key {
			return &Catalog[i]
		}
	}
	return nil
}

// cpeVendorProduct returns "part:vendor:product" from a CPE 2.3 string.
func cpeVendorProduct(cpe string) (vp, version, update string, ok bool) {
	f := splitCPE(cpe)
	if len(f) < 7 || f[0] != "cpe" || f[1] != "2.3" {
		return "", "", "", false
	}
	return f[2] + ":" + f[3] + ":" + f[4], f[5], f[6], true
}

// splitCPE splits a CPE 2.3 formatted string on unescaped colons.
func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	return append(out, cur.String())
}
