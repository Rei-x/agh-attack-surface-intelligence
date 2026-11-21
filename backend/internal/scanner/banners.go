package scanner

import (
	"regexp"
	"strings"
)

// Banner identification for the pure-Go scanner (no nmap). Every rule below parses what
// the real daemon sends unprompted on connect; product names follow nmap's service
// database (nmap-service-probes) so results from both scan paths look the same and
// map onto the same CPEs:
//
//	SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6           -> ssh  OpenSSH 8.9p1
//	SSH-2.0-ROSSSH                                     -> ssh  MikroTik RouterOS sshd
//	220 (vsFTPd 3.0.5)                                 -> ftp  vsftpd 3.0.5
//	220 ProFTPD 1.3.8b Server (Debian) [::ffff:1.2.3.4]  -> ftp  ProFTPD 1.3.8b
//	220 gw FTP server (MikroTik 6.49.10) ready         -> ftp  MikroTik router ftpd 6.49.10
//	220 mx ESMTP Postfix (Ubuntu)                      -> smtp Postfix smtpd
//	220 mx ESMTP Exim 4.96 Mon, 01 Jan ...             -> smtp Exim smtpd 4.96
//	+OK Dovecot (Ubuntu) ready.                        -> pop3 Dovecot pop3d
//	* OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.     -> imap Dovecot imapd
//	MySQL v10 handshake "8.0.36-0ubuntu0.22.04.1"      -> mysql MySQL 8.0.36
//	MySQL v10 handshake "5.5.5-10.6.16-MariaDB-0u..."  -> mysql MariaDB 10.6.16
var (
	reVsftpd      = regexp.MustCompile(`(?i)^220[ -]\(vsFTPd ([0-9][0-9.]*[0-9a-z]*)\)`)
	reProftpd     = regexp.MustCompile(`(?i)^220[ -]ProFTPD(?: ([0-9][0-9.]*[0-9a-z]*))?`)
	reMikrotikFTP = regexp.MustCompile(`(?i)^220[ -].*FTP server \(MikroTik ([0-9][0-9.]*[0-9a-z]*)\)`)
	rePureFTPd    = regexp.MustCompile(`(?i)Pure-FTPd`)
	reFileZilla   = regexp.MustCompile(`(?i)^220[ -]FileZilla Server(?: version)? ?([0-9][0-9.]*[0-9a-z]*)?`)
	reMSFTP       = regexp.MustCompile(`(?i)^220[ -]Microsoft FTP Service`)
	rePostfix     = regexp.MustCompile(`(?i)^220[ -]\S+ ESMTP Postfix`)
	reExim        = regexp.MustCompile(`(?i)^220[ -]\S+ ESMTP Exim ([0-9][0-9.]*)`)
	reSendmail    = regexp.MustCompile(`(?i)^220[ -]\S+ ESMTP Sendmail ([0-9][0-9.]*[0-9a-z/.]*)`)
	reMSExchange  = regexp.MustCompile(`(?i)^220[ -]\S+ Microsoft ESMTP MAIL Service`)
	reDovecotPOP  = regexp.MustCompile(`(?i)^\+OK .*Dovecot`)
	reDovecotIMAP = regexp.MustCompile(`(?i)^\* OK .*Dovecot`)
	reCourierIMAP = regexp.MustCompile(`(?i)^\* OK .*Courier-IMAP`)
	reMySQLVer    = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)(-[0-9]+\.[0-9]+\.[0-9]+-MariaDB)?[-A-Za-z0-9.~+]*`)
	reMariaDBVer  = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)-MariaDB`)
	reRedisVer    = regexp.MustCompile(`redis_version:([0-9][0-9.]*)`)
)

// identifyBanner returns the service, product and version a passive banner discloses.
// ok is false when the banner is not recognised (callers fall back to port heuristics).
func identifyBanner(port int, banner string) (svcName, product, version string, ok bool) {
	b := strings.TrimSpace(banner)
	if b == "" {
		return "", "", "", false
	}
	first := b
	if i := strings.IndexAny(first, "\r\n"); i >= 0 {
		first = first[:i]
	}

	if strings.HasPrefix(first, "SSH-") {
		return identifySSH(first)
	}
	if m := reVsftpd.FindStringSubmatch(first); m != nil {
		return "ftp", "vsftpd", m[1], true
	}
	if m := reMikrotikFTP.FindStringSubmatch(first); m != nil {
		return "ftp", "MikroTik router ftpd", m[1], true
	}
	if m := reProftpd.FindStringSubmatch(first); m != nil {
		return "ftp", "ProFTPD", m[1], true
	}
	if m := reFileZilla.FindStringSubmatch(first); m != nil {
		return "ftp", "FileZilla ftpd", m[1], true
	}
	if strings.HasPrefix(first, "220") && rePureFTPd.MatchString(b) {
		return "ftp", "Pure-FTPd", "", true
	}
	if reMSFTP.MatchString(first) {
		return "ftp", "Microsoft ftpd", "", true
	}
	if rePostfix.MatchString(first) {
		return "smtp", "Postfix smtpd", "", true
	}
	if m := reExim.FindStringSubmatch(first); m != nil {
		return "smtp", "Exim smtpd", m[1], true
	}
	if m := reSendmail.FindStringSubmatch(first); m != nil {
		return "smtp", "Sendmail", m[1], true
	}
	if reMSExchange.MatchString(first) {
		return "smtp", "Microsoft Exchange smtpd", "", true
	}
	if reDovecotPOP.MatchString(first) {
		return "pop3", "Dovecot pop3d", "", true
	}
	if reDovecotIMAP.MatchString(first) {
		return "imap", "Dovecot imapd", "", true
	}
	if reCourierIMAP.MatchString(first) {
		return "imap", "Courier Imapd", "", true
	}
	if m := reRedisVer.FindStringSubmatch(b); m != nil {
		return "redis", "Redis key-value store", m[1], true
	}
	if strings.HasPrefix(b, "-NOAUTH") || strings.HasPrefix(b, "-DENIED Redis") || b == "+PONG" {
		return "redis", "Redis key-value store", "", true
	}
	if svc, prod, ver, ok := identifyMySQLHandshake(port, b); ok {
		return svc, prod, ver, true
	}
	if strings.HasPrefix(first, "220") && (port == 25 || port == 587 || port == 465) {
		return "smtp", "", "", true
	}
	if strings.HasPrefix(first, "220") && port == 21 {
		return "ftp", "", "", true
	}
	return "", "", "", false
}

func identifySSH(first string) (string, string, string, bool) {
	// RFC 4253: SSH-protoversion-softwareversion SP comments
	parts := strings.SplitN(first, "-", 3)
	if len(parts) < 3 {
		return "ssh", "", "", true
	}
	soft := strings.Fields(parts[2])
	if len(soft) == 0 {
		return "ssh", "", "", true
	}
	sw := soft[0]
	switch {
	case strings.HasPrefix(sw, "OpenSSH_"):
		return "ssh", "OpenSSH", strings.TrimPrefix(sw, "OpenSSH_"), true
	case sw == "ROSSSH":
		return "ssh", "MikroTik RouterOS sshd", "", true
	case strings.HasPrefix(sw, "dropbear"):
		return "ssh", "Dropbear sshd", strings.TrimLeft(strings.TrimPrefix(sw, "dropbear"), "_"), true
	case strings.HasPrefix(sw, "Cisco-"):
		return "ssh", "Cisco SSH", strings.TrimPrefix(sw, "Cisco-"), true
	case strings.HasPrefix(sw, "libssh"):
		return "ssh", "libssh", strings.TrimLeft(strings.TrimPrefix(sw, "libssh"), "_-"), true
	}
	pv := strings.SplitN(sw, "_", 2)
	if len(pv) == 2 {
		return "ssh", pv[0], pv[1], true
	}
	return "ssh", sw, "", true
}

// identifyMySQLHandshake parses the server greeting of the MySQL client/server protocol
// (protocol version 10 followed by a NUL-terminated server version). The banner reaching
// us went through sanitizePrintable: NULs became spaces and other binary bytes vanished, so
// what is left is the 3-byte length's printable remains, "\n" (0x0a = protocol 10), the
// version, then salt and the auth plugin name.
func identifyMySQLHandshake(port int, b string) (string, string, string, bool) {
	lb := strings.ToLower(b)
	authPlugin := strings.Contains(lb, "mysql_native_password") || strings.Contains(lb, "caching_sha2_password")
	rest := b
	if i := strings.IndexByte(b, '\n'); i >= 0 && i <= 4 {
		rest = strings.TrimLeft(b[i+1:], " ")
	} else if !authPlugin {
		return "", "", "", false
	}
	m := reMySQLVer.FindStringSubmatchIndex(rest)
	if m == nil || m[0] != 0 {
		return "", "", "", false
	}
	verStr := rest[m[0]:m[1]]
	if mm := reMariaDBVer.FindStringSubmatch(verStr); mm != nil {
		// MariaDB 10.x prefixes "5.5.5-" for old-client compatibility.
		return "mysql", "MariaDB", mm[1], true
	}
	if strings.Contains(strings.ToLower(verStr), "mariadb") {
		return "mysql", "MariaDB", rest[m[2]:m[3]], true
	}
	if port != 3306 && !authPlugin {
		return "", "", "", false
	}
	return "mysql", "MySQL", rest[m[2]:m[3]], true
}
