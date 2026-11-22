package scanner

import "testing"

// mysqlGreeting builds a real MySQL protocol-10 greeting packet (header, version, thread
// id, salt, capabilities, auth plugin) exactly as mysqld / mariadbd send it.
func mysqlGreeting(version, plugin string, threadID byte) string {
	p := []byte{10}
	p = append(p, version...)
	p = append(p, 0, threadID, 0x31, 0, 0) // NUL + thread id (0x31 is a printable digit)
	p = append(p, "abcdefgh"...)
	p = append(p, 0, 0xff, 0xf7, 0xff, 0x02, 0x00, 0xff, 0xdf, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, "ijklmnopqrst"...)
	p = append(p, 0)
	p = append(p, plugin...)
	p = append(p, 0)
	hdr := []byte{byte(len(p)), 0, 0, 0}
	return string(append(hdr, p...))
}

func TestIdentifyBannerRealDaemons(t *testing.T) {
	cases := []struct {
		port                  int
		banner                string
		svc, product, version string
	}{
		{22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "ssh", "OpenSSH", "8.9p1"},
		{22, "SSH-2.0-OpenSSH_7.4", "ssh", "OpenSSH", "7.4"},
		{22, "SSH-2.0-ROSSSH", "ssh", "MikroTik RouterOS sshd", ""},
		{22, "SSH-2.0-dropbear_2020.81", "ssh", "Dropbear sshd", "2020.81"},
		{21, "220 (vsFTPd 3.0.5)", "ftp", "vsftpd", "3.0.5"},
		{21, "220 ProFTPD 1.3.8b Server (ProFTPD Default Installation) [10.0.0.5]", "ftp", "ProFTPD", "1.3.8b"},
		{21, "220 gw-core FTP server (MikroTik 6.49.10) ready", "ftp", "MikroTik router ftpd", "6.49.10"},
		{21, "220 Microsoft FTP Service", "ftp", "Microsoft ftpd", ""},
		{25, "220 mail.example.org ESMTP Postfix (Ubuntu)", "smtp", "Postfix smtpd", ""},
		{25, "220 mx1.example.org ESMTP Exim 4.96 Mon, 02 Jan 2006 15:04:05 +0100", "smtp", "Exim smtpd", "4.96"},
		{110, "+OK Dovecot (Ubuntu) ready.", "pop3", "Dovecot pop3d", ""},
		{143, "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] Dovecot (Ubuntu) ready.", "imap", "Dovecot imapd", ""},
		{6379, "-NOAUTH Authentication required.", "redis", "Redis key-value store", ""},
	}
	for _, c := range cases {
		svc, prod, ver, ok := identifyBanner(c.port, c.banner)
		if !ok || svc != c.svc || prod != c.product || ver != c.version {
			t.Errorf("identifyBanner(%d, %q) = %q %q %q %v; want %q %q %q", c.port, c.banner, svc, prod, ver, ok, c.svc, c.product, c.version)
		}
	}
}

func TestIdentifyMySQLGreetingThroughSanitizer(t *testing.T) {
	cases := []struct {
		raw              string
		product, version string
	}{
		{mysqlGreeting("8.0.36-0ubuntu0.22.04.1", "caching_sha2_password", 0x35), "MySQL", "8.0.36"},
		{mysqlGreeting("5.7.44", "mysql_native_password", 0x08), "MySQL", "5.7.44"},
		{mysqlGreeting("5.5.5-10.6.16-MariaDB-0ubuntu0.22.04.1", "mysql_native_password", 0x39), "MariaDB", "10.6.16"},
		{mysqlGreeting("5.5.5-10.11.6-MariaDB", "mysql_native_password", 0x0b), "MariaDB", "10.11.6"},
	}
	for _, c := range cases {
		banner := sanitizePrintable(c.raw)
		svc, prod, ver := inferServiceFromPortAndBanner(3306, banner)
		if svc != "mysql" || prod != c.product || ver != c.version {
			t.Errorf("greeting %q -> %q %q %q; want mysql %q %q", banner, svc, prod, ver, c.product, c.version)
		}
	}
}

func TestIdentifyBannerUnknownFallsBack(t *testing.T) {
	if _, _, _, ok := identifyBanner(8080, "HTTP/1.1 400 Bad Request"); ok {
		t.Fatal("HTTP error must not be identified as a known banner")
	}
	svc, _, _ := inferServiceFromPortAndBanner(80, "")
	if svc != "http" {
		t.Fatalf("port fallback broken: %q", svc)
	}
}
