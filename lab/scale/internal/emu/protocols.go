package emu

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/lab/scale/internal/plan"
)

const idleTimeout = 15 * time.Second

// sshBanner returns the identification string a real server would send.
func sshBanner(s *plan.Svc) string {
	if s.Product == "rosssh" {
		return "SSH-2.0-ROSSSH"
	}
	return "SSH-2.0-OpenSSH_" + s.Ver
}

func ftpBanner(h *plan.Host, s *plan.Svc, ip string) string {
	switch s.Product {
	case "proftpd":
		return fmt.Sprintf("220 ProFTPD %s Server (ProFTPD Default Installation) [%s]", s.Ver, ip)
	case "mikrotik-ftp":
		return fmt.Sprintf("220 %s FTP server (MikroTik %s) ready", h.Hostname, s.Ver)
	}
	return "220 (vsFTPd " + s.Ver + ")"
}

func smtpBanner(h *plan.Host, s *plan.Svc) string {
	fq := h.Hostname + ".lab.agh.local"
	if s.Product == "exim" {
		return fmt.Sprintf("220 %s ESMTP Exim %s %s", fq, s.Ver, time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	}
	return "220 " + fq + " ESMTP Postfix (Ubuntu)"
}

// Banner returns the server-first greeting (first line) for truth purposes.
func Banner(h *plan.Host, s *plan.Svc, ip string) string {
	switch s.Kind {
	case "ssh":
		return sshBanner(s)
	case "ftp":
		return ftpBanner(h, s, ip)
	case "smtp":
		b := smtpBanner(h, s)
		if s.Product == "exim" {
			return b[:strings.Index(b, s.Ver)+len(s.Ver)]
		}
		return b
	case "pop3":
		return "+OK Dovecot (Ubuntu) ready."
	case "imap":
		return "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED] Dovecot (Ubuntu) ready."
	}
	return ""
}

func serveConn(conn net.Conn, h *plan.Host, s *plan.Svc, ip string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(idleTimeout))
	switch s.Kind {
	case "ssh":
		serveSSH(conn, s)
	case "ftp":
		serveFTP(conn, h, s, ip)
	case "smtp":
		serveSMTP(conn, h, s)
	case "pop3":
		serveLines(conn, Banner(h, s, ip), func(cmd string) (string, bool) {
			switch cmd {
			case "QUIT":
				return "+OK Logging out", true
			case "CAPA":
				return "+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\nAUTH-RESP-CODE\r\nSTLS\r\nUSER\r\nSASL PLAIN\r\n.", false
			}
			return "-ERR Unknown command.", false
		})
	case "imap":
		serveLines(conn, Banner(h, s, ip), func(line string) (string, bool) {
			f := strings.Fields(line)
			tag := "*"
			if len(f) > 0 {
				tag = f[0]
			}
			if len(f) > 1 {
				switch strings.ToUpper(f[1]) {
				case "LOGOUT":
					return "* BYE Logging out\r\n" + tag + " OK Logout completed.", true
				case "CAPABILITY":
					return "* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS LOGINDISABLED\r\n" + tag + " OK Pre-login capabilities listed, post-login capabilities have more.", false
				}
			}
			return tag + " BAD Error in IMAP command received by server.", false
		})
	case "mysql":
		serveMySQL(conn, s)
	case "postgres":
		servePostgres(conn, s)
	case "redis":
		serveRedis(conn, s)
	case "rdp":
		serveRDP(conn)
	case "rtsp":
		serveRTSP(conn, s)
	case "telnet":
		serveTelnet(conn, h)
	default: // silent
		switch s.Port {
		case 135, 139, 445:
			// Windows (SMBv1 disabled) closes the connection on anything that is not
			// a protocol it speaks, e.g. nmap's SMBv1 negotiate or HTTP probes.
			buf := make([]byte, 2048)
			_, _ = conn.Read(buf)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1<<16))
	}
}

func serveSSH(conn net.Conn, s *plan.Svc) {
	_, _ = conn.Write([]byte(sshBanner(s) + "\r\n"))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	if !strings.HasPrefix(line, "SSH-") {
		_, _ = conn.Write([]byte("Invalid SSH identification string.\r\n"))
		return
	}
	// Minimal SSH_MSG_KEXINIT so clients see a plausible key exchange start.
	kex := []byte{20}
	cookie := make([]byte, 16)
	kex = append(kex, cookie...)
	for _, l := range []string{
		"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
		"rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
		"chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com",
		"umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256", "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
		"none,zlib@openssh.com", "none,zlib@openssh.com", "", "",
	} {
		kex = binary.BigEndian.AppendUint32(kex, uint32(len(l)))
		kex = append(kex, l...)
	}
	kex = append(kex, 0, 0, 0, 0, 0)
	pad := 8 - (len(kex)+5)%8
	if pad < 4 {
		pad += 8
	}
	pkt := binary.BigEndian.AppendUint32(nil, uint32(len(kex)+pad+1))
	pkt = append(pkt, byte(pad))
	pkt = append(pkt, kex...)
	pkt = append(pkt, make([]byte, pad)...)
	_, _ = conn.Write(pkt)
	_, _ = io.Copy(io.Discard, io.LimitReader(br, 1<<14))
}

func serveLines(conn net.Conn, banner string, handle func(string) (string, bool)) {
	_, _ = conn.Write([]byte(banner + "\r\n"))
	sc := bufio.NewScanner(io.LimitReader(conn, 1<<16))
	for n := 0; sc.Scan() && n < 20; n++ {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(banner, "* OK") { // IMAP keeps the client tag's case
			line = strings.ToUpper(line)
		}
		resp, done := handle(line)
		_, _ = conn.Write([]byte(resp + "\r\n"))
		if done {
			return
		}
	}
}

func serveFTP(conn net.Conn, h *plan.Host, s *plan.Svc, ip string) {
	serveLines(conn, ftpBanner(h, s, ip), func(line string) (string, bool) {
		cmd := strings.Fields(line + " x")[0]
		switch cmd {
		case "USER":
			return "331 Please specify the password.", false
		case "PASS":
			return "530 Login incorrect.", false
		case "SYST":
			return "215 UNIX Type: L8", false
		case "FEAT":
			return "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End", false
		case "HELP":
			return "214-The following commands are recognized.\r\n ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n214 Help OK.", false
		case "QUIT":
			return "221 Goodbye.", true
		case "AUTH":
			return "530 Please login with USER and PASS.", false
		}
		return "530 Please login with USER and PASS.", false
	})
}

func serveSMTP(conn net.Conn, h *plan.Host, s *plan.Svc) {
	fq := h.Hostname + ".lab.agh.local"
	serveLines(conn, smtpBanner(h, s), func(line string) (string, bool) {
		cmd := strings.Fields(line + " x")[0]
		switch cmd {
		case "EHLO":
			if s.Product == "exim" {
				return "250-" + fq + " Hello there\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING\r\n250-CHUNKING\r\n250-STARTTLS\r\n250 HELP", false
			}
			return "250-" + fq + "\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250-SMTPUTF8\r\n250 CHUNKING", false
		case "HELO":
			return "250 " + fq, false
		case "QUIT":
			return "221 2.0.0 Bye", true
		case "HELP":
			if s.Product == "exim" {
				return "214-Commands supported:\r\n214 AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP", false
			}
			return "502 5.5.0 Error: command not recognized", false
		case "NOOP":
			return "250 2.0.0 Ok", false
		}
		if s.Product == "exim" {
			return "500 unrecognized command", false
		}
		return "502 5.5.2 Error: command not recognized", false
	})
}

func serveMySQL(conn net.Conn, s *plan.Svc) {
	ver := s.Ver
	plugin := "caching_sha2_password"
	if s.Product == "mariadb" {
		ver = "5.5.5-" + ver
		plugin = "mysql_native_password"
	} else if strings.HasPrefix(ver, "5.") {
		plugin = "mysql_native_password"
	}
	p := []byte{10}
	p = append(p, ver...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, uint32(time.Now().UnixNano()%100000+8))
	salt := []byte(randAlnum(20))
	p = append(p, salt[:8]...)
	p = append(p, 0)
	p = append(p, 0xff, 0xff) // capabilities lower
	p = append(p, 0xff)       // charset utf8mb4
	p = append(p, 0x02, 0x00) // status autocommit
	p = append(p, 0xff, 0xdf) // capabilities upper
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, salt[8:]...)
	p = append(p, 0)
	p = append(p, plugin...)
	p = append(p, 0)
	hdr := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}
	_, _ = conn.Write(append(hdr, p...))
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	// Access denied error packet (1045).
	msg := "#28000Access denied for user 'root'@'" + hostOnly(conn.RemoteAddr().String(), "") + "' (using password: NO)"
	e := append([]byte{0xff, 0x15, 0x04}, msg...)
	_, _ = conn.Write(append([]byte{byte(len(e)), byte(len(e) >> 8), 0, 2}, e...))
}

func pgError(fields ...string) []byte {
	var b bytes.Buffer
	for i := 0; i+1 < len(fields); i += 2 {
		b.WriteString(fields[i])
		b.WriteString(fields[i+1])
		b.WriteByte(0)
	}
	b.WriteByte(0)
	out := []byte{'E'}
	out = binary.BigEndian.AppendUint32(out, uint32(b.Len()+4))
	return append(out, b.Bytes()...)
}

func servePostgres(conn net.Conn, s *plan.Svc) {
	line := map[string]string{"12": "2087", "14": "2155", "15": "2190", "16": "2232"}[s.Ver]
	if line == "" {
		line = "2155"
	}
	for i := 0; i < 3; i++ {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		code := binary.BigEndian.Uint32(hdr[4:])
		if n < 8 || n > 10000 {
			_, _ = conn.Write(pgError("S", "FATAL", "V", "FATAL", "C", "08P01", "M", "invalid length of startup packet", "F", "postmaster.c", "L", "1981", "R", "ProcessStartupPacket"))
			return
		}
		switch code {
		case 80877103, 80877104: // SSLRequest, GSSENCRequest
			_, _ = conn.Write([]byte("N"))
			continue
		case 196608: // protocol 3.0
			rest := make([]byte, n-8)
			_, _ = io.ReadFull(conn, rest)
			_, _ = conn.Write(pgError("S", "FATAL", "V", "FATAL", "C", "28000", "M", "no pg_hba.conf entry for host \""+hostOnly(conn.RemoteAddr().String(), "")+"\", user \"postgres\", database \"postgres\", no encryption", "F", "auth.c", "L", "543", "R", "ClientAuthentication"))
			return
		default:
			_, _ = conn.Write(pgError("S", "FATAL", "V", "FATAL", "C", "0A000", "M", fmt.Sprintf("unsupported frontend protocol %d.%d: server supports 3.0 to 3.0", code>>16, code&0xffff), "F", "postmaster.c", "L", line, "R", "ProcessStartupPacket"))
			return
		}
	}
}

func serveRedis(conn net.Conn, s *plan.Svc) {
	br := bufio.NewReader(io.LimitReader(conn, 1<<16))
	for n := 0; n < 20; n++ {
		args, err := readRedisCmd(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		if cmd == "POST" || strings.HasPrefix(cmd, "HOST:") {
			// Redis >= 3.2.7 drops connections that look like HTTP cross-protocol attacks.
			return
		}
		if s.Auth != "none" && cmd != "AUTH" && cmd != "QUIT" {
			_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
			continue
		}
		switch cmd {
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("+OK\r\n"))
			return
		case "AUTH":
			_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
		case "INFO":
			info := fmt.Sprintf("# Server\r\nredis_version:%s\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:%s\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\nmultiplexing_api:epoll\r\ngcc_version:11.4.0\r\nprocess_id:%d\r\ntcp_port:6379\r\nuptime_in_seconds:%d\r\n\r\n# Clients\r\nconnected_clients:3\r\n", s.Ver, randHex(16), 800+len(s.Ver)*13, 864000)
			_, _ = conn.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)))
		default:
			argStr := ""
			for _, a := range args[1:] {
				argStr += "'" + a + "' "
			}
			_, _ = conn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s', with args beginning with: %s\r\n", args[0], argStr)))
		}
	}
}

func readRedisCmd(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil
	}
	var n int
	if _, err := fmt.Sscanf(line, "*%d", &n); err != nil || n > 64 {
		return nil, fmt.Errorf("bad array")
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		var sz int
		if _, err := fmt.Sscanf(strings.TrimSpace(l), "$%d", &sz); err != nil || sz > 4096 {
			return nil, fmt.Errorf("bad bulk")
		}
		b := make([]byte, sz+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		out = append(out, string(b[:sz]))
	}
	return out, nil
}

func serveRDP(conn net.Conn) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 || buf[0] != 0x03 {
		return
	}
	// X.224 Connection Confirm with RDP_NEG_RSP selecting PROTOCOL_HYBRID (CredSSP/NLA).
	_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x02, 0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00})
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1<<14))
}

func serveRTSP(conn net.Conn, s *plan.Svc) {
	br := bufio.NewReader(io.LimitReader(conn, 1<<16))
	for n := 0; n < 10; n++ {
		req, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cseq := "1"
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimSpace(l)
			if l == "" {
				break
			}
			if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "CSeq") {
				cseq = strings.TrimSpace(v)
			}
		}
		date := time.Now().UTC().Format("Mon, Jan 02 2006 15:04:05 GMT")
		if strings.HasPrefix(req, "OPTIONS") {
			_, _ = conn.Write([]byte("RTSP/1.0 200 OK\r\nCSeq: " + cseq + "\r\nPublic: OPTIONS, DESCRIBE, PLAY, PAUSE, SETUP, TEARDOWN, SET_PARAMETER, GET_PARAMETER\r\nDate:  " + date + "\r\n\r\n"))
			continue
		}
		_, _ = conn.Write([]byte("RTSP/1.0 401 Unauthorized\r\nCSeq: " + cseq + "\r\nWWW-Authenticate: Digest realm=\"" + s.Model + "\", nonce=\"" + randHex(32) + "\", stale=\"FALSE\"\r\nDate:  " + date + "\r\n\r\n"))
	}
}

func serveTelnet(conn net.Conn, h *plan.Host) {
	_, _ = conn.Write([]byte{0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd, 0x23, 0xff, 0xfd, 0x27})
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)
	_ = conn.SetDeadline(time.Now().Add(idleTimeout))
	_, _ = conn.Write([]byte("\r\nLogin: "))
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1<<12))
}
