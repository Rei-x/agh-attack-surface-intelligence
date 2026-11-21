package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// fakeServer accepts connections and runs handle for each one.
func fakeServer(t *testing.T, handle func(net.Conn)) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func amqpStartFrame() []byte {
	var tbl bytes.Buffer
	putStr := func(k, v string) {
		tbl.WriteByte(byte(len(k)))
		tbl.WriteString(k)
		tbl.WriteByte('S')
		_ = binary.Write(&tbl, binary.BigEndian, uint32(len(v)))
		tbl.WriteString(v)
	}
	// a nested table first, to check that it is skipped
	tbl.WriteByte(12)
	tbl.WriteString("capabilities")
	tbl.WriteByte('F')
	_ = binary.Write(&tbl, binary.BigEndian, uint32(0))
	putStr("product", "RabbitMQ")
	putStr("version", "3.13.7")
	putStr("platform", "Erlang/OTP 26.2.5")
	var p bytes.Buffer
	_ = binary.Write(&p, binary.BigEndian, uint16(10))
	_ = binary.Write(&p, binary.BigEndian, uint16(10))
	p.Write([]byte{0, 9})
	_ = binary.Write(&p, binary.BigEndian, uint32(tbl.Len()))
	p.Write(tbl.Bytes())
	var f bytes.Buffer
	f.WriteByte(1)
	_ = binary.Write(&f, binary.BigEndian, uint16(0))
	_ = binary.Write(&f, binary.BigEndian, uint32(p.Len()))
	f.Write(p.Bytes())
	f.WriteByte(0xCE)
	return f.Bytes()
}

func noWait(context.Context) error { return nil }

func TestProbeAMQPReadsProductAndVersion(t *testing.T) {
	ip, port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		if _, err := c.Read(buf); err != nil || string(buf[:4]) != "AMQP" {
			return
		}
		_, _ = c.Write(amqpStartFrame())
	})
	svc := domain.ObservedService{Port: port, Protocol: "tcp", ServiceName: "amqp", Product: "Advanced Message Queue Protocol"}
	if !probeService(context.Background(), ip, &svc, false, noWait) {
		t.Fatal("probe did not change the service")
	}
	if svc.Product != "RabbitMQ" || svc.Version != "3.13.7" {
		t.Fatalf("got product %q version %q", svc.Product, svc.Version)
	}
}

func TestProbePostgresUnknownPort(t *testing.T) {
	ip, port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		if n, _ := c.Read(buf); n == 8 && buf[4] == 0x04 && buf[5] == 0xd2 {
			_, _ = c.Write([]byte("N"))
		}
	})
	svc := domain.ObservedService{Port: port, Protocol: "tcp", ServiceName: "tcp"}
	if !probeService(context.Background(), ip, &svc, false, noWait) || svc.ServiceName != "postgresql" || svc.Product != "PostgreSQL" {
		t.Fatalf("want postgresql, got %+v", svc)
	}
}

func TestProbeRedisNoAuth(t *testing.T) {
	ip, port := fakeServer(t, func(c net.Conn) {
		line, _ := bufio.NewReader(c).ReadString('\n')
		if strings.HasPrefix(line, "PING") {
			_, _ = c.Write([]byte("+PONG\r\n"))
		}
	})
	svc := domain.ObservedService{Port: port, Protocol: "tcp", ServiceName: "redis", Product: "Redis key-value store", Version: "7.4.1"}
	probeService(context.Background(), ip, &svc, false, noWait)
	if !hasTag(svc.Tags, "redis-no-auth") || !strings.Contains(svc.Banner, "no authentication") {
		t.Fatalf("want redis-no-auth, got %+v", svc)
	}
}

func TestProbeFTPAnonymous(t *testing.T) {
	for _, allow := range []bool{true, false} {
		ip, port := fakeServer(t, func(c net.Conn) {
			_, _ = c.Write([]byte("220 (vsFTPd 3.0.2)\r\n"))
			br := bufio.NewReader(c)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				switch {
				case strings.HasPrefix(line, "USER"):
					_, _ = c.Write([]byte("331 Please specify the password.\r\n"))
				case strings.HasPrefix(line, "PASS") && allow:
					_, _ = c.Write([]byte("230 Login successful.\r\n"))
				case strings.HasPrefix(line, "PASS"):
					_, _ = c.Write([]byte("530 Login incorrect.\r\n"))
				case strings.HasPrefix(line, "QUIT"):
					_, _ = c.Write([]byte("221 Goodbye.\r\n"))
					return
				}
			}
		})
		svc := domain.ObservedService{Port: port, Protocol: "tcp", ServiceName: "ftp", Product: "vsftpd", Version: "3.0.2"}
		probeService(context.Background(), ip, &svc, false, noWait)
		if got := hasTag(svc.Tags, "ftp-anonymous"); got != allow {
			t.Fatalf("allow=%v: tags %v", allow, svc.Tags)
		}
	}
}

func TestProbesLeaveHTTPAlone(t *testing.T) {
	ip, port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
	})
	svc := domain.ObservedService{Port: port, Protocol: "tcp", ServiceName: "nessus"}
	if probeService(context.Background(), ip, &svc, true, noWait) {
		t.Fatalf("HTTP server must not be renamed, got %+v", svc)
	}
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}
