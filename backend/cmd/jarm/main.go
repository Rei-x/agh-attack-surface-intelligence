// Command jarm computes the JARM TLS server fingerprint of one endpoint using
// Dzięcioł's Go implementation (internal/fingerprint/jarm.go). Output format
// mirrors `python3 jarm.py -v` so results can be diffed against the reference.
//
//	go run ./cmd/jarm -p 443 192.0.2.10
//	go run ./cmd/jarm -p 8443 -sni app.example.org -dump resp.hex 192.0.2.10
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/fingerprint"
)

func main() {
	port := flag.Int("p", 443, "port")
	sni := flag.String("sni", "", "server_name to send (default: the target as given)")
	verbose := flag.Bool("v", false, "print per-probe raw results")
	dump := flag.String("dump", "", "write per-probe server responses (hex, one per line) to this file")
	timeout := flag.Duration("timeout", 4*time.Second, "per-probe timeout")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: jarm [-p port] [-sni name] [-v] [-dump file] <ip>")
		os.Exit(2)
	}
	target := flag.Arg(0)
	res, err := fingerprint.ComputeJARM(context.Background(), target, *port, *sni, fingerprint.JARMOptions{ProbeTimeout: *timeout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	fmt.Println("Domain: " + target)
	fmt.Println("JARM: " + res.Hash)
	if *verbose {
		for i, r := range res.Raw {
			fmt.Printf("Scan %d: %s\n", i+1, r)
		}
	}
	if *dump != "" {
		lines := make([]string, len(res.Responses))
		for i, r := range res.Responses {
			lines[i] = hex.EncodeToString(r)
		}
		if err := os.WriteFile(*dump, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
