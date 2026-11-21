package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agent"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/screenshot"
)

const agentUsage = `Usage: dzieciol agent [flags]
       dzieciol agent install --server URL --token TOKEN [flags]   (Linux, root: systemd service)

Remote scanning agent: install it inside a network segment (another VLAN, site, behind NAT).
It connects OUT to the Dzięcioł server over HTTPS (no inbound port), enrolls once with a
one-time token from Admin > Agenci, then pulls scan jobs, scans locally with the same engine
and uploads results (buffered on disk while the server is unreachable).

Every flag can also come from the environment: DZIECIOL_AGENT_SERVER, DZIECIOL_AGENT_TOKEN,
DZIECIOL_AGENT_NAME, DZIECIOL_AGENT_DATA_DIR, DZIECIOL_AGENT_CA_FILE, DZIECIOL_AGENT_INSECURE=true,
DZIECIOL_AGENT_ALLOW_CIDR (comma separated).`

// agentEnv reads DZIECIOL_AGENT_<key>.
func agentEnv(key string) string { return os.Getenv("DZIECIOL_AGENT_" + key) }

// exitCredentialRejected tells systemd not to restart (RestartPreventExitStatus=3): a deleted
// agent must be re-enrolled, restarting cannot fix it.
const exitCredentialRejected = 3

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type agentFlags struct {
	server, token, name, dataDir, caFile string
	insecure, verbose                    bool
	allow                                stringList
}

func parseAgentFlags(name string, args []string) (*agentFlags, error) {
	fs := newFlagSet(name, agentUsage)
	f := &agentFlags{}
	fs.StringVar(&f.server, "server", agentEnv("SERVER"), "Dzięcioł server URL, e.g. https://dzieciol.example.edu")
	fs.StringVar(&f.token, "token", agentEnv("TOKEN"), "one-time enrollment token (first run only)")
	fs.StringVar(&f.name, "name", agentEnv("NAME"), "agent name shown in the UI (default: token name or hostname)")
	fs.StringVar(&f.dataDir, "data-dir", "", "data directory for the credential and buffered results (default /var/lib/dzieciol-agent as root, else ~/.dzieciol-agent)")
	fs.StringVar(&f.caFile, "ca-file", agentEnv("CA_FILE"), "extra CA certificate (PEM) to trust for the server")
	fs.BoolVar(&f.insecure, "insecure", strings.EqualFold(agentEnv("INSECURE"), "true"), "skip TLS verification / allow plain HTTP (LAB ONLY)")
	fs.Var(&f.allow, "allow-cidr", "only ever scan inside these networks (repeatable or comma separated); jobs outside are refused")
	fs.BoolVar(&f.verbose, "verbose", false, "verbose logging")
	if _, err := parseInterspersed(fs, args); err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(agentEnv("ALLOW_CIDR")); v != "" && len(f.allow) == 0 {
		f.allow = append(f.allow, v)
	}
	return f, nil
}

func agentDataDir(flagValue string) (string, error) {
	dir := strings.TrimSpace(flagValue)
	for _, env := range []string{"DZIECIOL_AGENT_DATA_DIR", "STATE_DIRECTORY"} { // STATE_DIRECTORY: systemd
		if dir == "" {
			dir = strings.TrimSpace(strings.Split(os.Getenv(env), ":")[0])
		}
	}
	if dir == "" {
		if os.Geteuid() == 0 && runtime.GOOS != "windows" {
			dir = "/var/lib/dzieciol-agent"
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("cannot determine home directory (use --data-dir): %w", err)
			}
			dir = filepath.Join(home, ".dzieciol-agent")
		}
	}
	return filepath.Abs(dir)
}

func cmdAgent(args []string) error {
	if len(args) > 0 && args[0] == "install" {
		return cmdAgentInstall(args[1:])
	}
	f, err := parseAgentFlags("agent", args)
	if err != nil {
		return err
	}
	dir, err := agentDataDir(f.dataDir)
	if err != nil {
		return err
	}
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags)
	if f.insecure {
		log.Printf("[WARN] --insecure: the server's TLS certificate is NOT verified (lab use only)")
	}
	a, err := agent.New(agent.Config{
		ServerURL: f.server, Token: f.token, Name: f.name, DataDir: dir,
		CAFile: f.caFile, Insecure: f.insecure, AllowCIDRs: f.allow, Version: appVersion(),
		Screenshots: screenshotCapturer(),
	})
	defer screenshot.Shutdown()
	log.Printf("[INFO] %s", screenshot.Status().Detail)
	if err != nil {
		var le *localdata.ErrLocked
		if errors.As(err, &le) {
			return fmt.Errorf("%w - another agent already uses %s", err, dir)
		}
		return err
	}
	defer a.Close()
	if !scanner.NmapAvailable() {
		log.Printf("[INFO] nmap not found: using the built-in TCP connect scanner (install nmap for richer fingerprints)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = a.Run(ctx)
	if errors.Is(err, agent.ErrCredentialRejected) {
		fmt.Fprintf(os.Stderr, "dzieciol agent: %v\n", err)
		os.Exit(exitCredentialRejected)
	}
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

// systemdUnit is the service installed by `dzieciol agent install` (same file as
// deploy/dzieciol-agent.service). It runs unprivileged (DynamicUser) with a private state
// directory: nmap -sT needs no capabilities.
const systemdUnit = `[Unit]
Description=Dzięcioł remote scanning agent
Documentation=https://github.com/Rei-x/agh-attack-surface-intelligence/blob/main/docs/DEPLOYMENT.md
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
# DZIECIOL_AGENT_SERVER / _TOKEN / _ALLOW_CIDR ... (0600, root).
# The token is single-use: after the first start the credential lives in the state directory.
EnvironmentFile=-/etc/dzieciol-agent.env
ExecStart=/usr/local/bin/dzieciol agent
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=3
DynamicUser=yes
StateDirectory=dzieciol-agent
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`

const (
	agentService  = "dzieciol-agent"
	agentEnvPath  = "/etc/dzieciol-agent.env"
	agentUnitPath = "/etc/systemd/system/dzieciol-agent.service"
	agentBinPath  = "/usr/local/bin/dzieciol"
)

func envQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ").Replace(v) + `"`
}

// cmdAgentInstall installs the agent as a systemd service: binary in /usr/local/bin, settings
// in /etc/dzieciol-agent.env (0600), unit, enable --now. The agent enrolls on its first start.
func cmdAgentInstall(args []string) error {
	f, err := parseAgentFlags("agent install", args)
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("`dzieciol agent install` sets up a systemd service (Linux); elsewhere run `dzieciol agent --server ... --token ...` under your service manager")
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo dzieciol agent install ...)")
	}
	if strings.TrimSpace(f.server) == "" || strings.TrimSpace(f.token) == "" {
		return errors.New("--server and --token are required")
	}
	if _, err := agent.ParseAllowCIDRs(f.allow); err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running on this host; run `dzieciol agent` under your init system instead")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if self != agentBinPath {
		if err := copyFile(self, agentBinPath, 0o755); err != nil {
			return fmt.Errorf("install binary to %s: %w", agentBinPath, err)
		}
		fmt.Printf("installed %s\n", agentBinPath)
	}
	var env strings.Builder
	env.WriteString("# Dzięcioł agent settings (dzieciol agent install). The token is single-use.\n")
	fmt.Fprintf(&env, "DZIECIOL_AGENT_SERVER=%s\n", envQuote(f.server))
	fmt.Fprintf(&env, "DZIECIOL_AGENT_TOKEN=%s\n", envQuote(f.token))
	if f.name != "" {
		fmt.Fprintf(&env, "DZIECIOL_AGENT_NAME=%s\n", envQuote(f.name))
	}
	if len(f.allow) > 0 {
		fmt.Fprintf(&env, "DZIECIOL_AGENT_ALLOW_CIDR=%s\n", envQuote(strings.Join(f.allow, ",")))
	}
	if f.caFile != "" {
		abs, _ := filepath.Abs(f.caFile)
		fmt.Fprintf(&env, "DZIECIOL_AGENT_CA_FILE=%s\n", envQuote(abs))
	}
	if f.insecure {
		env.WriteString("DZIECIOL_AGENT_INSECURE=true\n")
	}
	if err := os.WriteFile(agentEnvPath, []byte(env.String()), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(agentEnvPath, 0o600)
	if err := os.WriteFile(agentUnitPath, []byte(systemdUnit), 0o644); err != nil {
		return err
	}
	for _, c := range [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "--now", agentService}, {"systemctl", "restart", agentService}} {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}
	fmt.Printf("%[1]s service installed and started.\n  logs:   journalctl -u %[1]s -f\n  status: systemctl status %[1]s\n", agentService)
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
