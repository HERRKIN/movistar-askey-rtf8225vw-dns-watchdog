// Command sshprobe explores the router's SSH CLI to discover whether the LAN
// DNS can be configured over SSH (a much cleaner path than the web UI).
// Read-only: it only runs help/discovery commands. Reads the password from
// watchdog.secrets via config (never printed).
//
//	go run ./cmd/sshprobe            # user "support"
//	SSH_USER=admin go run ./cmd/sshprobe
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"dns-modem-watchdog/internal/config"

	"golang.org/x/crypto/ssh"
)

func main() {
	logger := log.New(os.Stdout, "sshprobe: ", 0)

	// config.Load requires these; sshprobe doesn't use them.
	if os.Getenv("NTFY_URL") == "" {
		os.Setenv("NTFY_URL", "https://ntfy.invalid")
	}
	if os.Getenv("DESIRED_DNS") == "" {
		os.Setenv("DESIRED_DNS", "192.168.1.254")
	}
	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("config error: %v", err)
	}

	host := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(cfg.RouterURL, "http://"), "https://"), "/")
	if !strings.Contains(host, ":") {
		host += ":22"
	}
	user := os.Getenv("SSH_USER")
	if user == "" {
		user = "support"
	}

	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.RouterPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	logger.Printf("connecting to %s as %q ...", host, user)
	client, err := ssh.Dial("tcp", host, sshCfg)
	if err != nil {
		logger.Fatalf("ssh dial/auth failed: %v", err)
	}
	defer client.Close()
	logger.Printf("AUTH OK — connected")

	session, err := client.NewSession()
	if err != nil {
		logger.Fatalf("new session: %v", err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("vt100", 200, 80, modes); err != nil {
		logger.Printf("pty request failed (continuing): %v", err)
	}
	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf
	stdin, err := session.StdinPipe()
	if err != nil {
		logger.Fatalf("stdin pipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		logger.Fatalf("start shell: %v", err)
	}

	// Discovery commands only (read-only).
	for _, c := range []string{"?", "help", "help all", "ls", "cat /etc/passwd | head", "show"} {
		_, _ = stdin.Write([]byte(c + "\n"))
		time.Sleep(1200 * time.Millisecond)
	}
	_, _ = stdin.Write([]byte("exit\n"))
	time.Sleep(800 * time.Millisecond)
	_ = session.Close()

	fmt.Println("----- SSH SHELL OUTPUT -----")
	fmt.Println(buf.String())
}
