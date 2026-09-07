// © 2026 Dan Vladoiu. All rights reserved.
package alert

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSMTPServer starts a minimal SMTP conversation server on 127.0.0.1:0.
// It records the DATA-phase message body and delivers it on the channel.
func fakeSMTPServer(t *testing.T, received chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		defer ln.Close()
		r := bufio.NewReader(conn)
		fmt.Fprintf(conn, "220 vigil-test ESMTP\r\n")
		inData := false
		var dataBuf strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimRight(line, "\r\n") == "." {
					fmt.Fprintf(conn, "250 accepted\r\n")
					inData = false
					received <- dataBuf.String()
					dataBuf.Reset()
				} else {
					dataBuf.WriteString(line)
				}
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				fmt.Fprintf(conn, "250 vigil-test\r\n")
			case strings.HasPrefix(upper, "MAIL"):
				fmt.Fprintf(conn, "250 ok\r\n")
			case strings.HasPrefix(upper, "RCPT"):
				fmt.Fprintf(conn, "250 ok\r\n")
			case strings.HasPrefix(upper, "DATA"):
				fmt.Fprintf(conn, "354 end data with <CR><LF>.<CR><LF>\r\n")
				inData = true
			case strings.HasPrefix(upper, "QUIT"):
				fmt.Fprintf(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprintf(conn, "250 ok\r\n")
			}
		}
	}()
	return ln.Addr().String()
}

// TestSendEmailDeliversMessage verifies the full SMTP conversation and
// message content for the v0.8.0 email route.
func TestSendEmailDeliversMessage(t *testing.T) {
	received := make(chan string, 1)
	addr := fakeSMTPServer(t, received)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	r := NewRouter(RoutingConfig{
		SMTPServer:     host,
		SMTPPort:       port,
		EmailFrom:      "vigil@test.local",
		EmailTo:        "soc@test.local, dev@test.local",
		EmailMinLevel:  "warn",
	})
	if r == nil {
		t.Fatal("expected non-nil router with SMTP configured")
	}

	r.sendEmail(Alert{
		Level:    CRITICAL,
		Category: "TEST_CATEGORY",
		Message:  "email route works",
		PID:      1234,
		Timestamp: time.Now(),
	})

	select {
	case msg := <-received:
		for _, want := range []string{
			"From: vigil@test.local",
			"To: soc@test.local, dev@test.local",
			"Subject: [VIGIL CRITICAL] TEST_CATEGORY",
			"email route works",
			"PID:       1234",
			"Severity: CRITICAL",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("message missing %q\n--- got ---\n%s", want, msg)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no email received by fake SMTP server within 5s")
	}
}

// TestEmailLevelDefaults verifies the email route defaults to CRITICAL.
func TestEmailLevelDefaults(t *testing.T) {
	r := NewRouter(RoutingConfig{SMTPServer: "smtp.example.com", EmailTo: "a@b.example"})
	if r == nil {
		t.Fatal("expected non-nil router")
	}
	if r.emailLevel != CRITICAL {
		t.Errorf("default email level = %v, want CRITICAL", r.emailLevel)
	}
}

// TestSplitRecipients verifies comma-separated recipient parsing.
func TestSplitRecipients(t *testing.T) {
	got := splitRecipients("a@x.example, b@y.example ,,")
	if len(got) != 2 || got[0] != "a@x.example" || got[1] != "b@y.example" {
		t.Errorf("splitRecipients = %v, want [a@x.example b@y.example]", got)
	}
}