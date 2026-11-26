package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// defaultPort is the port the image listens on.
const defaultPort = "5000"

// runHealthcheck asks /ready on the loopback interface, so the image keeps
// its HEALTHCHECK without a shell or Python. Like the Python image it tries
// PORT first and then 5000; a reply with status 2xx counts as ready.
func runHealthcheck(ctx context.Context, args []string, s streams) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(s.stderr)
	timeout := fs.Duration("timeout", 2*time.Second, "timeout per port")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *timeout <= 0 {
		return usageError(s.stderr, "healthcheck takes only -timeout with a positive duration")
	}
	client := &http.Client{
		Timeout: *timeout,
		// Never through a proxy from the environment, never anywhere else.
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var errs []error
	for _, port := range healthcheckPorts(os.Getenv("PORT")) {
		err := probeReady(ctx, client, port)
		if err == nil {
			return 0
		}
		errs = append(errs, err)
	}
	write(s.stderr, fmt.Sprintf("webssh: not ready: %v\n", errors.Join(errs...)))
	return 1
}

// healthcheckPorts returns PORT when it is a valid port, then 5000, without
// duplicates. An invalid PORT is skipped, so it can never change the host
// of the request.
func healthcheckPorts(port string) []string {
	if _, err := parsePort(port); err != nil || port == defaultPort {
		return []string{defaultPort}
	}
	return []string{port, defaultPort}
}

func probeReady(ctx context.Context, client *http.Client, port string) error {
	url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/ready"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req) // #nosec G704 -- fixed loopback address, port validated by healthcheckPorts
	if err != nil {
		return fmt.Errorf("port %s: %w", port, err)
	}
	_, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if err := errors.Join(copyErr, resp.Body.Close()); err != nil {
		return fmt.Errorf("port %s: %w", port, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("port %s: status %d", port, resp.StatusCode)
	}
	return nil
}
