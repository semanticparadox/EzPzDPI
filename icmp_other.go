//go:build !windows

package main

import (
	"context"
	"net"
	"time"
)

// defaultGateway is only implemented on Windows; elsewhere the gateway part
// of the voice soak is skipped.
func defaultGateway() (net.IP, bool) { return nil, false }

// pingGateway is a stub: raw ICMP needs privileges that tests do not have.
func pingGateway(ctx context.Context, gw net.IP, n int, interval time.Duration) *GatewayStats {
	return nil
}
