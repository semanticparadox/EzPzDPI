//go:build network

package main

import (
	"context"
	"testing"
	"time"
)

// Run with: go test -tags network -run Network -v
// Hits real STUN servers; not part of the normal test run.
func TestNetworkVoiceBurst(t *testing.T) {
	v := voiceBurst(context.Background(), 10)
	t.Logf("%+v", v)
	if v.Flows == 0 {
		t.Skip("no network")
	}
}

func TestNetworkVoiceSoak(t *testing.T) {
	r := voiceSoak(context.Background(), 6*time.Second)
	if r == nil {
		t.Skip("no network")
	}
	t.Logf("%+v gw=%+v", *r, r.Gateway)
	if r.Sent == 0 {
		t.Fatal("nothing sent")
	}
}
