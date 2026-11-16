package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"time"
)

// StunResult summarises a series of STUN Binding requests to one server.
type StunResult struct {
	Server string
	Sent   int
	Got    int
	Median time.Duration
	// Longest run of consecutive lost answers: long gaps are what drop a
	// voice call even when the average loss looks fine.
	MaxGap int
	Err    string
}

// Loss is the share of requests that got no answer.
func (s StunResult) Loss() float64 {
	if s.Sent == 0 {
		return 1
	}
	return 1 - float64(s.Got)/float64(s.Sent)
}

const stunMagic = 0x2112A442

// stunProbe sends count STUN Binding requests (RFC 5389) to addr, one per
// interval, over a single UDP socket, the way a voice client keeps a flow.
func stunProbe(ctx context.Context, addr string, count int, interval time.Duration) StunResult {
	res := StunResult{Server: addr}
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		res.Err = "адрес не найден"
		return res
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer conn.Close()

	type pending struct {
		seq  int
		sent time.Time
	}
	inflight := map[[12]byte]pending{}
	answered := make([]bool, count)
	var rtts []time.Duration
	buf := make([]byte, 1500)
	readUntil := func(deadline time.Time) {
		for {
			_ = conn.SetReadDeadline(deadline)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != 0x0101 || binary.BigEndian.Uint32(buf[4:8]) != stunMagic {
				continue
			}
			var id [12]byte
			copy(id[:], buf[8:20])
			if p, ok := inflight[id]; ok {
				delete(inflight, id)
				answered[p.seq] = true
				rtts = append(rtts, time.Since(p.sent))
			}
		}
	}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		var id [12]byte
		_, _ = rand.Read(id[:])
		msg := make([]byte, 20)
		binary.BigEndian.PutUint16(msg[0:2], 0x0001)
		binary.BigEndian.PutUint32(msg[4:8], stunMagic)
		copy(msg[8:20], id[:])
		if _, err := conn.WriteToUDP(msg, raddr); err != nil {
			res.Err = err.Error()
			break
		}
		inflight[id] = pending{seq: i, sent: time.Now()}
		res.Sent++
		readUntil(time.Now().Add(interval))
	}
	readUntil(time.Now().Add(time.Second))

	gap := 0
	for i := 0; i < res.Sent; i++ {
		if answered[i] {
			res.Got++
			gap = 0
			continue
		}
		gap++
		res.MaxGap = max(res.MaxGap, gap)
	}
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		res.Median = rtts[len(rtts)/2]
	}
	if res.Got == 0 && res.Err == "" {
		res.Err = errors.New("нет ответа").Error()
	}
	return res
}
