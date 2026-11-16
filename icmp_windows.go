//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestRoute = iphlpapi.NewProc("GetBestRoute")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSend     = iphlpapi.NewProc("IcmpSendEcho")
)

// mibIPForwardRow mirrors MIB_IPFORWARDROW (14 DWORDs).
type mibIPForwardRow struct {
	Dest, Mask, Policy, NextHop, IfIndex, Type, Proto, Age, NextHopAS uint32
	Metric1, Metric2, Metric3, Metric4, Metric5                       uint32
}

// defaultGateway asks Windows which next hop it would use for an internet
// address (the routing table decides, no adapter names or locale involved).
// GetBestRoute is the simple IPv4 form of GetBestRoute2: same answer, one
// flat struct. An on-link route (next hop 0.0.0.0) has no gateway to ping.
func defaultGateway() (net.IP, bool) {
	var row mibIPForwardRow
	dest := binary.LittleEndian.Uint32(net.IPv4(8, 8, 8, 8).To4())
	r, _, _ := procGetBestRoute.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&row)))
	if r != 0 || row.NextHop == 0 {
		return nil, false
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, row.NextHop)
	return ip, true
}

// pingGateway sends n ICMP echoes, one per interval, with IcmpSendEcho (no
// raw sockets, works without extra privileges). A 1 s timeout per echo keeps
// the cadence close to the requested interval.
func pingGateway(ctx context.Context, gw net.IP, n int, interval time.Duration) *GatewayStats {
	ip4 := gw.To4()
	if ip4 == nil || n <= 0 {
		return nil
	}
	h, _, _ := procIcmpCreate.Call()
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return nil
	}
	defer procIcmpClose.Call(h)

	addr := binary.LittleEndian.Uint32(ip4)
	payload := []byte("ezpzdpi-ping")
	// ICMP_ECHO_REPLY (40 bytes on x64) + payload + 8 + IO_STATUS_BLOCK.
	reply := make([]byte, 256)
	var rtts []time.Duration
	sent := 0
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for i := 0; i < n && ctx.Err() == nil; i++ {
		start := time.Now()
		cnt, _, _ := procIcmpSend.Call(h, uintptr(addr),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 1000)
		sent++
		// Reply layout: Address u32, Status u32, RoundTripTime u32. Status 0 = success.
		if cnt > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0 {
			rtt := time.Duration(binary.LittleEndian.Uint32(reply[8:12])) * time.Millisecond
			if rtt == 0 { // the API has 1 ms resolution; local replies often read 0
				rtt = time.Since(start)
			}
			rtts = append(rtts, rtt)
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
	return gatewayStatsFrom(sent, rtts)
}
