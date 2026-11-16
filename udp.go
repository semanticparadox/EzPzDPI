package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
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
		id, msg := newStunRequest()
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

// newStunRequest builds an RFC 5389 Binding request with a random
// transaction id.
func newStunRequest() (id [12]byte, msg []byte) {
	_, _ = rand.Read(id[:])
	msg = make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0001)
	binary.BigEndian.PutUint32(msg[4:8], stunMagic)
	copy(msg[8:20], id[:])
	return id, msg
}

// parseStunReply returns the transaction id of a Binding success response.
func parseStunReply(b []byte) (id [12]byte, ok bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:2]) != 0x0101 || binary.BigEndian.Uint32(b[4:8]) != stunMagic {
		return id, false
	}
	copy(id[:], b[8:20])
	return id, true
}

// --- voice (Discord and call) estimate ---

// The rule server sits inside the 19294-19344 range that bypass presets
// desync for Discord voice, so it travels the same rule as real calls. The
// control server is outside every rule: if only the rule server is silent,
// the cause is a block of voice traffic and not a dead UDP path.
const (
	voiceRuleServer    = "stun.l.google.com:19302"
	voiceControlServer = "stun.cloudflare.com:3478"
	burstStagger       = 80 * time.Millisecond // spread flows so the router is not flooded
	burstWait          = 2500 * time.Millisecond
	soakGapLimit       = 2 * time.Second // a silence longer than this is audible in a call
)

// VoiceResult is the estimate of how a voice call would behave. It is built
// from STUN probes, not from a real call, so every text says "оценка".
type VoiceResult struct {
	Flows, Answered         int         // handshake burst on the voice rule (stun.l.google.com:19302)
	ControlFlows, ControlOK int         // control outside the rule (stun.cloudflare.com:3478)
	Soak                    *SoakResult // nil when not run
	State                   SvcState    // StWorks, StPartial, StBlocked, StUnknown
	Detail                  string      // plain Russian, says it is an estimate
}

// SoakResult describes a long run on kept flows.
type SoakResult struct {
	Duration time.Duration
	Sent     int
	Got      int
	MaxGap   time.Duration // longest silence
	Gaps     int           // silences > 2 s
	Jitter   time.Duration
	Gateway  *GatewayStats // nil if unavailable
}

// GatewayStats is the ping series to the default gateway (the router).
type GatewayStats struct {
	Sent, Got      int
	MaxRTT, AvgRTT time.Duration
	Slow           int // replies slower than gatewaySlowRTT
}

const (
	gatewaySlowRTT   = 300 * time.Millisecond
	gatewaySlowCount = 3 // one stray spike is normal on Wi-Fi; sustained is not
	voiceOKRatio     = 0.9
)

// stunOnce opens a fresh socket (so a fresh source port, like a new call),
// sends one Binding request and reports whether an answer came back in time.
func stunOnce(ctx context.Context, raddr *net.UDPAddr, wait time.Duration) bool {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return false
	}
	defer conn.Close()
	ids := map[[12]byte]bool{}
	send := func() bool {
		id, msg := newStunRequest()
		if _, err := conn.WriteToUDP(msg, raddr); err != nil {
			return false
		}
		ids[id] = true
		return true
	}
	if !send() {
		return false
	}
	// Close the socket when the context ends so the read below returns early.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// One retry on the same socket halfway through: a single lost datagram is
	// not a blocked flow, DPI blocking would drop the retry too.
	start := time.Now()
	retryAt := start.Add(wait / 2)
	end := start.Add(wait)
	retried := false
	buf := make([]byte, 1500)
	for {
		dl := end
		if !retried {
			dl = retryAt
		}
		_ = conn.SetReadDeadline(dl)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if !retried && ctx.Err() == nil && errors.As(err, &ne) && ne.Timeout() {
				retried = true
				if !send() {
					return false
				}
				continue
			}
			return false
		}
		if got, ok := parseStunReply(buf[:n]); ok && ids[got] {
			return true
		}
	}
}

// burstCount runs flows fresh-socket probes against one server and returns
// how many were answered.
func burstCount(ctx context.Context, raddr *net.UDPAddr, flows int) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < flows; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if stunOnce(ctx, raddr, burstWait) {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
		select {
		case <-ctx.Done():
		case <-time.After(burstStagger):
		}
	}
	wg.Wait()
	return ok
}

// voiceBurst is the handshake test: flows fresh UDP flows to the voice rule
// and the same number to the control server, about 3-5 s in total. Every flow
// uses a new source port because DPI decides on the first packets of a flow.
func voiceBurst(ctx context.Context, flows int) VoiceResult {
	if flows <= 0 {
		flows = 15
	}
	rule, err1 := net.ResolveUDPAddr("udp4", voiceRuleServer)
	ctrl, err2 := net.ResolveUDPAddr("udp4", voiceControlServer)
	if err1 != nil && err2 != nil {
		v := VoiceResult{}
		v.State, v.Detail = classifyVoice(v)
		return v
	}
	var v VoiceResult
	var wg sync.WaitGroup
	if err1 == nil {
		wg.Add(1)
		go func() { defer wg.Done(); v.Answered = burstCount(ctx, rule, flows) }()
		v.Flows = flows
	}
	if err2 == nil {
		wg.Add(1)
		go func() { defer wg.Done(); v.ControlOK = burstCount(ctx, ctrl, flows) }()
		v.ControlFlows = flows
	}
	wg.Wait()
	if ctx.Err() != nil { // cut short: the numbers are not a measurement
		v.Flows, v.ControlFlows = 0, 0
	}
	v.State, v.Detail = classifyVoice(v)
	return v
}

// soakAnswer is one received STUN answer during the soak.
type soakAnswer struct {
	srv int
	at  time.Duration // offset from the soak start
	rtt time.Duration
}

// analyzeSoak turns raw answers into the soak statistics. Silences are
// measured on the union of all servers: a call survives one server hiccup
// but not a moment when nothing arrives at all.
func analyzeSoak(sent int, ans []soakAnswer, total time.Duration) *SoakResult {
	r := &SoakResult{Duration: total, Sent: sent, Got: len(ans)}
	sorted := append([]soakAnswer(nil), ans...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].at < sorted[j].at })
	prev := time.Duration(0)
	note := func(gap time.Duration) {
		r.MaxGap = max(r.MaxGap, gap)
		if gap > soakGapLimit {
			r.Gaps++
		}
	}
	for _, a := range sorted {
		if a.at > total {
			break
		}
		note(a.at - prev)
		prev = a.at
	}
	note(total - prev)

	// Jitter: mean absolute change of RTT between consecutive answers of
	// the same server (RFC 3550 style, without smoothing).
	last := map[int]time.Duration{}
	var sum time.Duration
	n := 0
	for _, a := range sorted {
		if p, ok := last[a.srv]; ok {
			d := a.rtt - p
			if d < 0 {
				d = -d
			}
			sum += d
			n++
		}
		last[a.srv] = a.rtt
	}
	if n > 0 {
		r.Jitter = sum / time.Duration(n)
	}
	return r
}

// soakFlow is one kept-alive UDP flow to one STUN server.
type soakFlow struct {
	idx   int
	conn  *net.UDPConn
	raddr *net.UDPAddr
}

// voiceSoak keeps two flows open for d, sends one STUN request per second on
// each and pings the gateway at 5 Hz in parallel, so a gap can be blamed on
// the local network or on the path beyond it. Returns nil when no flow could
// be opened or the context ended early.
func voiceSoak(ctx context.Context, d time.Duration) *SoakResult {
	if d < 2*time.Second {
		d = 2 * time.Second
	}
	var flows []*soakFlow
	for i, s := range []string{voiceRuleServer, voiceControlServer} {
		raddr, err := net.ResolveUDPAddr("udp4", s)
		if err != nil {
			continue
		}
		conn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			continue
		}
		defer conn.Close()
		flows = append(flows, &soakFlow{idx: i, conn: conn, raddr: raddr})
	}
	if len(flows) == 0 {
		return nil
	}

	var gw *GatewayStats
	var gwDone chan struct{}
	if ip, ok := defaultGateway(); ok {
		gwDone = make(chan struct{})
		go func() {
			defer close(gwDone)
			gw = pingGateway(ctx, ip, int(d/(200*time.Millisecond)), 200*time.Millisecond)
		}()
	}

	start := time.Now()
	var mu sync.Mutex
	inflight := map[[12]byte]time.Time{}
	var answers []soakAnswer
	var rd sync.WaitGroup
	for _, f := range flows {
		rd.Add(1)
		go func() {
			defer rd.Done()
			buf := make([]byte, 1500)
			for {
				n, _, err := f.conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				id, ok := parseStunReply(buf[:n])
				if !ok {
					continue
				}
				now := time.Now()
				mu.Lock()
				if t, ok := inflight[id]; ok {
					delete(inflight, id)
					answers = append(answers, soakAnswer{srv: f.idx, at: now.Sub(start), rtt: now.Sub(t)})
				}
				mu.Unlock()
			}
		}()
	}

	sent := 0
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for sec := 0; sec < int(d/time.Second) && ctx.Err() == nil; sec++ {
		for _, f := range flows {
			id, msg := newStunRequest()
			mu.Lock()
			inflight[id] = time.Now()
			mu.Unlock()
			if _, err := f.conn.WriteToUDP(msg, f.raddr); err == nil {
				sent++
			}
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
		}
	}
	// Give the last answers a moment, then unblock the readers.
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
	for _, f := range flows {
		_ = f.conn.Close()
	}
	rd.Wait()
	if gwDone != nil {
		<-gwDone
	}
	if ctx.Err() != nil {
		return nil
	}
	mu.Lock()
	// Measure up to d, not up to the drain second, or every run would end
	// with an artificial one-second silence.
	res := analyzeSoak(sent, answers, d)
	mu.Unlock()
	res.Gateway = gw
	return res
}

// gatewayStatsFrom aggregates the RTTs of answered pings; sent counts all.
func gatewayStatsFrom(sent int, rtts []time.Duration) *GatewayStats {
	g := &GatewayStats{Sent: sent, Got: len(rtts)}
	var sum time.Duration
	for _, r := range rtts {
		sum += r
		g.MaxRTT = max(g.MaxRTT, r)
		if r >= gatewaySlowRTT {
			g.Slow++
		}
	}
	if len(rtts) > 0 {
		g.AvgRTT = sum / time.Duration(len(rtts))
	}
	return g
}

// Thresholds for "the local network is the problem": sustained evidence only
// (loss above 10% or at least 3 replies over 300 ms). One stray spike is
// ordinary Wi-Fi and must not blame the user's network.
func gatewayBad(g *GatewayStats) bool {
	if g == nil || g.Sent == 0 {
		return false
	}
	loss := 1 - float64(g.Got)/float64(g.Sent)
	return loss > 0.10 || g.Slow >= gatewaySlowCount
}

// voiceOK reports whether the handshake burst is good enough to count the
// voice path as connecting: at least 90% of flows answered and not blocked.
func voiceOK(v VoiceResult) bool {
	if v.Flows <= 0 || v.State == StBlocked {
		return false
	}
	return float64(v.Answered) >= voiceOKRatio*float64(v.Flows)
}

// soakBad reports whether the soak shows what a user hears as drop-outs.
func soakBad(s *SoakResult) bool {
	if s == nil || s.Sent == 0 {
		return false
	}
	loss := 1 - float64(s.Got)/float64(s.Sent)
	return s.Gaps > 0 || loss > 0.10 || s.Jitter > 150*time.Millisecond
}

// voicePlural picks the Russian noun form for n (1 пропадание, 2 пропадания, 5 пропаданий).
func voicePlural(n int, one, few, many string) string {
	m := n % 100
	if m >= 11 && m <= 14 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	}
	return many
}

// classifyVoice maps measurements to a state and a plain Russian sentence.
// Pure function. Order matters: dead UDP, then blocked rule, then flaky
// handshake, then the local network, then drop-outs, and only then "works".
func classifyVoice(v VoiceResult) (SvcState, string) {
	const tail = " Это оценка по тестовым пакетам, настоящий звонок не проверялся."
	if v.Flows <= 0 {
		return StUnknown, "Не удалось проверить голос: нет связи со служебными серверами или проверку прервали. Это не значит, что звонки не работают."
	}
	if v.Answered == 0 {
		if v.ControlFlows > 0 && v.ControlOK == 0 {
			return StBlocked, fmt.Sprintf("UDP недоступен вообще: ни один из %d пробных пакетов не получил ответа, даже вне правил для голоса. Звонки не соединятся. Вероятно, UDP закрыт роутером, антивирусом или провайдером.", v.Flows) + tail
		}
		if v.ControlFlows > 0 {
			return StBlocked, fmt.Sprintf("Звонки блокируются: на порту голосовых серверов 0 ответов из %d, а контрольная проверка проходит (%d из %d). Вероятно, блокируется именно голосовой трафик.", v.Flows, v.ControlOK, v.ControlFlows) + tail
		}
		return StBlocked, fmt.Sprintf("Голосовой сервер не отвечает: 0 ответов из %d. Подключение к голосу, вероятно, не пройдёт.", v.Flows) + tail
	}
	if float64(v.Answered) < voiceOKRatio*float64(v.Flows) {
		return StPartial, fmt.Sprintf("Голос подключается через раз: ответили %d из %d проверок. Так выглядит бесконечное «RTC подключение» в Discord.", v.Answered, v.Flows) + tail
	}
	s := v.Soak
	if s != nil && soakBad(s) && gatewayBad(s.Gateway) {
		g := s.Gateway
		return StPartial, fmt.Sprintf("Обрывы ещё в вашем Wi-Fi или кабеле: до роутера потеряно %d из %d пакетов, самая долгая задержка %d мс. Сначала проверьте домашнюю сеть, обход тут не поможет.", g.Sent-g.Got, g.Sent, g.MaxRTT.Milliseconds()) + tail
	}
	if soakBad(s) {
		return StPartial, fmt.Sprintf("Подключается, потом обрывается: за %d с связь пропадала %d %s, самая долгая тишина %.1f с, дошло %d из %d пакетов. Роутер при этом отвечал ровно, значит, вероятно, нестабилен путь за ним.", int(s.Duration.Seconds()), s.Gaps, voicePlural(s.Gaps, "раз", "раза", "раз"), s.MaxGap.Seconds(), s.Got, s.Sent) + tail
	}
	if s == nil {
		return StWorks, fmt.Sprintf("Голосовые соединения устанавливаются: %d из %d. Проверку на обрывы не запускали.", v.Answered, v.Flows) + tail
	}
	note := ""
	if gatewayBad(s.Gateway) {
		note = " Роутер местами отвечал с задержкой, если будут сбои, проверьте Wi-Fi."
	}
	return StWorks, fmt.Sprintf("Голос выглядит стабильным: %d с без пропаданий, соединения устанавливаются (%d из %d).", int(s.Duration.Seconds()), v.Answered, v.Flows) + note + tail
}
