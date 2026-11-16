package main

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyVoice(t *testing.T) {
	cleanGW := &GatewayStats{Sent: 100, Got: 100, MaxRTT: 8 * time.Millisecond, AvgRTT: 3 * time.Millisecond}
	cases := []struct {
		name string
		v    VoiceResult
		want SvcState
		sub  string
	}{
		{"no data", VoiceResult{}, StUnknown, "Не удалось проверить"},
		{"udp dead", VoiceResult{Flows: 15, ControlFlows: 15}, StBlocked, "UDP недоступен вообще"},
		{"rule blocked", VoiceResult{Flows: 15, ControlFlows: 15, ControlOK: 14}, StBlocked, "Звонки блокируются"},
		{"flaky", VoiceResult{Flows: 15, Answered: 1, ControlFlows: 15, ControlOK: 15}, StPartial, "через раз"},
		{"one lost of 15", VoiceResult{Flows: 15, Answered: 14, ControlFlows: 15, ControlOK: 15}, StWorks, "оценка"},
		{"90 percent", VoiceResult{Flows: 20, Answered: 18, ControlFlows: 20, ControlOK: 20}, StWorks, "оценка"},
		{"mostly ok", VoiceResult{Flows: 20, Answered: 17, ControlFlows: 20, ControlOK: 20}, StPartial, "через раз"},
		{"13 of 15", VoiceResult{Flows: 15, Answered: 13, ControlFlows: 15, ControlOK: 15}, StPartial, "через раз"},
		{"works, no soak", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15}, StWorks, "оценка"},
		{"works, clean soak", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 120 * time.Second, Sent: 240, Got: 239, MaxGap: 1200 * time.Millisecond, Gateway: cleanGW}},
			StWorks, "без пропаданий"},
		{"drops, clean gateway", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 120 * time.Second, Sent: 240, Got: 225, MaxGap: 6 * time.Second, Gaps: 3, Gateway: cleanGW}},
			StPartial, "потом обрывается"},
		{"drops, no gateway data", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 60 * time.Second, Sent: 120, Got: 100, MaxGap: 5 * time.Second, Gaps: 1}},
			StPartial, "потом обрывается"},
		{"wifi loss", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 120 * time.Second, Sent: 240, Got: 220, MaxGap: 4 * time.Second, Gaps: 2,
				Gateway: &GatewayStats{Sent: 600, Got: 500, MaxRTT: 90 * time.Millisecond}}},
			StPartial, "в вашем Wi-Fi"},
		{"wifi sustained slow, soak drops", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 120 * time.Second, Sent: 240, Got: 230, MaxGap: 4 * time.Second, Gaps: 1,
				Gateway: &GatewayStats{Sent: 600, Got: 600, MaxRTT: 500 * time.Millisecond, Slow: 5}}},
			StPartial, "в вашем Wi-Fi"},
		{"wifi sustained slow, clean soak", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 120 * time.Second, Sent: 240, Got: 240,
				Gateway: &GatewayStats{Sent: 600, Got: 600, MaxRTT: 500 * time.Millisecond, Slow: 5}}},
			StWorks, "проверьте Wi-Fi"},
		{"wifi spikes", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 120 * time.Second, Sent: 240, Got: 240,
				Gateway: &GatewayStats{Sent: 600, Got: 599, MaxRTT: 800 * time.Millisecond, Slow: 1}}},
			StWorks, "без пропаданий"},
		{"high jitter", VoiceResult{Flows: 15, Answered: 15, ControlFlows: 15, ControlOK: 15,
			Soak: &SoakResult{Duration: 60 * time.Second, Sent: 120, Got: 120, Jitter: 400 * time.Millisecond, Gateway: cleanGW}},
			StPartial, "потом обрывается"},
	}
	for _, c := range cases {
		got, text := classifyVoice(c.v)
		if got != c.want {
			t.Errorf("%s: state %s, want %s (%s)", c.name, got, c.want, text)
		}
		if !strings.Contains(text, c.sub) {
			t.Errorf("%s: text %q lacks %q", c.name, text, c.sub)
		}
		if got != StUnknown && !strings.Contains(text, "оценк") {
			t.Errorf("%s: text must say it is an estimate: %q", c.name, text)
		}
		if strings.Contains(text, "голос работает") {
			t.Errorf("%s: must never claim the voice works: %q", c.name, text)
		}
	}
}

func TestAnalyzeSoak(t *testing.T) {
	var ans []soakAnswer
	// One answer per second except a 5 s hole between 10 s and 15 s.
	for s := 1; s <= 30; s++ {
		if s > 10 && s < 15 {
			continue
		}
		at := time.Duration(s) * time.Second
		ans = append(ans, soakAnswer{srv: 0, at: at, rtt: 30 * time.Millisecond})
	}
	r := analyzeSoak(30, ans, 30*time.Second)
	if r.Gaps != 1 || r.MaxGap != 5*time.Second {
		t.Fatalf("gaps %d maxgap %v, want 1 and 5s", r.Gaps, r.MaxGap)
	}
	if r.Got != 26 || r.Sent != 30 || r.Jitter != 0 {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestAnalyzeSoakUnionAndJitter(t *testing.T) {
	// Server 0 goes silent for good, server 1 keeps answering: no gap.
	var ans []soakAnswer
	for s := 1; s <= 10; s++ {
		at := time.Duration(s) * time.Second
		ans = append(ans, soakAnswer{srv: 1, at: at + 5*time.Millisecond, rtt: time.Duration(20+10*(s%2)) * time.Millisecond})
	}
	r := analyzeSoak(20, ans, 10*time.Second)
	if r.Gaps != 0 {
		t.Fatalf("union of servers must hide one silent server, gaps=%d", r.Gaps)
	}
	if r.Jitter != 10*time.Millisecond {
		t.Fatalf("jitter %v, want 10ms", r.Jitter)
	}
}

func TestAnalyzeSoakNoAnswers(t *testing.T) {
	r := analyzeSoak(10, nil, 10*time.Second)
	if r.Gaps != 1 || r.MaxGap != 10*time.Second || r.Got != 0 {
		t.Fatalf("silent soak: %+v", r)
	}
}

func TestGatewayHelpers(t *testing.T) {
	g := gatewayStatsFrom(5, []time.Duration{2 * time.Millisecond, 4 * time.Millisecond, 9 * time.Millisecond})
	if g.Sent != 5 || g.Got != 3 || g.MaxRTT != 9*time.Millisecond || g.AvgRTT != 5*time.Millisecond {
		t.Fatalf("stats %+v", g)
	}
	if !gatewayBad(g) { // 40% loss
		t.Fatal("40% loss to the router must be bad")
	}
	if gatewayBad(&GatewayStats{Sent: 100, Got: 100, MaxRTT: 800 * time.Millisecond, Slow: 1}) {
		t.Fatal("a single spike is not sustained evidence")
	}
	if !gatewayBad(&GatewayStats{Sent: 100, Got: 100, MaxRTT: 400 * time.Millisecond, Slow: 3}) {
		t.Fatal("three slow replies are sustained")
	}
	if gatewayBad(&GatewayStats{Sent: 100, Got: 95}) {
		t.Fatal("5% loss alone is not bad")
	}
	if gs := gatewayStatsFrom(3, []time.Duration{10 * time.Millisecond, 300 * time.Millisecond, 350 * time.Millisecond}); gs.Slow != 2 {
		t.Fatalf("slow count %d", gs.Slow)
	}
	if gatewayBad(nil) || gatewayBad(&GatewayStats{}) {
		t.Fatal("no data is not bad")
	}
}

func TestStunMessageRoundTrip(t *testing.T) {
	id, msg := newStunRequest()
	if len(msg) != 20 {
		t.Fatalf("len %d", len(msg))
	}
	reply := append([]byte(nil), msg...)
	reply[0], reply[1] = 0x01, 0x01 // Binding success response
	got, ok := parseStunReply(reply)
	if !ok || got != id {
		t.Fatal("reply must parse back to the same transaction id")
	}
	if _, ok := parseStunReply(msg); ok {
		t.Fatal("a request is not a response")
	}
	if _, ok := parseStunReply([]byte{1, 2, 3}); ok {
		t.Fatal("short packet")
	}
}

func TestVoicePlural(t *testing.T) {
	for n, want := range map[int]string{1: "раз", 2: "раза", 5: "раз", 11: "раз", 22: "раза"} {
		if got := voicePlural(n, "раз", "раза", "раз"); got != want {
			t.Errorf("%d: %s, want %s", n, got, want)
		}
	}
}

func TestVoiceOK(t *testing.T) {
	cases := []struct {
		v    VoiceResult
		want bool
	}{
		{VoiceResult{}, false},
		{VoiceResult{Flows: 15, Answered: 15}, true},
		{VoiceResult{Flows: 15, Answered: 14}, true},
		{VoiceResult{Flows: 20, Answered: 18}, true},
		{VoiceResult{Flows: 15, Answered: 13}, false},
		{VoiceResult{Flows: 15, Answered: 15, State: StBlocked}, false},
	}
	for i, c := range cases {
		if got := voiceOK(c.v); got != c.want {
			t.Errorf("case %d: %v, want %v", i, got, c.want)
		}
	}
}
