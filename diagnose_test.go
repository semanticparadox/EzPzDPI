package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func probe(svc, host string, ok bool, stage string, mut ...func(*ProbeResult)) ProbeResult {
	p := ProbeResult{Target: Target{Service: svc, Host: host}, OK: ok, Stage: stage}
	if !ok {
		p.Err = "x"
	}
	for _, m := range mut {
		m(&p)
	}
	return p
}

func TestDiagnose(t *testing.T) {
	svc := &Service{ID: "s", GeoSigns: []string{"unsupported_country"}}
	opt := func(p *ProbeResult) { p.Optional = true }
	cases := []struct {
		name string
		res  []ProbeResult
		want SvcState
	}{
		{"all ok", []ProbeResult{probe("s", "a", true, ""), probe("s", "b", true, "")}, StWorks},
		{"tls hang, server answers neutral sni", []ProbeResult{probe("s", "a", false, StageTLS, func(p *ProbeResult) { p.Neutral = NeutralAnswers })}, StBlocked},
		{"tls hang, not checked", []ProbeResult{probe("s", "a", false, StageTLS)}, StBlocked},
		{"tls hang, address silent", []ProbeResult{probe("s", "a", false, StageTLS, func(p *ProbeResult) { p.Neutral = NeutralSilent })}, StIPBlock},
		{"tcp fails", []ProbeResult{probe("s", "a", false, StageTCP)}, StIPBlock},
		{"freeze after 16 KB", []ProbeResult{probe("s", "a", true, ""), probe("s", "b", false, StageData)}, StThrottled},
		{"name block wins over ip", []ProbeResult{probe("s", "a", false, StageTCP), probe("s", "b", false, StageTLS)}, StBlocked},
		{"dns stub", []ProbeResult{probe("s", "a", false, StageTLS, func(p *ProbeResult) { p.CertErr = true })}, StDNS},
		{"geo page", []ProbeResult{probe("s", "a", true, "", func(p *ProbeResult) { p.Status = 403; p.Head = []byte(`{"code":"Unsupported_Country"}`) })}, StGeo},
		{"451", []ProbeResult{probe("s", "a", true, "", func(p *ProbeResult) { p.Status = 451 })}, StGeo},
		{"optional fails", []ProbeResult{probe("s", "a", true, ""), probe("s", "b", false, StageTLS, opt)}, StPartial},
		{"other service ignored", []ProbeResult{probe("s", "a", true, ""), probe("z", "b", false, StageTCP)}, StWorks},
		{"no targets", nil, StUnknown},
	}
	for _, c := range cases {
		if got := Diagnose(svc, Report{Results: c.res}); got.State != c.want {
			t.Errorf("%s: got %s want %s (%s)", c.name, got.State, c.want, got.Detail)
		}
	}
	geoSvc := &Service{ID: "s", ProviderGeo: true}
	if d := Diagnose(geoSvc, Report{Results: []ProbeResult{probe("s", "a", true, "")}}); d.State != StGeo {
		t.Errorf("provider geo with open network: %s", d.State)
	}
	if d := Diagnose(geoSvc, Report{Results: []ProbeResult{probe("s", "a", false, StageTLS)}}); d.State != StBlocked {
		t.Errorf("provider geo with blocked network: %s", d.State)
	}
	codes := &Service{ID: "s", GeoCodes: []int{403}}
	if d := Diagnose(codes, Report{Results: []ProbeResult{probe("s", "a", true, "", func(p *ProbeResult) { p.Status = 403 })}}); d.State != StGeo {
		t.Errorf("geo code: %s", d.State)
	}
	spoof := func(p *ProbeResult) { p.DNSSpoofed = true }
	if d := Diagnose(svc, Report{Results: []ProbeResult{probe("s", "a", true, "", spoof)}}); d.State != StDNS {
		t.Errorf("dns only: %s", d.State)
	}
	if d := Diagnose(svc, Report{Results: []ProbeResult{probe("s", "a", false, StageTLS, spoof)}}); d.State != StBlocked || !strings.Contains(d.Detail, "защищённый DNS") {
		t.Errorf("dns + block: %+v", d)
	}
	anyOK := &Service{ID: "s", AnyOK: true}
	if d := Diagnose(anyOK, Report{Results: []ProbeResult{probe("s", "a", true, ""), probe("s", "b", false, StageTLS)}}); d.State != StPartial {
		t.Errorf("any ok: %s", d.State)
	}
	if d := Diagnose(anyOK, Report{Results: []ProbeResult{probe("s", "a", false, StageTLS), probe("s", "b", false, StageTLS)}}); d.State != StBlocked {
		t.Errorf("any ok, all fail: %s", d.State)
	}
	known := &Service{ID: "s", Known: "Звонки заблокированы."}
	d := Diagnose(known, Report{Results: []ProbeResult{probe("s", "a", true, "")}})
	if d.State != StPartial || !strings.Contains(d.Detail, "Звонки") {
		t.Errorf("known note: %+v", d)
	}
}

func TestScoreTrial(t *testing.T) {
	r := Report{Results: []ProbeResult{
		probe("yt", "a", true, "", func(p *ProbeResult) { p.Took = time.Second }),
		probe("dc", "b", false, StageTLS),
		probe("tg", "c", true, ""),
	}}
	s := ScoreTrial(r, []string{"yt", "dc"}, []string{"tg"})
	if s.Fixed != 1 || s.Broke != 0 || !s.Services["yt"] || s.Services["dc"] {
		t.Fatalf("score %+v", s)
	}
	worse := TrialScore{Fixed: 1, Broke: 1}
	if !s.Better(worse) || worse.Better(s) {
		t.Fatal("broken service must lose")
	}
}

func TestInjectHostlist(t *testing.T) {
	in := []string{"--filter-tcp=443", `--hostlist=C:\z\lists\list-general.txt`, `--hostlist=C:\z\lists\list-general-user.txt`, "--new", `--hostlist=C:\z\lists\list-google.txt`}
	got := injectHostlist(in, `C:\z\lists\list-ezpzdpi.txt`)
	want := []string{"--filter-tcp=443", `--hostlist=C:\z\lists\list-general.txt`, `--hostlist=C:\z\lists\list-ezpzdpi.txt`, `--hostlist=C:\z\lists\list-general-user.txt`, "--new", `--hostlist=C:\z\lists\list-google.txt`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestGameFilterSubstitution(t *testing.T) {
	src := `start "" "%BIN%winws.exe" --wf-tcp=443,%GameFilterTCP% --filter-udp=%GameFilterUDP%`
	on, _ := parseFlowsealBat(src, "b", "l", gameFilterOn)
	off, _ := parseFlowsealBat(src, "b", "l", gameFilterOff)
	if on[0] != "--wf-tcp=443,1024-65535" || off[1] != "--filter-udp=12" {
		t.Fatalf("on %q off %q", on, off)
	}
}
