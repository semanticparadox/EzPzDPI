package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// SvcState is what the UI shows for one service.
type SvcState string

const (
	StUnknown   SvcState = "unknown"
	StTesting   SvcState = "testing"
	StWorks     SvcState = "works"
	StBlocked   SvcState = "blocked"   // name-based DPI block: the bypass can fix it
	StThrottled SvcState = "throttled" // slowed down or frozen after a few KB: the bypass can fix it
	StFixed     SvcState = "fixed"     // works only with the bypass
	StIPBlock   SvcState = "ip_block"  // the address itself is unreachable: needs a VPN
	StGeo       SvcState = "geo"       // the service refuses Russian users
	StDNS       SvcState = "dns"       // the ISP's DNS returns a fake address
	StPartial   SvcState = "partial"   // main part works, something secondary does not
	StOffline   SvcState = "offline"
)

// Fixable reports whether the DPI bypass can be expected to help.
func (s SvcState) Fixable() bool { return s == StBlocked || s == StThrottled }

// Broken reports whether the service does not work for the user.
func (s SvcState) Broken() bool {
	switch s {
	case StBlocked, StThrottled, StIPBlock, StGeo, StDNS, StOffline:
		return true
	}
	return false
}

// Diagnosis is the verdict for one service.
type Diagnosis struct {
	ID     string   `json:"id"`
	State  SvcState `json:"state"`
	Detail string   `json:"detail"`
	// Reachable: every required probe got through at the network level
	// (the service may still refuse Russia or need secure DNS).
	Reachable bool `json:"-"`
}

// probe classes
const (
	pcOK       = "ok"
	pcGeo      = "geo"
	pcDNS      = "dns"
	pcIP       = "ip"
	pcName     = "name"
	pcThrottle = "throttle"
)

func isGeo(svc *Service, p ProbeResult) bool {
	if p.Status == 451 {
		return true
	}
	for _, c := range svc.GeoCodes {
		if p.Status == c {
			return true
		}
	}
	if len(svc.GeoSigns) == 0 || len(p.Head) == 0 {
		return false
	}
	body := bytes.ToLower(p.Head)
	for _, sig := range svc.GeoSigns {
		if bytes.Contains(body, []byte(sig)) {
			return true
		}
	}
	return false
}

func classifyProbe(svc *Service, p ProbeResult, linkSlow bool) string {
	if p.Status > 0 && isGeo(svc, p) {
		return pcGeo
	}
	if p.OK && p.Slow && !linkSlow {
		return pcThrottle // this site is slow while Russian sites are fast
	}
	if p.OK {
		return pcOK
	}
	switch {
	case p.Stage == StageDNS, p.CertErr:
		return pcDNS
	case p.Stage == StageTCP:
		return pcIP
	case p.Stage == StageTLS && p.Neutral == NeutralSilent:
		return pcIP
	case p.Stage == StageData:
		return pcThrottle
	default: // TLS hang/reset with a live server, or HTTP-level interference
		return pcName
	}
}

const (
	msgGeo      = "Сеть открыта, но сервис сам не работает с Россией. Обход этого не меняет."
	msgDNSOnly  = "Сайт доступен, но DNS провайдера не отдаёт его адрес: сервис удалён из российского DNS. Включите защищённый DNS."
	msgDNSAlso  = " Кроме того, DNS провайдера не отдаёт адрес сайта: понадобится защищённый DNS."
	msgName     = ". Блокировка по имени сайта: обход должен помочь."
	msgThrottle = ". Замедление: обход должен помочь."
	msgStub     = ". Провайдер подменяет адрес сайта: включите защищённый DNS."
	msgIP       = ". Адрес недоступен целиком: обход вряд ли поможет, скорее нужен VPN."
)

// Diagnose turns probe results into one verdict per service.
func Diagnose(svc *Service, r Report) Diagnosis {
	d := Diagnosis{ID: svc.ID, State: StWorks}
	var reqFail, optFail []ProbeResult
	classes := map[string]int{}
	required, okCount, geo := 0, 0, 0
	dnsSpoof := false
	for _, p := range r.Results {
		if p.Service != svc.ID {
			continue
		}
		if p.DNSSpoofed {
			dnsSpoof = true
		}
		c := classifyProbe(svc, p, r.LinkSlow())
		if !p.Optional {
			required++
		}
		switch {
		case c == pcGeo:
			geo++
		case c == pcOK:
			if !p.Optional {
				okCount++
			}
		case p.Optional:
			optFail = append(optFail, p)
		default:
			classes[c]++
			reqFail = append(reqFail, p)
		}
	}
	if svc.AnyOK && okCount > 0 && len(reqFail) > 0 {
		optFail, reqFail, classes = append(optFail, reqFail...), nil, map[string]int{}
	}
	d.Reachable = required > 0 && len(reqFail) == 0
	switch {
	case required == 0:
		d.State = StUnknown
	case geo > 0:
		d.State, d.Detail = StGeo, msgGeo
	case len(reqFail) == 0 && svc.ProviderGeo:
		d.State, d.Detail = StGeo, msgGeo
	case len(reqFail) == 0 && dnsSpoof:
		d.State, d.Detail = StDNS, msgDNSOnly
	case len(reqFail) == 0 && len(optFail) == 0:
		d.State = StWorks
	case len(reqFail) == 0:
		d.State, d.Detail = StPartial, failLine(optFail)+"."
	case classes[pcName] > 0:
		d.State, d.Detail = StBlocked, failLine(reqFail)+msgName
	case classes[pcThrottle] > 0:
		d.State, d.Detail = StThrottled, failLine(reqFail)+msgThrottle
		for _, p := range reqFail {
			if p.OK && p.Slow {
				d.Detail = joinSentences(d.Detail, fmt.Sprintf("%s скачивается очень медленно (%d КБ за %d с), а российские сайты быстро.", p.Host, p.Bytes>>10, int(p.Took.Seconds())))
			}
		}
	case classes[pcDNS] > 0 && classes[pcIP] == 0:
		d.State, d.Detail = StDNS, failLine(reqFail)+msgStub
	default:
		d.State, d.Detail = StIPBlock, failLine(reqFail)+msgIP
	}
	if dnsSpoof && (d.State == StBlocked || d.State == StThrottled || d.State == StIPBlock) {
		d.Detail += msgDNSAlso
	}
	if pl := partsLine(svc, r); pl != "" && d.State != StWorks && d.State != StGeo {
		d.Detail = joinSentences(pl, d.Detail)
	}
	if svc.Known != "" && (d.State == StWorks || d.State == StPartial) {
		d.State = StPartial
		d.Detail = joinSentences(d.Detail, svc.Known)
	}
	if svc.Advice != "" && (d.State == StIPBlock || d.State == StGeo) {
		d.Detail = joinSentences(d.Detail, svc.Advice)
	}
	if svc.Note != "" {
		d.Detail = joinSentences(d.Detail, svc.Note)
	}
	return d
}

func joinSentences(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " " + b
}

func failLine(ps []ProbeResult) string {
	var parts []string
	for i, p := range ps {
		if i == 2 {
			parts = append(parts, fmt.Sprintf("и ещё %d", len(ps)-2))
			break
		}
		what := p.Host
		if p.Label != "" {
			what = p.Label + " (" + p.Host + ")"
		}
		msg := p.Err
		if msg == "" && p.Slow {
			msg = "очень медленно"
		}
		parts = append(parts, what+": "+msg)
	}
	return strings.Join(parts, "; ")
}

// partsLine names working and broken parts: "Сайт открывается, видео — нет."
func partsLine(svc *Service, r Report) string {
	var ok, bad []string
	seen := map[string]bool{}
	for _, p := range r.Results {
		if p.Service != svc.ID || p.Label == "" || seen[p.Label] {
			continue
		}
		seen[p.Label] = true
		if p.OK {
			ok = append(ok, p.Label)
		} else {
			bad = append(bad, p.Label)
		}
	}
	if len(ok) == 0 || len(bad) == 0 {
		return ""
	}
	return upperFirst(strings.Join(ok, ", ")) + " открывается, " + strings.Join(bad, ", ") + " — нет."
}

func upperFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

// TrialScore rates a strategy against the services that need fixing and
// those that already worked (which it must not break).
type TrialScore struct {
	Fixed    int
	Broke    int
	Latency  time.Duration
	Services map[string]bool // service id -> works with this strategy
}

func ScoreTrial(r Report, want, keep []string) TrialScore {
	s := TrialScore{Services: map[string]bool{}, Latency: r.Latency()}
	for _, id := range want {
		ok := r.ServiceOK(id)
		s.Services[id] = ok
		if ok {
			s.Fixed++
		}
	}
	for _, id := range keep {
		ok := r.ServiceOK(id)
		s.Services[id] = ok
		if !ok {
			s.Broke++
		}
	}
	return s
}

// Better orders trial scores: more fixed, fewer broken, then faster.
func (s TrialScore) Better(o TrialScore) bool {
	if s.Fixed != o.Fixed {
		return s.Fixed > o.Fixed
	}
	if s.Broke != o.Broke {
		return s.Broke < o.Broke
	}
	return s.Latency < o.Latency
}
