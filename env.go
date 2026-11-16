package main

// Shared types for environment findings. Detection lives in
// detect_windows.go; the controller renders findings as notices.

// Finding is one thing on this PC that affects the bypass or the check.
type Finding struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`  // dpi, engines, vpn, proxy, hosts, av, own, platform, system, discord, game
	Level  string   `json:"level"` // error, warn, info
	Title  string   `json:"title"`
	Text   string   `json:"text"`
	Active bool     `json:"active"` // affects traffic or the check right now
	Acts   []Action `json:"actions,omitempty"`

	// Internal data the actions need (not sent to the page).
	Services  []string          `json:"-"` // Windows service names
	Procs     []ProcRef         `json:"-"`
	Tasks     []string          `json:"-"` // scheduled task paths
	Shortcuts []string          `json:"-"` // autostart .lnk/.bat paths
	Hosts     []string          `json:"-"` // hosts-file lines
	Data      map[string]string `json:"-"`
}

// Action is a button on a notice. Confirm, when set, is asked first.
type Action struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Confirm string `json:"confirm,omitempty"`
}

// ProcRef identifies a running process by PID and verified image path.
type ProcRef struct {
	PID        uint32
	Name       string
	Path       string
	ParentName string
	Manager    bool // a GUI/watchdog that respawns an engine: stop it first
}

// Env is the result of scanning the PC.
type Env struct {
	Findings []Finding
}

// ForeignActive lists findings of other bypass tools that are running now.
func (e Env) ForeignActive() []Finding {
	var out []Finding
	for _, f := range e.Findings {
		if f.Kind == "dpi" && f.Active {
			out = append(out, f)
		}
	}
	return out
}

// Foreign lists every finding about another bypass tool, running or not.
func (e Env) Foreign() []Finding {
	var out []Finding
	for _, f := range e.Findings {
		if f.Kind == "dpi" {
			out = append(out, f)
		}
	}
	return out
}

func (e Env) Find(id string) (Finding, bool) {
	for _, f := range e.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// Has reports whether a finding of the given kind is active.
func (e Env) Has(kind string) bool {
	for _, f := range e.Findings {
		if f.Kind == kind && f.Active {
			return true
		}
	}
	return false
}
