package main

import "strings"

// Service is one thing people want back (a site, an app, a game platform).
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"` // video, social, messenger, games, ai, web
	Targets  []Target `json:"-"`
	// Domains are added to the bypass host list (beyond Flowseal's lists).
	Domains []string `json:"-"`
	// Known is a fact users should see even when the web check passes,
	// e.g. "calls are blocked" for a messenger whose calls we cannot test.
	Known string `json:"-"`
	// GeoSigns are lowercase body fragments that mean the service itself
	// refuses Russian users (not a network block).
	GeoSigns []string `json:"-"`
	// Advice explains what to do when the bypass cannot help.
	Advice string `json:"-"`
	// Note is extra context shown in the details, without changing state.
	Note string `json:"-"`
	// Default services are checked unless the user turns them off.
	Default bool `json:"-"`
	// NoBypass: Flowseal deliberately excludes this service from the bypass;
	// EzPzDPI only checks it and adds no domains.
	NoBypass bool `json:"-"`
	// ProviderGeo: the service itself refuses Russian users, so a working
	// network path still means "does not work from Russia".
	ProviderGeo bool `json:"-"`
	// GeoCodes are HTTP statuses that mean a provider geo-block for this
	// service (e.g. Docker answers 403 instead of its normal 401).
	GeoCodes []int `json:"-"`
	// AnyOK: the service works when any one target works (e.g. DNS providers).
	AnyOK bool `json:"-"`
	// Special marks services checked by custom code ("voice").
	Special string `json:"-"`
}

// catalog is filled in catalog_data.go.
func catalogByID() map[string]*Service {
	m := map[string]*Service{}
	for i := range catalog {
		m[catalog[i].ID] = &catalog[i]
	}
	return m
}

// allTargets lists every target of the given services (all when ids is nil),
// with Target.Service set to the service id.
func allTargets(ids map[string]bool) []Target {
	var out []Target
	for _, s := range catalog {
		if ids != nil && !ids[s.ID] {
			continue
		}
		for _, t := range s.Targets {
			t.Service = s.ID
			out = append(out, t)
		}
	}
	return out
}

// extraDomains returns the host list EzPzDPI adds for the given services.
func extraDomains(ids map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range catalog {
		if (ids != nil && !ids[s.ID]) || s.NoBypass {
			continue
		}
		for _, d := range s.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d != "" && !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}
