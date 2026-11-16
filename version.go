package main

const (
	appName     = "EzPzDPI"
	serviceName = "EzPzDPI"
	repoURL     = "https://github.com/semanticparadox/EzPzDPI"
)

// version is set at build time: -ldflags "-X main.version=..."
var version = "dev"

// controlTarget is a Russian site that is never blocked: if it fails, the
// problem is the internet connection itself, not DPI.
var controlTarget = Target{Service: "Интернет", Host: "ya.ru", Path: "/", MinBytes: 0}
