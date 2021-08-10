package main

import (
	"embed"

	"github.com/benbjohnson/hashfs"
	"github.com/some-programs/natbwmon/internal/mon"
)

// clientsTemplateData .
type clientsTemplateData struct {
	Title string
}

// conntrackTemplateData .
type conntrackTemplateData struct {
	Title       string
	FS          mon.FlowSlice
	IPFilter    string
	OrderFilter string
	NMAP        bool
	IP          string
}

//go:embed static
var StaticFS embed.FS

var StaticHashFS = hashfs.NewFS(StaticFS)

//go:embed template
var TemplateFS embed.FS
