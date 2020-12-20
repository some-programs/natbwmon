package main

import (
	"embed"

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
}

//go:embed static
var StaticFS embed.FS

//go:embed template
var TemplateFS embed.FS
