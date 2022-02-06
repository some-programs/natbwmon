package assets

import (
	"embed"

	"github.com/benbjohnson/hashfs"
)

//go:embed static
var StaticFS embed.FS

var StaticHashFS = hashfs.NewFS(StaticFS)

//go:embed template
var TemplateFS embed.FS

//go:embed manuf
var ManufTxt []byte
