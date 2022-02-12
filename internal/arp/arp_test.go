package arp

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/matryer/is"
)

//go:embed testdata/arp
var testData []byte

func TestParse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		is := is.New(t)
		vs, err := ReadAll(bytes.NewReader(testData))
		is.NoErr(err)
		is.Equal(4, len(vs))
	})

	t.Run("not complete line", func(t *testing.T) {
		is := is.New(t)
		vs, err := ReadAll(bytes.NewReader([]byte(`first line will be ignored
192.168.4.145    0x1         0x2         38:c9:86:2c:2f:97     *
`)))
		is.Equal(err.Error(), "line contains less than 6 rows: '192.168.4.145    0x1         0x2         38:c9:86:2c:2f:97     *'")
		is.Equal(0, len(vs))
	})


}
