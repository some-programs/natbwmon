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
		is.Equal(3, len(vs))
		is.Equal(1, len(vs.FilterDeviceName("br0")))
		is.Equal(2, len(vs.FilterDeviceName("enp0s31f6")))

		ipmap := vs.HWAddrByIP()
		is.Equal(3, len(ipmap))
		is.True(func() bool { _, ok := ipmap["192.168.4.145"]; return ok }())
		is.True(func() bool { _, ok := ipmap["10.0.0.1"]; return !ok }())

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
