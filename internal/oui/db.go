// Package oui provides functions to work with MAC and OUI's
package oui

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const ouiReStr = `^(\S+)\s*\t+(\S+)(\s+#\s+(\S.*))?`

var ErrInvalidMACAddress = errors.New("invalid MAC address")

// Helper functions

func macToUint64(address [6]byte) uint64 {
	var a uint64
	for _, x := range address {
		a <<= 8
		a |= uint64(x)
	}
	return a
}

func maskToUint64(mask uint8) uint64 {
	return ^(uint64(1)<<(48-mask) - 1)
}

func parseMAC(s string) ([6]byte, error) {
	var hw [6]byte

	var oct []string
	if strings.IndexByte(s, ':') < 0 {
		oct = strings.Split(s, "-")
	} else {
		oct = strings.Split(s, ":")
	}

	for i, x := range oct {
		h, err := strconv.ParseUint(x, 16, 8)
		if err != nil {
			return hw, err
		}
		hw[i] = uint8(h)
	}

	return hw, nil
}

type addressBlock interface {
	Uint64OUI() uint64
	Uint64Mask() uint64
	Organization() string
}

// oui, mask, organization
type addressBlock24 struct {
	oui          [3]byte
	mask         byte
	organization [8]byte
}

func (a *addressBlock24) Uint64OUI() uint64 {
	return uint64(a.oui[0])<<40 | uint64(a.oui[1])<<32 | uint64(a.oui[2])<<24
}

func (a *addressBlock24) Uint64Mask() uint64 {
	return ^(uint64(1)<<24 - 1)
}

func (a *addressBlock24) Organization() string {
	return strings.TrimSpace(string(a.organization[:]))
}

type addressBlocks24 []addressBlock24

func (bs addressBlocks24) Len() int {
	return len(bs)
}

func (bs addressBlocks24) Less(i, j int) bool {
	return bs[i].Uint64OUI() < bs[j].Uint64OUI()
}

func (bs addressBlocks24) Swap(i, j int) {
	bs[i], bs[j] = bs[j], bs[i]
}

func (bs addressBlocks24) Search(addr uint64, i, j int) addressBlock {

	k := (i + j) / 2
	o := bs[k].Uint64OUI()
	m := bs[k].Uint64Mask()

	if addr&m == o {
		return addressBlock(&bs[k])
	}

	if i == j {
		return nil
	}

	if addr&m < o {
		return bs.Search(addr, i, k)
	} else {
		return bs.Search(addr, k+1, j)
	}
}

type addressBlock48 struct {
	oui          [6]byte
	mask         byte
	organization [8]byte
}

func (a *addressBlock48) Uint64OUI() uint64 {
	return macToUint64(a.oui)
}

func (a *addressBlock48) Uint64Mask() uint64 {
	return maskToUint64(a.mask)
}

func (a *addressBlock48) Organization() string {
	return strings.TrimSpace(string(a.organization[:]))
}

type addressBlocks48 []addressBlock48

func (bs addressBlocks48) Len() int {
	return len(bs)
}

func (bs addressBlocks48) Less(i, j int) bool {
	return bs[i].Uint64OUI() < bs[j].Uint64OUI()
}

func (bs addressBlocks48) Swap(i, j int) {
	bs[i], bs[j] = bs[j], bs[i]
}

func (bs addressBlocks48) Search(addr uint64, i, j int) addressBlock {

	k := (i + j) / 2
	o := bs[k].Uint64OUI()
	m := bs[k].Uint64Mask()

	if addr&m == o {
		return addressBlock(&bs[k])
	}

	if i == j {
		return nil
	}

	if addr&m < o {
		return bs.Search(addr, i, k)
	} else {
		return bs.Search(addr, k+1, j)
	}
}

type DB struct {
	blocks24 addressBlocks24
	blocks48 addressBlocks48
}

func (db *DB) load(file io.Reader) (err error) {
	fieldsRe := regexp.MustCompile(ouiReStr)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" || text[0] == '#' || text[0] == '\t' {
			continue
		}

		// Skip token ring entries
		if strings.Contains(text, "[TR?]") {
			continue
		}

		// Split input text into address and organization name
		fields := fieldsRe.FindAllStringSubmatch(text, -1)
		// incorrectly formated database might not create fields, which would prevent the line from being parsed
		if fields == nil {
			continue
		}
		addr := fields[0][1]
		org := fields[0][2] + "        "

		switch org[:8] {
		case "IeeeRegi", "Spanning":
			continue
		}

		var oui [6]byte
		var mask int

		if i := strings.IndexByte(addr, '/'); i < 0 {
			if oui, err = parseMAC(addr); err != nil {
				continue
			}
			mask = (len(addr) + 1) / 3 * 8
		} else {
			if oui, err = parseMAC(addr[:i]); err != nil {
				continue
			}
			if mask, err = strconv.Atoi(addr[i+1:]); err != nil {
				continue
			}
		}

		var orgbytes [8]byte
		copy(orgbytes[:], org)

		if mask > 24 {
			block := addressBlock48{oui, uint8(mask), orgbytes}
			db.blocks48 = append(db.blocks48, block)
		} else {
			var o [3]byte
			o[0] = oui[0]
			o[1] = oui[1]
			o[2] = oui[2]
			block := addressBlock24{o, uint8(mask), orgbytes}
			db.blocks24 = append(db.blocks24, block)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(db.blocks48) == 0 && len(db.blocks24) == 0 {
		return fmt.Errorf("database is empty")
	}

	return nil
}

// New returns a new OUI database loaded from the data.
func NewDB(data []byte) (*DB, error) {
	buf := bytes.NewBuffer(data)
	return newDBFromReader(buf)
}

// NewFromReader returns a new OUI database loaded from the reader.
func NewDBFromReader(r io.Reader) (*DB, error) {
	return newDBFromReader(r)
}

func newDBFromReader(r io.Reader) (*DB, error) {
	db := new(DB)
	if err := db.load(r); err != nil {
		return nil, err
	}

	sort.Sort(db.blocks48)
	sort.Sort(db.blocks24)

	return db, nil
}

// NewFromFile returns a new OUI database loaded from the specified file.
func NewDBFromFile(path string) (*DB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return newDBFromReader(file)
}

func (db *DB) blockLookup(address [6]byte) addressBlock {
	a := macToUint64(address)

	if b := db.blocks48.Search(a, 0, len(db.blocks48)-1); b != nil {
		return b
	}

	return db.blocks24.Search(a, 0, len(db.blocks24)-1)
}

// Lookup obtains the vendor organization name from the MAC address s.
func (db *DB) Lookup(s string) (string, error) {
	addr, err := parseMAC(s)
	if err != nil {
		return "", err
	}
	block := db.blockLookup(addr)
	if block == nil {
		return "", nil
	}
	return block.Organization(), nil
}
