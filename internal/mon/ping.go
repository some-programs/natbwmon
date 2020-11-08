package mon

import (
	"net"
	"sync"
	"time"

	ping "github.com/digineo/go-ping"
	"github.com/some-programs/natbwmon/internal/log"
)

var (
	pings   []time.Duration
	pingsMu sync.Mutex
)

func Pinger() {

	p, err := ping.New("0.0.0.0", "")
	if err != nil {
		panic(err)
	}
	for {
		d, err := p.Ping(&net.IPAddr{IP: net.ParseIP("1.1.1.1")}, time.Second)
		if err != nil {
			log.Warn().Err(err).Msg("ping error")
		} else {
			log.Info().Stringer("duration", d).Msg("ping reply")
		}

		time.Sleep(2 * time.Second)
	}

}
