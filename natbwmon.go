package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-pa/flagutil"
	"github.com/peterbourgon/ff/v3"
	"github.com/some-programs/natbwmon/internal/log"
	"github.com/some-programs/natbwmon/internal/mon"
	"github.com/tomruk/oui"
)

//go:embed manuf
var manufTxt []byte

// Flags contains the top level program configuration.
type Flags struct {
	chain                    string
	LANIface                 string
	listen                   string
	clear                    bool
	avgSamples               int
	iptablesReadDuration     time.Duration
	iptablesRulesDuration    time.Duration
	arpDuration              time.Duration
	resolveHostnamesDuration time.Duration
	aliases                  flagutil.StringSliceFlag
	nmap                     bool
	log                      log.Flags
}

// Register registers the flags into a FlagSet.
func (flags *Flags) Register(fs *flag.FlagSet) {
	fs.BoolVar(&flags.clear, "clear", false, "just clear iptables rules and chains and exit")
	fs.StringVar(&flags.LANIface, "lan.if", "br0", "The 'LAN' interface")
	fs.StringVar(&flags.listen, "listen", "0.0.0.0:8833", "where web server listens")
	fs.StringVar(&flags.chain, "iptables.chain", "NATBW", "name of iptables chain to create")
	fs.IntVar(&flags.avgSamples, "avg.samples", 8, "number of samples to create bitrate averages from")
	fs.DurationVar(&flags.iptablesReadDuration, "iptables.read.delay", 400*time.Millisecond, "delay between reading counters from iptables rules")
	fs.DurationVar(&flags.iptablesRulesDuration, "iptables.rules.delay", 10*time.Second, "delay between updating ip tables rules and adding new new clients")
	fs.DurationVar(&flags.arpDuration, "arp.delay", 5*time.Second, "delay between rereading arp table to update client hardware addresses")
	fs.DurationVar(&flags.resolveHostnamesDuration, "dns.delay", time.Minute, "delay between reresolving host names.")
	fs.Var(&flags.aliases, "aliases", "hardware address aliases comma separated. ex: -aliases=00:00:00:00:00:00=nas.alias,00:00:00:00:00:01=server.alias")
	fs.BoolVar(&flags.nmap, "nmap", false, "enable nmap api")
	flags.log.Register(fs)
}

// Setup must be run after the flags are parsed.
func (flags *Flags) Setup(out io.Writer) error {
	if err := flags.log.Setup(); err != nil {
		fmt.Fprintln(out, err)
		return err
	}
	return nil
}

func main() {
	var flags Flags
	flags.Register(flag.CommandLine)
	ff.Parse(flag.CommandLine, os.Args[1:],
		ff.WithEnvVarPrefix("NATBWMON"),
	)

	if err := flags.Setup(os.Stderr); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	log.Debug().Msg("application starting")

	ctx, cancel := context.WithCancel(context.Background())

	go func(ctx context.Context) {
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		select {
		case <-ctx.Done():
			cancel()
		}
	}(ctx)

	hostAliases := make(map[string]string, 0)
	for _, v := range flags.aliases {
		ss := strings.SplitN(v, "=", 2)
		if len(ss) != 2 {
			fmt.Println("invalid alias specification:", v)
			os.Exit(1)
		}
		hostAliases[ss[0]] = ss[1]
	}

	ipt, err := mon.NewIPTables(flags.chain, flags.LANIface)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	if err := ipt.Delete(); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	if flags.clear {
		return
	}

	if err := ipt.ClearChain(); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	if err := ipt.Update(); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	ouiDB, err := oui.NewDB(manufTxt)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	clients := mon.NewClients(flags.avgSamples, hostAliases)

	go func(ctx context.Context) {
		ipt, err := mon.NewIPTables(flags.chain, flags.LANIface)
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
		ticker := time.NewTicker(flags.iptablesRulesDuration)
		for {
			select {
			case <-ticker.C:
				err := ipt.Update()
				if err != nil {
					log.Info().Err(err).Msg("")
				}
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		update := func() {
			arps, err := mon.Arps()
			if err != nil {
				log.Info().Err(err).Msg("")
				return
			}
			arps = arps.FilterDeviceName(flags.LANIface)
			if err := clients.UpdateArp(arps); err != nil {
				log.Info().Err(err).Msg("update arp failed")
			}
		}
		update()
		ticker := time.NewTicker(flags.arpDuration)
		for {
			select {
			case <-ticker.C:
				update()
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		ticker := time.NewTicker(flags.resolveHostnamesDuration)
	loop:
		for {
			select {
			case <-ticker.C:
				arps, err := mon.Arps()
				if err != nil {
					log.Info().Err(err).Msg("")
					continue loop
				}
				arps = arps.FilterDeviceName(flags.LANIface)
				names := make(map[string]string, len(arps))
				for _, v := range arps {
					name, err := mon.ResolveHostname(v.IPAddress)
					if err != nil {
						log.Info().Err(err).Msg("")
					}
					names[v.IPAddress] = name
				}
				if err := clients.UpdateNames(names); err != nil {
					log.Info().Err(err).Msg("update names failed")
				}

			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		ticker := time.NewTicker(flags.iptablesReadDuration)
	loop:
		for {
			select {
			case <-ticker.C:
				next, err := ipt.Stats()
				if err != nil {
					log.Info().Err(err).Msg("")
					continue loop
				}
				if err = clients.UpdateIPTables(next); err != nil {
					log.Info().Err(err).Msg("")
					continue loop
				}
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	mime.AddExtensionType(".woff", "font/woff")
	mime.AddExtensionType(".woff2", "font/woff2")

	serv := &Server{
		nmapEnabled: flags.nmap,
		ouiDB:       ouiDB,
		clients:     clients,
	}
	hs := &http.Server{
		Addr:           flags.listen,
		ReadTimeout:    10 * time.Minute,
		WriteTimeout:   10 * time.Minute,
		MaxHeaderBytes: 1 << 20,
		Handler:        serv.Routes(),
	}
	go func() {
		log.Fatal().Err(hs.ListenAndServe()).Msg("")
	}()

	<-ctx.Done()
	log.Info().Msg("shutting down...")
	if err := ipt.Delete(); err != nil {
		log.Fatal().Err(err).Msg("")
	}
}
