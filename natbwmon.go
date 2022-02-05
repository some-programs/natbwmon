package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/benbjohnson/hashfs"
	"github.com/go-pa/fenv"
	"github.com/go-pa/flagutil"
	"github.com/some-programs/natbwmon/internal/clientstats"
	"github.com/some-programs/natbwmon/internal/log"
	"github.com/some-programs/natbwmon/internal/mon"
	"github.com/tomruk/oui"
)

//go:embed manuf
var manufTxt []byte

// all command line flags, global state for now
var flags = struct {
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
}{}

func main() {
	var logFlags log.Flags

	logFlags.Register(flag.CommandLine)
	flag.BoolVar(&flags.clear, "clear", false, "just clear iptables rules and chains and exit")
	flag.StringVar(&flags.LANIface, "lan.if", "br0", "The 'LAN' interface")
	flag.StringVar(&flags.listen, "listen", "0.0.0.0:8833", "where web server listens")
	flag.StringVar(&flags.chain, "iptables.chain", "NATBW", "name of iptables chain to create")
	flag.IntVar(&flags.avgSamples, "avg.samples", 8, "number of samples to create bitrate averages from")
	flag.DurationVar(&flags.iptablesReadDuration, "iptables.read.delay", 400*time.Millisecond, "delay between reading counters from iptables rules")
	flag.DurationVar(&flags.iptablesRulesDuration, "iptables.rules.delay", 10*time.Second, "delay between updating ip tables rules and adding new new clients")
	flag.DurationVar(&flags.arpDuration, "arp.delay", 5*time.Second, "delay between rereading arp table to update client hardware addresses")
	flag.DurationVar(&flags.resolveHostnamesDuration, "dns.delay", time.Minute, "delay between reresolving host names.")
	flag.Var(&flags.aliases, "aliases", "hardware address aliases comma separated. ex: -aliases=00:00:00:00:00:00=nas.alias,00:00:00:00:00:01=server.alias")
	flag.BoolVar(&flags.nmap, "nmap", false, "enable nmap api")

	fenv.CommandLinePrefix("NATBWMON_")
	fenv.MustParse()
	flag.Parse()

	if err := logFlags.Setup(); err != nil {
		panic(err)
	}

	log.Debug().Msg("application starting")

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(c)

		select {
		case <-ctx.Done():
		case <-c:
			cancel()
		}
	}()

	for _, v := range flags.aliases {
		ss := strings.SplitN(v, "=", 2)
		if len(ss) != 2 {
			fmt.Println("invalid alias specification:", v)
			os.Exit(1)
		}
		mon.AliasesMap[ss[0]] = ss[1]
	}

	clientsTempl, err := template.New("base.html").Funcs(
		template.FuncMap{
			"static": StaticHashFS.HashName,
		},
	).ParseFS(TemplateFS, "template/base.html", "template/clients.html")
	if err != nil {
		log.Fatal().Err(err).Msg("parse templates")
	}

	conntrackTempl, err := template.New("base.html").Funcs(
		template.FuncMap{
			"static": StaticHashFS.HashName,
			"ipclass": func(ip net.IP) string {
				if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return "blue"
				}
				if ip.IsPrivate() {
					return "failed"
				}
				return "success"
			},
		},
	).ParseFS(TemplateFS, "template/base.html", "template/conntrack.html")
	if err != nil {
		log.Fatal().Err(err).Msg("")
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

	clients := mon.NewClients(flags.avgSamples)

	// go pinger()

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

	orderStats := func(s clientstats.Stats, r *http.Request) {
		s.OrderByIP()
		orderBy := r.URL.Query().Get("order_by")
		switch orderBy {
		case "rate_in":
			s.OrderByInRate()
		case "rate_out":
			s.OrderByOutRate()
		case "hwaddr":
			s.OrderByHWAddr()
		case "name":
			s.OrderByName()
		case "manufacturer":
			s.OrderByHWAddr()
			s.OrderByManufacturer()
		}
	}

	includeFilter := func(ss clientstats.Stats, r *http.Request) clientstats.Stats {
		q := r.URL.Query()
		IPs := q["ip"]
		HWAddrs := q["hwaddr"]
		names := q["name"]

		if len(IPs) == 0 && len(HWAddrs) == 0 && len(names) == 0 {
			return ss
		}
		var res clientstats.Stats
	loop:
		for _, s := range ss {
			for _, v := range IPs {
				if s.IP == v {
					res = append(res, s)
					continue loop
				}
			}
			for _, v := range names {
				if s.Name == v {
					res = append(res, s)
					continue loop
				}
			}
			for _, v := range HWAddrs {
				if s.HWAddr == v {
					res = append(res, s)
					continue loop
				}
			}
		}
		return res
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		d := clientsTemplateData{}
		err := clientsTempl.Execute(w, &d)
		if err != nil {
			log.Info().Err(err).Msg("")
		}
	})

	filterConntrack := func(fs mon.FlowSlice, r *http.Request) mon.FlowSlice {
		q := r.URL.Query()
		ip := q.Get("ip")
		if ip != "" {
			ip := net.ParseIP(ip)
			fs = fs.FilterByIP(ip)
		}
		return fs
	}

	orderConntrack := func(fs mon.FlowSlice, r *http.Request) {
		q := r.URL.Query()
		ords := q["o"]
		for i := len(ords) - 1; i >= 0; i-- {
			orderBy := ords[i]
			switch orderBy {
			case "ttl":
				fs.OrderByTTL()
			case "orig_src":
				fs.OrderByOriginalSPort()
				fs.OrderByOriginalSource()
			case "orig_dst":
				fs.OrderByOriginalDPort()
				fs.OrderByOriginalDestination()
			case "reply_src":
				fs.OrderByReplySPort()
				fs.OrderByReplySource()
			case "reply_dst":
				fs.OrderByReplyDPort()
				fs.OrderByReplyDestination()
			}
		}
	}

	var conntrackMu sync.Mutex // limit to avoid abuse
	http.HandleFunc("/conntrack", func(w http.ResponseWriter, r *http.Request) {
		conntrackMu.Lock()
		defer conntrackMu.Unlock()
		fs, err := mon.Flows()
		if err != nil {
			log.Info().Err(err).Msg("")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		fs = filterConntrack(fs, r)
		orderConntrack(fs, r)

		data := conntrackTemplateData{
			NMAP:        flags.nmap,
			IP:          r.URL.Query().Get("ip"),
			FS:          fs,
			Title:       "conntrack",
			IPFilter:    r.URL.Query().Get("ip"),
			OrderFilter: r.URL.Query().Get("o"),
		}
		err = conntrackTempl.Execute(w, &data)
		if err != nil {
			log.Info().Err(err).Msg("render conntrack")
		}
	})

	http.HandleFunc("/v1/stats/", func(w http.ResponseWriter, r *http.Request) {
		c := clients.Stats()
		c = includeFilter(c, r)
		var res clientstats.Stats
		for _, stat := range c {
			v, err := ouiDB.Lookup(stat.HWAddr)
			if err != nil {
				log.Error().Err(err).Msg("lookup error")
			} else {
				stat.Manufacturer = v
			}
			if stat.Manufacturer == "" {
				hwa, err := net.ParseMAC(stat.HWAddr)
				if err != nil {
					log.Error().Err(err).Msg("error parsing hardware addr")
				} else {
					switch {
					case (hwa[0] & 1) > 0:
						stat.Manufacturer = "{multicast}"
					case (hwa[0] & 2) > 0:
						stat.Manufacturer = "{local/random}"
					}
				}
			}
			res = append(res, stat)
		}
		orderStats(res, r)
		data, err := json.Marshal(&res)
		if err != nil {
			log.Info().Err(err).Msg("")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	if flags.nmap {
		// experimental v0 api, subject to change
		http.HandleFunc("/v0/nmap/", func(w http.ResponseWriter, r *http.Request) {
			ipStr := r.URL.Query().Get("ip")
			ip := net.ParseIP(ipStr)
			if ip == nil {
				log.Info().Str("ip", ipStr).Msg("could not parse ip argument")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")

			ctx := r.Context()
			cmd := exec.CommandContext(ctx, "nmap", "-v", "-A", "-T4", ip.String())
			w.Write([]byte(fmt.Sprintf("running: %s\n", strings.Join(cmd.Args, " "))))
			cmd.Stdout = w
			cmd.Stderr = w
			err := cmd.Run()
			if err != nil {
				log.Error().Err(err).Str("ip", ipStr).Msg("nmap failed")
				return
			}
			w.Write([]byte("\n nmap successful exit"))

		})
	}

	mime.AddExtensionType(".woff", "font/woff")
	mime.AddExtensionType(".woff2", "font/woff2")
	http.Handle("/static/", hashfs.FileServer(StaticHashFS))

	hs := &http.Server{
		Addr:           flags.listen,
		ReadTimeout:    10 * time.Minute,
		WriteTimeout:   10 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		log.Fatal().Err(hs.ListenAndServe()).Msg("")
	}()

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

	<-ctx.Done()
	log.Info().Msg("shutting down...")
	if err := ipt.Delete(); err != nil {
		log.Fatal().Err(err).Msg("")
	}
}
