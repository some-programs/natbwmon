package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-pa/fenv"
	"github.com/go-pa/flagutil"
	"github.com/thomasf/natbwmon/internal/mon"
)

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
}{}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

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

	fenv.CommandLinePrefix("NATBWMON_")
	fenv.MustParse()
	flag.Parse()

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

	clientsTempl, err := template.New("").Parse(clientsTpl)
	if err != nil {
		log.Fatal(err)
	}

	conntrackTempl, err := template.New("").Funcs(
		template.FuncMap{
			"ipclass": func(ip net.IP) string {
				if mon.IsPrivateIP(ip) {
					return "failed"
				}
				return "success"
			}},
	).Parse(conntrackTpl)
	if err != nil {
		log.Fatal(err)
	}

	ipt, err := mon.NewIPTables(flags.chain, flags.LANIface)
	if err != nil {
		log.Fatal(err)
	}

	if err := ipt.Delete(); err != nil {
		log.Fatal(err)
	}

	if flags.clear {
		return
	}

	if err := ipt.ClearChain(); err != nil {
		log.Fatal(err)
	}

	if err := ipt.Update(); err != nil {
		log.Fatal(err)
	}

	clients := mon.NewClients(flags.avgSamples)

	// go pinger()

	go func(ctx context.Context) {
		ipt, err := mon.NewIPTables(flags.chain, flags.LANIface)
		if err != nil {
			log.Fatal(err)
		}
		ticker := time.NewTicker(flags.iptablesRulesDuration)
		for {
			select {
			case <-ticker.C:
				err := ipt.Update()
				if err != nil {
					log.Println(err)
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
				log.Println(err)
				return
			}
			arps = arps.FilterDeviceName(flags.LANIface)
			clients.UpdateArp(arps)
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
					log.Println(err)
					continue loop
				}
				arps = arps.FilterDeviceName(flags.LANIface)
				names := make(map[string]string, len(arps))
				for _, v := range arps {
					name, err := mon.ResolveHostname(v.IPAddress)
					if err != nil {
						log.Println(err)
					}
					names[v.IPAddress] = name
				}
				clients.UpdateNames(names)

			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	orderStats := func(s mon.Stats, r *http.Request) {
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
		}
	}

	includeFilter := func(ss mon.Stats, r *http.Request) mon.Stats {
		q := r.URL.Query()
		IPs := q["ip"]
		HWAddrs := q["hwaddr"]
		names := q["name"]

		if len(IPs) == 0 && len(HWAddrs) == 0 && len(names) == 0 {
			return ss
		}
		var res mon.Stats
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
		c := clients.Stats()
		orderStats(c, r)
		d := clientsTemplateData{
			Hosts: c,
		}
		err := clientsTempl.Execute(w, &d)
		if err != nil {
			log.Println(err)
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
			case "proto":
				fs.OrderByState()
				fs.OrderByProtoName()
			case "ttl":
				fs.OrderByTTL()
			case "state":
				fs.OrderByTTL()
				fs.OrderByProtoName()
				fs.OrderByState()
			case "orig_src":
				fs.OrderByState()
				fs.OrderByOriginalSPort()
				fs.OrderByOriginalSource()
			case "orig_dst":
				fs.OrderByState()
				fs.OrderByOriginalDPort()
				fs.OrderByOriginalDestination()
			case "reply_src":
				fs.OrderByState()
				fs.OrderByReplySPort()
				fs.OrderByReplySource()
			case "reply_dst":
				fs.OrderByState()
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
			log.Println(err)
			w.WriteHeader(500)
			return
		}
		fs = filterConntrack(fs, r)
		orderConntrack(fs, r)

		data := conntrackTemplateData{
			FS:          fs,
			Title:       "conntrack",
			IPFilter:    r.URL.Query().Get("ip"),
			OrderFilter: r.URL.Query().Get("o"),
		}
		err = conntrackTempl.Execute(w, &data)
		if err != nil {
			log.Println(err)
		}
	})

	http.HandleFunc("/v1/stats/", func(w http.ResponseWriter, r *http.Request) {
		c := clients.Stats()
		orderStats(c, r)
		c = includeFilter(c, r)
		data, err := json.Marshal(&c)
		if err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(data)
	})

	hs := &http.Server{
		Addr:           flags.listen,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		log.Fatal(hs.ListenAndServe())
	}()

	go func(ctx context.Context) {

		ticker := time.NewTicker(flags.iptablesReadDuration)
	loop:
		for {
			select {
			case <-ticker.C:
				next, err := ipt.Stats()
				if err != nil {
					log.Println(err)
					continue loop
				}
				if err = clients.UpdateIPTables(next); err != nil {
					log.Println(err)
					continue loop
				}
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	<-ctx.Done()
	log.Println("shutting down...")
	if err := ipt.Delete(); err != nil {
		log.Fatal(err)
	}

}
