package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-pa/flagutil"
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

var aliasesMap map[string]string

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
	flag.Parse()

	aliasesMap = make(map[string]string, len(flags.aliases))
	for _, v := range flags.aliases {
		ss := strings.SplitN(v, "=", 2)
		if len(ss) != 2 {
			fmt.Println("invalid alias specification:", v)
			os.Exit(1)
		}
		aliasesMap[ss[0]] = ss[1]
	}

	clientsTempl, err := template.New("").Parse(clientsTpl)
	if err != nil {
		log.Fatal(err)
	}

	conntrackTempl, err := template.New("").Funcs(
		template.FuncMap{
			"ipclass": func(ip net.IP) string {
				if isPrivateIP(ip) {
					return "failed"
				}
				return "success"
			}},
	).Parse(conntrackTpl)
	if err != nil {
		log.Fatal(err)
	}

	ipt, err := NewIPTables()
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

	clients := NewClients()

	// go pinger()

	go func() {
		ipt, err := NewIPTables()
		if err != nil {
			log.Fatal(err)
		}
		for {
			time.Sleep(flags.iptablesRulesDuration)
			err := ipt.Update()
			if err != nil {
				log.Println(err)
			}
		}
	}()

	go func() {
		for {
			arps, err := arps()
			if err != nil {
				log.Println(err)
				time.Sleep(flags.arpDuration)
				continue
			}
			clients.UpdateArp(arps)
			time.Sleep(flags.arpDuration)
		}
	}()

	go func() {
	loop:
		for {
			arps, err := arps()
			if err != nil {
				log.Println(err)
				time.Sleep(flags.resolveHostnamesDuration)
				continue loop
			}
			names := make(map[string]string, len(arps))
			for _, v := range arps {
				name, err := resolveHostname(v.IPAddress)
				if err != nil {
					log.Println(err)
				}
				names[v.IPAddress] = name
			}
			clients.UpdateNames(names)
			time.Sleep(flags.resolveHostnamesDuration)
		}
	}()

	orderStats := func(s Stats, r *http.Request) {
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

	includeFilter := func(ss Stats, r *http.Request) Stats {
		q := r.URL.Query()
		IPs := q["ip"]
		HWAddrs := q["hwaddr"]
		names := q["name"]

		if len(IPs) == 0 && len(HWAddrs) == 0 && len(names) == 0 {
			return ss
		}
		var res Stats
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

	filterConntrack := func(fs FlowSlice, r *http.Request) FlowSlice {
		q := r.URL.Query()
		ip := q.Get("ip")
		if ip != "" {
			ip := net.ParseIP(ip)
			fs = fs.FilterByIP(ip)
		}
		return fs
	}

	orderConntrack := func(fs FlowSlice, r *http.Request) {
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
		fs, err := Flows()
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

	for {
		time.Sleep(flags.iptablesReadDuration)
		next, err := ipt.Stats()
		if err != nil {
			log.Fatal(err)
		}
		if err = clients.UpdateIPTables(next); err != nil {
			log.Fatal(err)
		}
	}
}
