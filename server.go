package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/benbjohnson/hashfs"
	"github.com/justinas/alice"
	"github.com/rs/zerolog/hlog"
	"github.com/some-programs/natbwmon/internal/clientstats"
	"github.com/some-programs/natbwmon/internal/log"
	"github.com/some-programs/natbwmon/internal/mon"
	"github.com/tomruk/oui"
)

// AppHandler adds generic error handling to a handler func.
//
// A handler func that writes it's own error response should typically not return an error.
//
type AppHandler func(http.ResponseWriter, *http.Request) error

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
}

// Server .
type Server struct {
	clients     *mon.Clients
	nmapEnabled bool
	ouiDB       *oui.DB
}

func (s *Server) Routes() *http.ServeMux {
	c := alice.New()
	c = c.Append(
		hlog.NewHandler(log.Logger),
		hlog.RequestIDHandler("req_id", "Request-Id"),
		hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			l := log.WithIDWithoutCaller(r.Context()).Logger()
			l.Info().
				Str("caller", "http").
				Str("method", r.Method).
				Stringer("url", r.URL).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg("")
		}),
		MaxBytesReaderMiddleware(1024*1024),
	)

	mux := http.NewServeMux()

	mux.Handle("/", c.Then(s.Clients()))
	mux.Handle("/conntrack", c.Then(s.Conntrack()))
	mux.Handle("/v1/stats/", c.Then(s.StatsV1()))
	if s.nmapEnabled {
		mux.Handle("/v0/nmap/", c.Then(s.NmapV0()))
	}
	mux.Handle("/static/", c.Then(hashfs.FileServer(StaticHashFS)))

	return mux
}

func (s *Server) Clients() AppHandler {
	tmpl, err := template.New("base.html").Funcs(
		template.FuncMap{
			"static": StaticHashFS.HashName,
		},
	).ParseFS(TemplateFS, "template/base.html", "template/clients.html")
	if err != nil {
		log.Fatal().Err(err).Msg("parse templates")
	}
	return func(w http.ResponseWriter, r *http.Request) error {
		d := clientsTemplateData{}
		err := tmpl.Execute(w, &d)
		if err != nil {
			log.Info().Err(err).Msg("")
			return err
		}
		return nil
	}
}

// Conntrack displays a page with the
func (s *Server) Conntrack() AppHandler {
	templ, err := template.New("base.html").Funcs(
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
			"bytes": func(n uint64) string {
				return clientstats.FmtBytes(float64(n), "")
			},
		},
	).ParseFS(TemplateFS, "template/base.html", "template/conntrack.html")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	filter := func(fs mon.FlowSlice, r *http.Request) mon.FlowSlice {
		q := r.URL.Query()
		ip := q.Get("ip")
		if ip != "" {
			ip := net.ParseIP(ip)
			fs = fs.FilterByIP(ip)
		}
		return fs
	}

	order := func(fs mon.FlowSlice, r *http.Request) {
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
			case "orig_bytes":
				fs.OrderByOriginalBytes()
			case "reply_src":
				fs.OrderByReplySPort()
				fs.OrderByReplySource()
			case "reply_dst":
				fs.OrderByReplyDPort()
				fs.OrderByReplyDestination()
			case "reply_bytes":
				fs.OrderByReplyBytes()

			}
		}
	}

	var conntrackMu sync.Mutex // limit to avoid abuse
	return func(w http.ResponseWriter, r *http.Request) error {
		conntrackMu.Lock()
		defer conntrackMu.Unlock()
		fs, err := mon.Flows()
		if err != nil {
			log.Info().Err(err).Msg("")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return nil
		}
		fs = filter(fs, r)
		order(fs, r)

		data := conntrackTemplateData{
			NMAP:        s.nmapEnabled,
			IP:          r.URL.Query().Get("ip"),
			FS:          fs,
			Title:       "conntrack",
			IPFilter:    r.URL.Query().Get("ip"),
			OrderFilter: r.URL.Query().Get("o"),
		}
		err = templ.Execute(w, &data)
		if err != nil {
			log.Info().Err(err).Msg("render conntrack")
			return err
		}
		return nil
	}
}

// StatsV1 is an API resource that returns a JSON encoded respons with the
// current list of identified network devices and their current bandwidth rate.
func (s *Server) StatsV1() AppHandler {
	order := func(s clientstats.Stats, r *http.Request) {
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

	filter := func(ss clientstats.Stats, r *http.Request) clientstats.Stats {
		q := r.URL.Query()
		IPs := q["ip"]
		HWAddrs := q["hwaddr"]
		names := q["name"]

		if len(IPs) == 0 && len(HWAddrs) == 0 && len(names) == 0 {
			return ss
		}
		res := make(clientstats.Stats, 0, len(ss))
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

	return func(w http.ResponseWriter, r *http.Request) error {
		c := s.clients.Stats()
		c = filter(c, r)
		res := make(clientstats.Stats, 0, len(c))
		for _, stat := range c {
			v, err := s.ouiDB.Lookup(stat.HWAddr)
			if err != nil {
				log.Warn().Err(err).Msg("lookup error")
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
		order(res, r)
		data, err := json.Marshal(&res)
		if err != nil {
			log.Info().Err(err).Msg("")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return nil
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return nil
	}
}

// NmapV0 runs a simple nmap against an ip address.
func (s *Server) NmapV0() AppHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		ipStr := r.URL.Query().Get("ip")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Info().Str("ip", ipStr).Msg("could not parse ip argument")
			w.WriteHeader(http.StatusBadRequest)
			return nil
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
			return nil
		}
		w.Write([]byte("\n nmap successful exit"))
		return nil
	}
}

// maxBytesReaderMiddleware .
type maxBytesReaderMiddleware struct {
	h http.Handler
	N int64
}

func (b maxBytesReaderMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, b.N)
	b.h.ServeHTTP(w, r)
}

func MaxBytesReaderMiddleware(maxSize int64) func(h http.Handler) http.Handler {
	if maxSize <= 0 {
		log.Fatal().Msgf("maxSize cannot be equal or less than 0: %v", maxSize)
	}
	fn := func(h http.Handler) http.Handler {
		return maxBytesReaderMiddleware{h: h, N: maxSize}
	}
	return fn
}
