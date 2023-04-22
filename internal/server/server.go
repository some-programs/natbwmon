package server

import (
	"context"
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
	"github.com/some-programs/natbwmon/assets"
	"github.com/some-programs/natbwmon/internal/clientstats"
	"github.com/some-programs/natbwmon/internal/log"
	"github.com/some-programs/natbwmon/internal/mon"
)

// Server contains the web page and JSON API routes.
type Server struct {
	MonClients  *mon.Clients
	NmapEnabled bool
	OUILookup   func(s string) (string, error)
}

// Routes returns a *http.ServeMux with all the application request handlers.
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
				Dur("dur", duration).
				Str("addr", r.RemoteAddr).
				Msg("")
		}),
		MaxBytesReaderMiddleware(1024*1024),
	)

	mux := http.NewServeMux()

	mux.Handle("/", c.Then(s.Clients()))
	mux.Handle("/conntrack", c.Then(s.Conntrack()))
	mux.Handle("/v1/stats/", c.Then(s.StatsV1()))
	if s.NmapEnabled {
		mux.Handle("/v0/nmap/", c.Then(s.NmapV0()))
	}
	mux.Handle("/static/", c.Then(hashfs.FileServer(assets.StaticHashFS)))

	return mux
}

// clientsTemplateData .
type clientsTemplateData struct {
	Title string
}

// Clients serves the list of clients web page.
func (s *Server) Clients() AppHandler {
	tmpl, err := template.New("base.html").
		Funcs(template.FuncMap{
			"static": assets.StaticHashFS.HashName,
		},
		).
		ParseFS(assets.TemplateFS, "template/base.html", "template/clients.html")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse clients template")
	}
	return func(w http.ResponseWriter, r *http.Request) error {
		logger := log.FromRequest(r)
		d := clientsTemplateData{}
		if err := tmpl.Execute(w, &d); err != nil {
			logger.Info().Err(err).Msg("")
			return err
		}
		return nil
	}
}

// conntrackTemplateData .
type conntrackTemplateData struct {
	Title       string
	FS          mon.FlowSlice
	IPFilter    string
	OrderFilter string
	NMAP        bool
	IP          string
}

// Clients serves the connection tracking web page.
func (s *Server) Conntrack() AppHandler {
	templ, err := template.New("base.html").
		Funcs(template.FuncMap{
			"static": assets.StaticHashFS.HashName,
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
		).
		ParseFS(assets.TemplateFS, "template/base.html", "template/conntrack.html")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse conntrack template")
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

	var conntrackMu sync.Mutex // limit to a single concurrent to deter abuse

	return func(w http.ResponseWriter, r *http.Request) error {
		conntrackMu.Lock()
		defer conntrackMu.Unlock()
		logger := log.FromRequest(r)
		fs, err := mon.Flows()
		if err != nil {
			logger.Info().Err(err).Msg("")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return nil
		}
		fs = filter(fs, r)
		order(fs, r)

		data := conntrackTemplateData{
			NMAP:        s.NmapEnabled,
			IP:          r.URL.Query().Get("ip"),
			FS:          fs,
			Title:       "conntrack",
			IPFilter:    r.URL.Query().Get("ip"),
			OrderFilter: r.URL.Query().Get("o"),
		}
		if err := templ.Execute(w, &data); err != nil {
			logger.Info().Err(err).Msg("render conntrack")
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
		logger := log.FromRequest(r)
		c := s.MonClients.Stats()
		c = filter(c, r)
		res := make(clientstats.Stats, 0, len(c))
		for _, stat := range c {
			v, err := s.OUILookup(stat.HWAddr)
			if err != nil {
				logger.Warn().Err(err).Msg("lookup error")
			} else {
				stat.Manufacturer = v
			}
			if stat.Manufacturer == "" {
				hwa, err := net.ParseMAC(stat.HWAddr)
				if err != nil {
					logger.Error().Err(err).Msg("error parsing hardware addr")
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
			logger.Info().Err(err).Msg("")
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

// NmapV0 runs a predefined nmap qiery against a single IP address.
func (s *Server) NmapV0() AppHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()
		logger := log.Ctx(ctx)
		ipStr := r.URL.Query().Get("ip")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			logger.Info().Str("ip", ipStr).Msg("could not parse ip argument")
			w.WriteHeader(http.StatusBadRequest)
			return nil
		}
		w.Header().Set("Content-Type", "text/event-stream")

		cmd := exec.CommandContext(ctx, "nmap", "-v", "-A", "-T4", ip.String())
		w.Write([]byte(fmt.Sprintf("running: %s\n", strings.Join(cmd.Args, " "))))
		cmd.Stdout = w
		cmd.Stderr = w
		err := cmd.Run()
		if err != nil {
			logger.Error().Err(err).Str("ip", ipStr).Msg("nmap failed")
			return nil
		}
		w.Write([]byte("\n nmap successful exit"))
		return nil
	}
}
