package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/peterbourgon/ff/v3"
	"github.com/some-programs/natbwmon/internal/clientstats"
)

const pollInterval = 200 * time.Millisecond

func readStats(ctx context.Context, baseurl string) (clientstats.Stats, error) {
	url := fmt.Sprintf("%s/v1/stats/", baseurl)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var stats clientstats.Stats
	err = json.Unmarshal(data, &stats)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

type tickMsg struct{}

type statsMsg clientstats.Stats

type errMsg struct{ err error }

var headers = []string{"ip (i)", "rx rate (r)", "tx rate (t)", "name (n)", "hwaddr (h)"}

type model struct {
	baseURL string
	orderBy string
	stats   clientstats.Stats
	err     error
	height  int
	// colWidths only ever grow so the columns don't jump around as rates change.
	colWidths []int
}

func newModel(baseURL string) model {
	m := model{
		baseURL:   baseURL,
		orderBy:   "n",
		colWidths: make([]int, len(headers)),
	}
	m.growColWidths(headers)
	return m
}

func (m model) Init() tea.Cmd {
	return m.fetch
}

func (m model) fetch() tea.Msg {
	stats, err := readStats(context.Background(), m.baseURL)
	if err != nil {
		return errMsg{err}
	}
	return statsMsg(stats)
}

func tick() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch k := msg.String(); k {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "r", "t", "h", "n", "i":
			m.orderBy = k
			m.sort()
		}
	case tea.WindowSizeMsg:
		m.height = msg.Height
	case tickMsg:
		return m, m.fetch
	case statsMsg:
		m.stats = clientstats.Stats(msg)
		m.sort()
		for _, v := range m.stats {
			m.growColWidths(row(v))
		}
		return m, tick()
	case errMsg:
		m.err = msg.err
		return m, tea.Quit
	}
	return m, nil
}

func (m *model) sort() {
	switch m.orderBy {
	case "r":
		m.stats.OrderByInRate()
	case "t":
		m.stats.OrderByOutRate()
	case "h":
		m.stats.OrderByHWAddr()
	case "n":
		m.stats.OrderByName()
	default:
		m.stats.OrderByIP()
	}
}

func (m *model) growColWidths(row []string) {
	for idx, v := range row {
		// +2 for horizontal padding
		if l := lipgloss.Width(v) + 2; m.colWidths[idx] < l {
			m.colWidths[idx] = l
		}
	}
}

func row(s clientstats.Stat) []string {
	return []string{s.IP, s.InFmt(), s.OutFmt(), s.Name, s.HWAddr}
}

func (m model) View() tea.View {
	t := table.New().
		Border(lipgloss.NormalBorder()).
		Headers(headers...).
		StyleFunc(func(_, col int) lipgloss.Style {
			return lipgloss.NewStyle().Padding(0, 1).Width(m.colWidths[col])
		})
	if m.height > 0 {
		t.Height(m.height)
	}
	for _, v := range m.stats {
		t.Row(row(v)...)
	}
	v := tea.NewView(t.Render())
	v.AltScreen = true
	v.WindowTitle = "natbwmontop"
	return v
}

func main() {
	var baseURL string

	flag.StringVar(&baseURL, "url", "http://192.168.0.1:8833", "base url for natbwmon")

	ff.Parse(flag.CommandLine, os.Args[1:],
		ff.WithEnvVarPrefix("NATBWMONTOP"),
	)

	m, err := tea.NewProgram(newModel(baseURL), tea.WithFPS(30)).Run()
	if err != nil && !errors.Is(err, tea.ErrInterrupted) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if m, ok := m.(model); ok && m.err != nil {
		fmt.Println(m.err)
		os.Exit(1)
	}
}
