package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/go-pa/fenv"
	"github.com/thomasf/natbwmon/internal/mon"
)

func readStats(ctx context.Context, baseurl string) (mon.Stats, error) {
	url := fmt.Sprintf("%s/v1/stats/", baseurl)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	var stats mon.Stats
	err = json.Unmarshal(data, &stats)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return stats, nil

}

func main() {

	var baseURL string

	flag.StringVar(&baseURL, "url", "http://192.168.0.1:8833", "base url for natbwmon")
	fenv.CommandLinePrefix("NATBWMONTOP_")
	fenv.MustParse()
	flag.Parse()

	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}

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

	defer ui.Close()
	table := widgets.NewTable()
	table.TextStyle = ui.StyleClear
	w, h := ui.TerminalDimensions()
	table.SetRect(0, 0, w, h)
	table.RowSeparator = false
	table.ColumnWidths = []int{5, 5, 5, 5, 5}

	statsCh := make(chan mon.Stats, 0)

	go func(ctx context.Context) {
		ticker := time.NewTicker(200 * time.Millisecond)
	loop:
		for {
			select {
			case <-ticker.C:
				stats, err := readStats(ctx, baseURL)
				if err != nil {
					log.Println(err)
					continue loop
				}
				statsCh <- stats
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	uiEvents := ui.PollEvents()
	orderBy := "n"
loop:
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				break loop

			case "r", "t", "h", "n", "i":
				orderBy = e.ID
			case "<Resize>":
				payload := e.Payload.(ui.Resize)
				table.SetRect(0, 0, payload.Width, payload.Height)
				ui.Clear()
				ui.Render(table)
			}
		case stats := <-statsCh:
			switch orderBy {
			case "r":
				stats.OrderByInRate()
			case "t":
				stats.OrderByOutRate()
			case "h":
				stats.OrderByHWAddr()
			case "n":
				stats.OrderByName()
			default:
				stats.OrderByIP()
			}
			var rows [][]string
			rows = append(rows, []string{"ip", "rx rate", "tx rate", "name", "hwaddr"})
			for _, v := range stats {
				row := []string{v.IP, v.InFmt(), v.OutFmt(), v.Name, v.HWAddr}
				rows = append(rows, row)
				for idx, v := range row {
					l := len(v) + 2
					if table.ColumnWidths[idx] < l {
						table.ColumnWidths[idx] = l
					}
				}
			}
			table.Rows = rows
			ui.Render(table)
		case <-ctx.Done():
			break loop
		}
	}
	cancel()
	<-ctx.Done()
}
