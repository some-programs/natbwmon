package main

import (
	"honnef.co/go/conntrack"
)

// clientsTemplateData .
type clientsTemplateData struct {
	Hosts []Stat
	Title string
}

const clientsTpl = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>{{.Title}}</title>
  </head>
<body>
` + style + `
  <table>
    <tr>
      <th><a href="/?order_by=ip">IP</a></th>
      <th><a href="/?order_by=name">Hostname</a></th>
      <th><a href="/?order_by=rate_in">IN rate</a></th>
      <th><a href="/?order_by=rate_out">OUT rate</a></th>
      <th><a href="/?order_by=hwaddr">Hardware address</a></th>
    </tr>
    {{range .Hosts}}
    <tr>
      <td><a href="/conntrack?ip={{.IP}}">{{ .IP }}</a></td>
      <td>{{ .Name }}</td>
      <td>{{ .InKb }}</td>
      <td>{{ .OutKb }}</td>
      <td><a href="https://hwaddress.com/?q={{ .HWAddrPrefix }}">{{ .HWAddr }}</a></td>
    </tr>
    {{else}}
    <tr>
      <td><strong>no rows</strong></td>
    </tr>
    {{end}}
  </table>
<script>
var t=setTimeout(function(){window.location.reload()}, 900);
document.onkeypress = function(e){clearTimeout(t)};
document.addEventListener('click', function(e){clearTimeout(t)});
</script>
</body>
</html>`

// conntrackTemplateData .
type conntrackTemplateData struct {
	Title       string
	FS          conntrack.FlowSlice
	IPFilter    string
	OrderFilter string
}

const conntrackTpl = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>{{.Title}}</title>
  </head>
<body>
` + style + `

<h1>conntrack {{.IPFilter}}</h1>
<h2>actions</h2>
<a href="/conntrack">clear filters</a>
<h2>summary</h2>
<table>
  <tr>
   <th>key</th>
   <th>value</th>
  </tr>
 <tr>
   <td>total</td>
   <td>{{ len .FS }}</td>
 </tr>
</table>
<h1>list</h1>
  <table>
    <tr>
    <th><a href="/conntrack?o=proto&ip={{ .IPFilter }}">proto</a></th>
    <th><a href="/conntrack?o=state&ip={{ .IPFilter }}">state</a></th>
    <th><a href="/conntrack?o=ttl&ip={{ .IPFilter }}">TTL</a></th>
    <th><a href="/conntrack?o=orig_src&ip={{ .IPFilter }}">orig source</a></th>
    <th><a href="/conntrack?o=orig_dst&ip={{ .IPFilter }}">orig dest</a></th>
    <th><a href="/conntrack?o=reply_src&ip={{ .IPFilter }}">reply source</a></th>
    <th><a href="/conntrack?o=reply_dst&ip={{ .IPFilter }}">reply dest</a></th>
    </tr>
    {{range .FS }}
    <tr>
      <td>{{ .Protocol.Name }}</td>
      <td>{{ .State }}</td>
      <td>{{ .TTL }}</td>
      <td class="{{ ipclass .Original.Source }}"><a href="/conntrack?o={{ $.OrderFilter }}&ip={{ .Original.Source }}">{{ .Original.Source }}</a>:{{ .Original.SPort }}</td>
      <td class="{{ ipclass .Original.Destination }}"><a href="/conntrack?o={{ $.OrderFilter }}&ip={{ .Original.Destination }}">{{ .Original.Destination }}</a>:{{ .Original.DPort }}</td>
      <td class="{{ ipclass .Reply.Source }}"><a href="/conntrack?o={{ $.OrderFilter }}&ip={{ .Reply.Source }}">{{ .Reply.Source }}</a>:{{ .Reply.SPort }}</td>
      <td class="{{ ipclass .Reply.Destination }}"><a href="/conntrack?o={{ $.OrderFilter }}&ip={{ .Reply.Destination }}">{{ .Reply.Destination }}</a>:{{ .Reply.DPort }}</td>
    </tr>
    {{else}}
    <tr>
      <td><strong>no rows</strong></td>
    </tr>
    {{end}}
  </table>
</body>
</html>`

const style = `
<link href="https://fonts.googleapis.com/css2?family=Roboto&family=Roboto+Condensed&family=Roboto+Mono&display=swap" rel="stylesheet">

    <style type="text/css" media="screen">

      body {
        font-family: 'Roboto', sans-serif;
        color: #222;
        padding: 1em .5em;
      }

      a {
        color: #125E89;
        text-decoration: none;
      }
      a:hover {
        text-decoration: underline;
      }

      tbody > tr:first-child{
        border-bottom: 2px solid #ddd;
      }
      tbody > tr:last-child{
        border-bottom: 2px solid #ddd;
      }


      table {
        font-family: 'Roboto Condensed', sans-serif;
        border-collapse: collapse;
      }
      tr:hover {
        background-color: #e8e8e8;
        color: black;
      }
      tr > td:nth-child(1) {
        white-space: nowrap;
        font-family: 'Roboto', sans-serif;
      }
      td {
        padding-left: 5px;
        padding-right: 5px;
      }

      pre {
        font-family: 'Roboto Mono', monospace;
        color: #222;
        font-size: 85%;
        line-height: 1.3em;
      }

      .success {
        color: #598700;
      }
      .success > a {
        color: #598700;
      }

      .failed {
        color: #A11C42;
      }
      .failed > a {
        color: #A11C42;
      }

      h1,h2,h3,h4 {
        font-family: 'Roboto Condensed', sans-serif;
        color: #222;
        font-weight: normal;
      }

      h1 {
        border-top: 2px solid #CA9F00;
        color: #222;
      }
      h4 {
        margin: 0;
      }

      h1 { font-size: 1.9em; }
      h2 { font-size: 1.55em; }
      h3 { font-size: 1.4em; }
      h4 { font-size: 1.2em; }

      .success-invert {
        background-color: #598700;
        color: white;
      }
      .success-invert > a {
        color: white;
      }

      .failed-invert {
        background-color: #A11C42;
        color: white;
      }
      .failed-invert > a {
        color: white;
      }
    </style>
`
