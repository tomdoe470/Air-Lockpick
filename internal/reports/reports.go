package reports

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/auditteam/wifiaudit/internal/session"
)

// Generator creates audit reports in various formats
type Generator struct {
	outputDir   string
	auditorName string
	orgName     string
}

func NewGenerator(outputDir string) *Generator {
	os.MkdirAll(outputDir, 0755)
	return &Generator{outputDir: outputDir}
}

func (g *Generator) SetMeta(auditor, org string) {
	g.auditorName = auditor
	g.orgName = org
}

// GenerateJSON produces a JSON report
func (g *Generator) GenerateJSON(sess *session.Session) (string, error) {
	type JSONReport struct {
		GeneratedAt  time.Time          `json:"generated_at"`
		Auditor      string             `json:"auditor,omitempty"`
		Organization string             `json:"organization,omitempty"`
		Session      *session.Session   `json:"session"`
		Summary      map[string]interface{} `json:"summary"`
	}

	report := JSONReport{
		GeneratedAt:  time.Now(),
		Auditor:      g.auditorName,
		Organization: g.orgName,
		Session:      sess,
		Summary: map[string]interface{}{
			"total_networks":    len(sess.Networks),
			"total_clients":     sess.TotalClients(),
			"total_captures":    len(sess.Captures),
			"encryption_stats":  sess.EncryptionStats(),
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	outPath := g.outputPath(sess.ID, "json")
	return outPath, os.WriteFile(outPath, data, 0644)
}

// GenerateHTML produces an HTML report
func (g *Generator) GenerateHTML(sess *session.Session) (string, error) {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlTemplate))

	type TemplateData struct {
		GeneratedAt  string
		Auditor      string
		Organization string
		Session      *session.Session
		EncStats     map[string]int
	}

	data := TemplateData{
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05"),
		Auditor:      g.auditorName,
		Organization: g.orgName,
		Session:      sess,
		EncStats:     sess.EncryptionStats(),
	}

	outPath := g.outputPath(sess.ID, "html")
	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", err
	}
	return outPath, nil
}

// GenerateTXT produces a plain text report
func (g *Generator) GenerateTXT(sess *session.Session) (string, error) {
	outPath := g.outputPath(sess.ID, "txt")
	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprintln(f, "═══════════════════════════════════════════════════════════")
	fmt.Fprintln(f, "  WIFI AUDIT REPORT")
	fmt.Fprintln(f, "═══════════════════════════════════════════════════════════")
	fmt.Fprintf(f, "  Generated    : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if g.auditorName != "" {
		fmt.Fprintf(f, "  Auditor      : %s\n", g.auditorName)
	}
	if g.orgName != "" {
		fmt.Fprintf(f, "  Organization : %s\n", g.orgName)
	}
	fmt.Fprintf(f, "  Session ID   : %s\n", sess.ID)
	fmt.Fprintf(f, "  Interface    : %s\n", sess.Interface)
	fmt.Fprintf(f, "  Start Time   : %s\n", sess.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(f)

	// Summary
	fmt.Fprintln(f, "───────────────────────────────────────────────────────────")
	fmt.Fprintln(f, "  SUMMARY")
	fmt.Fprintln(f, "───────────────────────────────────────────────────────────")
	fmt.Fprintf(f, "  Total Networks  : %d\n", len(sess.Networks))
	fmt.Fprintf(f, "  Total Clients   : %d\n", sess.TotalClients())
	fmt.Fprintf(f, "  Captures        : %d\n", len(sess.Captures))
	fmt.Fprintln(f)

	enc := sess.EncryptionStats()
	fmt.Fprintln(f, "  Encryption Breakdown:")
	for k, v := range enc {
		fmt.Fprintf(f, "    %-12s : %d networks\n", k, v)
	}
	fmt.Fprintln(f)

	// Networks
	fmt.Fprintln(f, "───────────────────────────────────────────────────────────")
	fmt.Fprintln(f, "  DISCOVERED NETWORKS")
	fmt.Fprintln(f, "───────────────────────────────────────────────────────────")
	fmt.Fprintf(f, "%-22s %-18s %-5s %-8s %-8s %s\n",
		"SSID", "BSSID", "CH", "ENC", "SIGNAL", "VENDOR")
	fmt.Fprintln(f, "────────────────────────────────────────────────────────────────")

	for _, n := range sess.Networks {
		ssid := n.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		if len(ssid) > 20 {
			ssid = ssid[:17] + "..."
		}
		fmt.Fprintf(f, "%-22s %-18s %-5d %-8s %-8d %s\n",
			ssid, n.BSSID, n.Channel, n.Encryption, n.Signal, n.Vendor)
	}

	// Captures
	if len(sess.Captures) > 0 {
		fmt.Fprintln(f)
		fmt.Fprintln(f, "───────────────────────────────────────────────────────────")
		fmt.Fprintln(f, "  CAPTURED HANDSHAKES")
		fmt.Fprintln(f, "───────────────────────────────────────────────────────────")
		for _, c := range sess.Captures {
			fmt.Fprintf(f, "  BSSID: %-18s SSID: %-20s File: %s\n",
				c.BSSID, c.SSID, c.FilePath)
		}
	}

	fmt.Fprintln(f)
	fmt.Fprintln(f, "═══════════════════════════════════════════════════════════")
	fmt.Fprintln(f, "  END OF REPORT")
	fmt.Fprintln(f, "═══════════════════════════════════════════════════════════")

	return outPath, nil
}

func (g *Generator) outputPath(sessionID, ext string) string {
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(g.outputDir, fmt.Sprintf("report_%s_%s.%s", ts, sessionID[:8], ext))
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Audit Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 1rem; margin-bottom: 1.5rem; }
  h2 { color: #79c0ff; margin: 1.5rem 0 0.75rem; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }
  .card-title { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; margin-bottom: 0.3rem; }
  .card-value { font-size: 1.5rem; font-weight: bold; color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
  th { background: #161b22; color: #8b949e; padding: 0.5rem 1rem; text-align: left; font-size: 0.75rem; text-transform: uppercase; }
  td { padding: 0.5rem 1rem; border-bottom: 1px solid #21262d; }
  tr:hover { background: #161b22; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px; font-size: 0.7rem; font-weight: bold; }
  .wpa2 { background: #1f6feb33; color: #79c0ff; }
  .wpa { background: #f7854033; color: #ffa657; }
  .wep { background: #f8514933; color: #ff7b72; }
  .opn { background: #da3633; color: #fff; }
  .footer { margin-top: 2rem; font-size: 0.75rem; color: #8b949e; text-align: center; }
</style>
</head>
<body>
<h1>📡 WiFi Audit Report</h1>
<div class="meta">
  <div class="card"><div class="card-title">Generated</div><div class="card-value" style="font-size:1rem">{{.GeneratedAt}}</div></div>
  {{if .Auditor}}<div class="card"><div class="card-title">Auditor</div><div class="card-value" style="font-size:1rem">{{.Auditor}}</div></div>{{end}}
  {{if .Organization}}<div class="card"><div class="card-title">Organization</div><div class="card-value" style="font-size:1rem">{{.Organization}}</div></div>{{end}}
  <div class="card"><div class="card-title">Total Networks</div><div class="card-value">{{len .Session.Networks}}</div></div>
  <div class="card"><div class="card-title">Session Interface</div><div class="card-value" style="font-size:1rem">{{.Session.Interface}}</div></div>
</div>

<h2>Encryption Breakdown</h2>
<div class="meta">
{{range $enc, $count := .EncStats}}
  <div class="card"><div class="card-title">{{$enc}}</div><div class="card-value">{{$count}}</div></div>
{{end}}
</div>

<h2>Discovered Networks</h2>
<table>
<tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal (dBm)</th><th>Encryption</th><th>Vendor</th></tr>
{{range .Session.Networks}}
<tr>
  <td>{{if .SSID}}{{.SSID}}{{else}}<em>&lt;hidden&gt;</em>{{end}}</td>
  <td style="font-family:monospace">{{.BSSID}}</td>
  <td>{{.Channel}}</td>
  <td>{{.Signal}}</td>
  <td><span class="badge {{.Encryption | printf "%s" | lower}}">{{.Encryption}}</span></td>
  <td>{{.Vendor}}</td>
</tr>
{{end}}
</table>

{{if .Session.Captures}}
<h2>Captured Handshakes</h2>
<table>
<tr><th>BSSID</th><th>SSID</th><th>Captured At</th><th>File</th></tr>
{{range .Session.Captures}}
<tr>
  <td style="font-family:monospace">{{.BSSID}}</td>
  <td>{{.SSID}}</td>
  <td>{{.CapturedAt.Format "2006-01-02 15:04:05"}}</td>
  <td style="font-family:monospace;font-size:0.8rem">{{.FilePath}}</td>
</tr>
{{end}}
</table>
{{end}}

<div class="footer">Generated by wifiaudit | Session: {{.Session.ID}}</div>
</body>
</html>`
