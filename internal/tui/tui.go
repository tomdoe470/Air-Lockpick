package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/auditteam/wifiaudit/internal/monitor"
	"github.com/auditteam/wifiaudit/internal/scanner"
)

// ─────────────────────────────────────────────
//  Colours
// ─────────────────────────────────────────────

var (
	cAccent = lipgloss.Color("#58a6ff")
	cMuted  = lipgloss.Color("#6e7681")
	cText   = lipgloss.Color("#c9d1d9")
	cGreen  = lipgloss.Color("#3fb950")
	cYellow = lipgloss.Color("#d29922")
	cOrange = lipgloss.Color("#db6d28")
	cRed    = lipgloss.Color("#f85149")
	cCyan   = lipgloss.Color("#39d353")
	cSel    = lipgloss.Color("#1f6feb")
)

var (
	sTitle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sMuted = lipgloss.NewStyle().Foreground(cMuted)
	sText  = lipgloss.NewStyle().Foreground(cText)
	sHead  = lipgloss.NewStyle().Foreground(cMuted).Bold(true)
	sSel   = lipgloss.NewStyle().Background(cSel).Foreground(lipgloss.Color("#ffffff")).Bold(true)
	sSep   = lipgloss.NewStyle().Foreground(cMuted)

	sTabOn  = lipgloss.NewStyle().Bold(true).Foreground(cAccent).Underline(true).PaddingLeft(1).PaddingRight(1)
	sTabOff = lipgloss.NewStyle().Foreground(cMuted).PaddingLeft(1).PaddingRight(1)

	sEncOPN  = lipgloss.NewStyle().Bold(true).Foreground(cRed)
	sEncWEP  = lipgloss.NewStyle().Bold(true).Foreground(cOrange)
	sEncWPA  = lipgloss.NewStyle().Bold(true).Foreground(cYellow)
	sEncWPA2 = lipgloss.NewStyle().Bold(true).Foreground(cGreen)
	sEncWPA3 = lipgloss.NewStyle().Bold(true).Foreground(cCyan)
)

// ─────────────────────────────────────────────
//  Model
// ─────────────────────────────────────────────

type tabID int

const (
	tabNetworks tabID = iota
	tabClients
	tabCaptures
	tabMACs
)

type Model struct {
	iface      string
	sc         *scanner.Scanner
	mon        *monitor.Manager
	networks   []scanner.Network
	clients    []scanner.Client
	tab        tabID
	cursor     int
	width      int
	height     int
	scanning   bool
	status     string
	statusErr  bool
	lastUpdate time.Time
	spinner    spinner.Model
}

// ─────────────────────────────────────────────
//  Messages
// ─────────────────────────────────────────────

type tickMsg time.Time
type scanStartedMsg struct{}
type errMsg error

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ─────────────────────────────────────────────
//  Init / Update
// ─────────────────────────────────────────────

func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(), m.spinner.Tick, m.cmdStartScan())
}

func (m Model) cmdStartScan() tea.Cmd {
	return func() tea.Msg {
		if err := m.mon.Enable(); err != nil {
			return errMsg(err)
		}
		go m.sc.ScanNetworks([]int{})
		return scanStartedMsg{}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var spCmd tea.Cmd
	m.spinner, spCmd = m.spinner.Update(msg)
	cmds = append(cmds, spCmd)

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case scanStartedMsg:
		m.scanning = true
		m.status = "Scanning"

	case tickMsg:
		if m.scanning {
			m.networks = m.sc.GetNetworks()
			m.clients = m.sc.GetClients()
			m.lastUpdate = time.Now()
		}
		cmds = append(cmds, tick())

	case errMsg:
		m.statusErr = true
		m.status = fmt.Sprintf("Error: %v", msg)

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.sc.Stop()
			m.mon.Disable()
			return m, tea.Quit

		case "tab":
			m.tab = (m.tab + 1) % 4
			m.cursor = 0

		case "1":
			m.tab, m.cursor = tabNetworks, 0
		case "2":
			m.tab, m.cursor = tabClients, 0
		case "3":
			m.tab, m.cursor = tabCaptures, 0
		case "4":
			m.tab, m.cursor = tabMACs, 0

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if n := m.listLen(); m.cursor < n-1 {
				m.cursor++
			}
		}
	}

	return m, tea.Batch(cmds...)
}

func (m Model) listLen() int {
	switch m.tab {
	case tabNetworks:
		return len(m.networks)
	case tabClients:
		return len(m.clients)
	}
	return 0
}

// ─────────────────────────────────────────────
//  View
// ─────────────────────────────────────────────

func (m Model) View() string {
	if m.width == 0 {
		return "Loading…"
	}
	w := m.width
	lines := []string{
		m.viewHeader(w),
		"",
		m.viewTabs(),
		"",
	}

	switch m.tab {
	case tabNetworks:
		lines = append(lines, m.viewNetworks(w)...)
	case tabClients:
		lines = append(lines, m.viewAllClients(w)...)
	case tabCaptures:
		lines = append(lines,
			sMuted.Render("  No captures yet."),
			sMuted.Render("  Use: air-lockpick capture handshake --bssid <BSSID> --channel <CH>"),
		)
	case tabMACs:
		lines = append(lines,
			sMuted.Render("  MAC list management."),
			sMuted.Render("  Use: air-lockpick mac list / add / remove / lookup"),
		)
	}

	// pad to fill height, push status bar to bottom
	body := strings.Join(lines, "\n")
	bodyH := lipgloss.Height(body)
	padH := m.height - bodyH - 2
	if padH > 0 {
		body += strings.Repeat("\n", padH)
	}

	return body + "\n" + m.viewStatusBar(w)
}

// ─────────────────────────────────────────────
//  Header
// ─────────────────────────────────────────────

func (m Model) viewHeader(w int) string {
	spin := ""
	if m.scanning {
		spin = m.spinner.View() + " "
	}

	left := sTitle.Render("✦ AIR-LOCKPICK")
	right := sMuted.Render(fmt.Sprintf(
		"%s%s  │  nets: %d  │  clients: %d  │  %s",
		spin,
		m.iface,
		len(m.networks),
		len(m.clients),
		m.lastUpdate.Format("15:04:05"),
	))

	gap := w - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	bar := left + strings.Repeat(" ", gap) + right
	sep := sSep.Render(strings.Repeat("─", w))
	return bar + "\n" + sep
}

// ─────────────────────────────────────────────
//  Tab bar
// ─────────────────────────────────────────────

func (m Model) viewTabs() string {
	tabs := []struct {
		id  tabID
		lbl string
	}{
		{tabNetworks, "1 Networks"},
		{tabClients, "2 Clients"},
		{tabCaptures, "3 Captures"},
		{tabMACs, "4 MACs"},
	}
	var parts []string
	for _, t := range tabs {
		if t.id == m.tab {
			parts = append(parts, sTabOn.Render(t.lbl))
		} else {
			parts = append(parts, sTabOff.Render(t.lbl))
		}
	}
	return " " + strings.Join(parts, "  ")
}

// ─────────────────────────────────────────────
//  Networks tab (AP table + clients section)
// ─────────────────────────────────────────────

const (
	colBSSID  = 19
	colCH     = 4
	colSIG    = 7
	colENC    = 5
	colCIPHER = 7
)

func (m Model) viewNetworks(w int) []string {
	ssidW := w - colBSSID - colCH - colSIG - colENC - colCIPHER - 7
	if ssidW < 10 {
		ssidW = 10
	}

	hdr := sHead.Render(fmt.Sprintf(
		" %-*s  %*s  %-*s  %-*s  %-*s  %-*s",
		colBSSID, "BSSID",
		colCH, "CH",
		colSIG, "SIGNAL",
		colENC, "ENC",
		colCIPHER, "CIPHER",
		ssidW, "SSID",
	))
	sep := sSep.Render(" " + strings.Repeat("─", w-2))

	lines := []string{hdr, sep}

	if len(m.networks) == 0 {
		var msg string
		if m.scanning {
			msg = fmt.Sprintf("  %s  Scanning for networks…", m.spinner.View())
		} else {
			msg = "  No networks found."
		}
		lines = append(lines, sMuted.Render(msg))
		return lines
	}

	// visible window
	bodyH := m.height - 16
	if bodyH < 3 {
		bodyH = 3
	}
	start := 0
	if m.cursor >= bodyH {
		start = m.cursor - bodyH + 1
	}
	end := start + bodyH
	if end > len(m.networks) {
		end = len(m.networks)
	}

	for i := start; i < end; i++ {
		n := m.networks[i]
		ssid := n.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		if len(ssid) > ssidW {
			ssid = ssid[:ssidW-1] + "…"
		}

		cursor := "  "
		if i == m.cursor {
			cursor = "▶ "
		}

		row := fmt.Sprintf("%s%-*s  %*d  %-*s  %-*s  %-*s  %-*s",
			cursor,
			colBSSID-2, n.BSSID,
			colCH, n.Channel,
			colSIG, signalBars(n.Signal),
			colENC, encTag(n.Encryption),
			colCIPHER, orDash(n.Cipher),
			ssidW, ssid,
		)

		if i == m.cursor {
			lines = append(lines, sSel.Width(w).Render(row))
		} else {
			lines = append(lines, sText.Render(row))
		}
	}

	// ── Selected AP clients ──────────────────
	lines = append(lines, "")
	if m.cursor < len(m.networks) {
		n := m.networks[m.cursor]
		clientTitle := fmt.Sprintf(" CLIENTS  %s", sText.Render(n.BSSID))
		if n.SSID != "" {
			clientTitle += sMuted.Render("  "+n.SSID)
		}
		lines = append(lines, sTitle.Render(clientTitle))
		lines = append(lines, sSep.Render(" "+strings.Repeat("─", w-2)))

		if len(n.Clients) == 0 {
			lines = append(lines, sMuted.Render("  No clients detected on this AP yet"))
		} else {
			cHdr := sHead.Render(fmt.Sprintf(
				"  %-19s  %-7s  %s", "STATION", "SIGNAL", "VENDOR"))
			lines = append(lines, cHdr)
			for _, c := range n.Clients {
				vendor := c.Vendor
				if vendor == "" {
					vendor = "—"
				}
				line := fmt.Sprintf("  %-19s  %-7s  %s",
					c.MAC, fmt.Sprintf("%ddBm", c.Signal), vendor)
				lines = append(lines, sText.Render(line))
			}
		}
	}

	return lines
}

// ─────────────────────────────────────────────
//  Clients tab (all clients)
// ─────────────────────────────────────────────

func (m Model) viewAllClients(w int) []string {
	vendorW := w - 19 - 19 - 8 - 5
	if vendorW < 10 {
		vendorW = 10
	}
	hdr := sHead.Render(fmt.Sprintf(
		"  %-19s  %-19s  %-7s  %-*s",
		"STATION", "AP BSSID", "SIGNAL", vendorW, "VENDOR"))
	sep := sSep.Render("  " + strings.Repeat("─", w-4))

	lines := []string{hdr, sep}

	if len(m.clients) == 0 {
		var msg string
		if m.scanning {
			msg = fmt.Sprintf("  %s  Listening for client frames…", m.spinner.View())
		} else {
			msg = "  No clients found."
		}
		lines = append(lines, sMuted.Render(msg))
		return lines
	}

	bodyH := m.height - 10
	if bodyH < 3 {
		bodyH = 3
	}
	start := 0
	if m.cursor >= bodyH {
		start = m.cursor - bodyH + 1
	}
	end := start + bodyH
	if end > len(m.clients) {
		end = len(m.clients)
	}

	for i := start; i < end; i++ {
		c := m.clients[i]
		vendor := c.Vendor
		if vendor == "" {
			vendor = "—"
		}
		bssid := c.BSSID
		if bssid == "" {
			bssid = "—"
		}
		row := fmt.Sprintf("  %-19s  %-19s  %-7s  %-*s",
			c.MAC, bssid, fmt.Sprintf("%ddBm", c.Signal), vendorW, vendor)

		if i == m.cursor {
			lines = append(lines, sSel.Width(w).Render(row))
		} else {
			lines = append(lines, sText.Render(row))
		}
	}
	return lines
}

// ─────────────────────────────────────────────
//  Status bar
// ─────────────────────────────────────────────

func (m Model) viewStatusBar(w int) string {
	dot := lipgloss.NewStyle().Foreground(cGreen).Render("●")
	if m.statusErr {
		dot = lipgloss.NewStyle().Foreground(cRed).Render("●")
	}

	left := dot + " " + sMuted.Render(m.status)
	right := sMuted.Render("q:quit  tab/1-4:switch  ↑↓ jk:scroll")

	gap := w - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}
	bar := left + strings.Repeat(" ", gap) + right
	sep := sSep.Render(strings.Repeat("─", w))
	return sep + "\n" + bar
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

func signalBars(dbm int) string {
	var n int
	switch {
	case dbm >= -50:
		n = 5
	case dbm >= -60:
		n = 4
	case dbm >= -70:
		n = 3
	case dbm >= -80:
		n = 2
	default:
		n = 1
	}
	filled := strings.Repeat("█", n)
	empty := strings.Repeat("░", 5-n)

	var c lipgloss.Color
	switch n {
	case 5, 4:
		c = cGreen
	case 3:
		c = cYellow
	case 2:
		c = cOrange
	default:
		c = cRed
	}
	return lipgloss.NewStyle().Foreground(c).Render(filled + empty)
}

func encTag(enc string) string {
	switch enc {
	case "OPN":
		return sEncOPN.Render("OPN")
	case "WEP":
		return sEncWEP.Render("WEP")
	case "WPA":
		return sEncWPA.Render("WPA")
	case "WPA2":
		return sEncWPA2.Render("WPA2")
	case "WPA3":
		return sEncWPA3.Render("WPA3")
	default:
		return sMuted.Render("???")
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ─────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────

func Run(iface string) error {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(cAccent)

	mon := monitor.New(iface)
	sc := scanner.New(mon.MonitorIface())

	m := Model{
		iface:      iface,
		mon:        mon,
		sc:         sc,
		networks:   []scanner.Network{},
		clients:    []scanner.Client{},
		status:     "Initializing…",
		lastUpdate: time.Now(),
		spinner:    sp,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
