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

// ──────────────────────────────────────────────
//  Colour palette
// ──────────────────────────────────────────────

var (
	clrBg      = lipgloss.Color("#0d1117")
	clrBorder  = lipgloss.Color("#30363d")
	clrMuted   = lipgloss.Color("#8b949e")
	clrText    = lipgloss.Color("#c9d1d9")
	clrAccent  = lipgloss.Color("#58a6ff")
	clrGreen   = lipgloss.Color("#3fb950")
	clrYellow  = lipgloss.Color("#d29922")
	clrOrange  = lipgloss.Color("#db6d28")
	clrRed     = lipgloss.Color("#f85149")
	clrPurple  = lipgloss.Color("#bc8cff")
	clrCyan    = lipgloss.Color("#39d353")
	clrSelected = lipgloss.Color("#1f6feb")
)

var (
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(clrAccent)

	styleMuted = lipgloss.NewStyle().Foreground(clrMuted)

	styleText = lipgloss.NewStyle().Foreground(clrText)

	styleSelected = lipgloss.NewStyle().
			Background(clrSelected).
			Foreground(lipgloss.Color("#ffffff")).
			Bold(true)

	styleHeader = lipgloss.NewStyle().
			Foreground(clrMuted).
			Bold(true)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(clrBorder)

	styleBadgeOPN  = lipgloss.NewStyle().Bold(true).Foreground(clrRed)
	styleBadgeWEP  = lipgloss.NewStyle().Bold(true).Foreground(clrOrange)
	styleBadgeWPA  = lipgloss.NewStyle().Bold(true).Foreground(clrYellow)
	styleBadgeWPA2 = lipgloss.NewStyle().Bold(true).Foreground(clrGreen)
	styleBadgeWPA3 = lipgloss.NewStyle().Bold(true).Foreground(clrCyan)

	styleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(clrAccent).
			Border(lipgloss.Border{Bottom: "─"}, false, false, true, false).
			BorderForeground(clrAccent).
			PaddingLeft(1).PaddingRight(1)

	styleTabInactive = lipgloss.NewStyle().
				Foreground(clrMuted).
				PaddingLeft(1).PaddingRight(1)
)

// ──────────────────────────────────────────────
//  Model
// ──────────────────────────────────────────────

type tab int

const (
	tabNetworks tab = iota
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
	currentTab tab
	cursor     int // AP list cursor
	width      int
	height     int
	scanning   bool
	status     string
	statusOK   bool
	lastUpdate time.Time
	err        error
	spinner    spinner.Model
}

// ──────────────────────────────────────────────
//  Messages
// ──────────────────────────────────────────────

type tickMsg time.Time
type scanStartedMsg struct{}
type errMsg error

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ──────────────────────────────────────────────
//  Init / Update
// ──────────────────────────────────────────────

func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(), m.spinner.Tick, m.startScan())
}

func (m Model) startScan() tea.Cmd {
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
		m.width = msg.Width
		m.height = msg.Height

	case scanStartedMsg:
		m.scanning = true
		m.status = "Scanning…"
		m.statusOK = true

	case tickMsg:
		if m.scanning {
			m.networks = m.sc.GetNetworks()
			m.clients = m.sc.GetClients()
			m.lastUpdate = time.Now()
		}
		cmds = append(cmds, tick())

	case errMsg:
		m.err = msg
		m.status = fmt.Sprintf("Error: %v", msg)
		m.statusOK = false

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.sc.Stop()
			m.mon.Disable()
			return m, tea.Quit

		case "tab":
			m.currentTab = (m.currentTab + 1) % 4
			m.cursor = 0

		case "1":
			m.currentTab = tabNetworks
			m.cursor = 0
		case "2":
			m.currentTab = tabClients
			m.cursor = 0
		case "3":
			m.currentTab = tabCaptures
			m.cursor = 0
		case "4":
			m.currentTab = tabMACs
			m.cursor = 0

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			maxIdx := m.listLen() - 1
			if m.cursor < maxIdx {
				m.cursor++
			}
		}
	}
	return m, tea.Batch(cmds...)
}

func (m Model) listLen() int {
	switch m.currentTab {
	case tabNetworks:
		return len(m.networks)
	case tabClients:
		return len(m.clients)
	}
	return 0
}

// ──────────────────────────────────────────────
//  View
// ──────────────────────────────────────────────

func (m Model) View() string {
	if m.width == 0 {
		return "Loading…"
	}

	var sb strings.Builder

	// ── Header ──────────────────────────────────
	sb.WriteString(m.renderHeader())
	sb.WriteString("\n")

	// ── Tabs ────────────────────────────────────
	sb.WriteString(m.renderTabs())
	sb.WriteString("\n\n")

	// ── Body ────────────────────────────────────
	switch m.currentTab {
	case tabNetworks:
		sb.WriteString(m.renderNetworksPanel())
	case tabClients:
		sb.WriteString(m.renderClientsPanel())
	case tabCaptures:
		sb.WriteString(styleMuted.Render("  No captures yet. Use: wifiaudit capture handshake --bssid <BSSID> --channel <CH>"))
	case tabMACs:
		sb.WriteString(styleMuted.Render("  MAC management. Use: wifiaudit mac list/add/remove/lookup"))
	}

	// ── Status bar ──────────────────────────────
	sb.WriteString("\n\n")
	sb.WriteString(m.renderStatusBar())

	return sb.String()
}

// ── Header ──────────────────────────────────────────────────────────────────

func (m Model) renderHeader() string {
	title := styleTitle.Render("✦ AIR-LOCKPICK")

	stats := styleMuted.Render(fmt.Sprintf(
		"iface: %s   nets: %d   clients: %d   updated: %s",
		m.iface,
		len(m.networks),
		len(m.clients),
		m.lastUpdate.Format("15:04:05"),
	))

	gap := m.width - lipgloss.Width(title) - lipgloss.Width(stats) - 2
	if gap < 1 {
		gap = 1
	}
	return title + strings.Repeat(" ", gap) + stats
}

// ── Tabs ────────────────────────────────────────────────────────────────────

func (m Model) renderTabs() string {
	labels := []string{"[1] Networks", "[2] Clients", "[3] Captures", "[4] MACs"}
	var parts []string
	for i, lbl := range labels {
		if tab(i) == m.currentTab {
			parts = append(parts, styleTabActive.Render(lbl))
		} else {
			parts = append(parts, styleTabInactive.Render(lbl))
		}
	}
	return strings.Join(parts, "  ")
}

// ── Networks panel (split-view) ─────────────────────────────────────────────

func (m Model) renderNetworksPanel() string {
	leftW := 52
	rightW := m.width - leftW - 5
	if rightW < 30 {
		rightW = 30
	}

	left := m.renderAPList(leftW)
	right := m.renderAPDetail(rightW)

	return lipgloss.JoinHorizontal(lipgloss.Top,
		stylePanel.Width(leftW).Render(left),
		"  ",
		stylePanel.Width(rightW).Render(right),
	)
}

func (m Model) renderAPList(w int) string {
	var sb strings.Builder

	hdr := styleHeader.Render(fmt.Sprintf("%-22s %3s  %-5s  %-4s", "SSID", "CH", "SIG", "ENC"))
	sb.WriteString(hdr + "\n")
	sb.WriteString(styleHeader.Render(strings.Repeat("─", w)) + "\n")

	if len(m.networks) == 0 {
		if m.scanning {
			sb.WriteString(styleMuted.Render(
				fmt.Sprintf("  %s  Scanning…", m.spinner.View())))
		} else {
			sb.WriteString(styleMuted.Render("  No networks found yet"))
		}
		return sb.String()
	}

	bodyH := m.height - 12
	if bodyH < 5 {
		bodyH = 5
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
		if len(ssid) > 20 {
			ssid = ssid[:17] + "…"
		}

		clientCount := ""
		if len(n.Clients) > 0 {
			clientCount = fmt.Sprintf("(%d)", len(n.Clients))
		}

		cursor := "  "
		if i == m.cursor {
			cursor = "▶ "
		}

		line := fmt.Sprintf("%s%-20s %3d  %-5s  %s %s",
			cursor,
			ssid,
			n.Channel,
			signalBars(n.Signal),
			encBadge(n.Encryption),
			styleMuted.Render(clientCount),
		)

		if i == m.cursor {
			sb.WriteString(styleSelected.Width(w).Render(line) + "\n")
		} else {
			sb.WriteString(encStyle(n.Encryption).Render(line) + "\n")
		}
	}
	return sb.String()
}

func (m Model) renderAPDetail(w int) string {
	if len(m.networks) == 0 {
		return styleMuted.Render("  Select a network with ↑↓")
	}
	if m.cursor >= len(m.networks) {
		return ""
	}

	n := m.networks[m.cursor]
	var sb strings.Builder

	ssid := n.SSID
	if ssid == "" {
		ssid = "<hidden>"
	}

	// ── AP detail block ──────────────────────
	sb.WriteString(styleTitle.Render("▸ " + ssid) + "\n")
	sb.WriteString(styleHeader.Render(strings.Repeat("─", w-2)) + "\n")

	field := func(label, value string) string {
		return styleMuted.Render(fmt.Sprintf("  %-12s", label)) +
			styleText.Render(value) + "\n"
	}

	sb.WriteString(field("BSSID", n.BSSID))
	sb.WriteString(field("Channel", fmt.Sprintf("%d", n.Channel)))
	sb.WriteString(field("Signal", fmt.Sprintf("%d dBm  %s", n.Signal, signalBars(n.Signal))))
	sb.WriteString(field("Encryption", encBadgeFull(n.Encryption, n.Cipher)))
	sb.WriteString(field("Vendor", orDash(n.Vendor)))
	sb.WriteString(field("Beacons", fmt.Sprintf("%d", n.Beacons)))
	sb.WriteString(field("First seen", n.FirstSeen.Format("15:04:05")))

	// ── Clients block ────────────────────────
	sb.WriteString("\n")
	clientHeader := fmt.Sprintf("  CLIENTS (%d)", len(n.Clients))
	sb.WriteString(styleTitle.Render(clientHeader) + "\n")
	sb.WriteString(styleHeader.Render(strings.Repeat("─", w-2)) + "\n")

	if len(n.Clients) == 0 {
		sb.WriteString(styleMuted.Render("  No clients detected on this AP\n"))
		sb.WriteString(styleMuted.Render("  Data frames are captured passively\n"))
	} else {
		hdr := styleHeader.Render(fmt.Sprintf("  %-19s %-7s %s", "MAC", "SIGNAL", "VENDOR"))
		sb.WriteString(hdr + "\n")
		for _, c := range n.Clients {
			vendor := c.Vendor
			if vendor == "" {
				vendor = "Unknown"
			}
			line := fmt.Sprintf("  %-19s %-7s %s",
				c.MAC,
				fmt.Sprintf("%ddBm", c.Signal),
				vendor,
			)
			sb.WriteString(styleText.Render(line) + "\n")
		}
	}

	return sb.String()
}

// ── Clients tab (all clients) ────────────────────────────────────────────────

func (m Model) renderClientsPanel() string {
	var sb strings.Builder

	hdr := styleHeader.Render(fmt.Sprintf("  %-19s %-18s %-7s %s",
		"CLIENT MAC", "AP BSSID", "SIGNAL", "VENDOR"))
	sb.WriteString(hdr + "\n")
	sb.WriteString(styleHeader.Render("  " + strings.Repeat("─", m.width-4)) + "\n")

	if len(m.clients) == 0 {
		if m.scanning {
			sb.WriteString(styleMuted.Render(
				fmt.Sprintf("  %s  Listening for client frames…", m.spinner.View())))
		} else {
			sb.WriteString(styleMuted.Render("  No clients found yet"))
		}
		return sb.String()
	}

	bodyH := m.height - 12
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
		line := fmt.Sprintf("  %-19s %-18s %-7s %s",
			c.MAC, bssid, fmt.Sprintf("%ddBm", c.Signal), vendor)

		if i == m.cursor {
			sb.WriteString(styleSelected.Width(m.width - 4).Render(line) + "\n")
		} else {
			sb.WriteString(styleText.Render(line) + "\n")
		}
	}
	return sb.String()
}

// ── Status bar ───────────────────────────────────────────────────────────────

func (m Model) renderStatusBar() string {
	var dot string
	if m.statusOK {
		dot = lipgloss.NewStyle().Foreground(clrGreen).Render("●")
	} else {
		dot = lipgloss.NewStyle().Foreground(clrRed).Render("●")
	}

	status := styleMuted.Render(m.status)
	keys := styleMuted.Render("  q:quit  tab:next-tab  ↑↓/jk:navigate")

	return dot + " " + status + "   " + keys
}

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────

func signalBars(dbm int) string {
	var bars int
	switch {
	case dbm >= -50:
		bars = 5
	case dbm >= -60:
		bars = 4
	case dbm >= -70:
		bars = 3
	case dbm >= -80:
		bars = 2
	default:
		bars = 1
	}
	filled := strings.Repeat("█", bars)
	empty := strings.Repeat("░", 5-bars)

	var color lipgloss.Color
	switch bars {
	case 5, 4:
		color = clrGreen
	case 3:
		color = clrYellow
	case 2:
		color = clrOrange
	default:
		color = clrRed
	}
	return lipgloss.NewStyle().Foreground(color).Render(filled + empty)
}

func encBadge(enc string) string {
	switch enc {
	case "OPN":
		return styleBadgeOPN.Render("OPN ")
	case "WEP":
		return styleBadgeWEP.Render("WEP ")
	case "WPA":
		return styleBadgeWPA.Render("WPA ")
	case "WPA2":
		return styleBadgeWPA2.Render("WPA2")
	case "WPA3":
		return styleBadgeWPA3.Render("WPA3")
	default:
		return styleMuted.Render("????")
	}
}

func encBadgeFull(enc, cipher string) string {
	badge := encBadge(enc)
	if cipher != "" {
		badge += styleMuted.Render(" / "+cipher)
	}
	return badge
}

func encStyle(enc string) lipgloss.Style {
	switch enc {
	case "OPN":
		return lipgloss.NewStyle().Foreground(clrRed)
	case "WEP":
		return lipgloss.NewStyle().Foreground(clrOrange)
	case "WPA":
		return lipgloss.NewStyle().Foreground(clrYellow)
	default:
		return lipgloss.NewStyle().Foreground(clrText)
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ──────────────────────────────────────────────
//  Entry point
// ──────────────────────────────────────────────

func Run(iface string) error {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(clrAccent)

	mon := monitor.New(iface)
	sc := scanner.New(mon.MonitorIface())

	m := Model{
		iface:      iface,
		mon:        mon,
		sc:         sc,
		networks:   []scanner.Network{},
		clients:    []scanner.Client{},
		status:     "Initializing…",
		statusOK:   true,
		lastUpdate: time.Now(),
		spinner:    sp,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
