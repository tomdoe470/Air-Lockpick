package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/auditteam/wifiaudit/internal/monitor"
	"github.com/auditteam/wifiaudit/internal/scanner"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#58a6ff")).
			PaddingLeft(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8b949e")).
			Bold(true)

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#21262d")).
			Foreground(lipgloss.Color("#79c0ff"))

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#c9d1d9"))

	dangerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff7b72"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#56d364"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffa657"))

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#30363d")).
			Padding(0, 1)
)

type tab int

const (
	tabNetworks tab = iota
	tabClients
	tabCaptures
	tabMACs
)

// Model is the main TUI model
type Model struct {
	iface       string
	scanner     *scanner.Scanner
	monitor     *monitor.Manager
	networks    []scanner.Network
	clients     []scanner.Client
	currentTab  tab
	cursor      int
	width       int
	height      int
	scanning    bool
	status      string
	statusColor string
	lastUpdate  time.Time
	logs        []string
	err         error
}

type tickMsg time.Time
type networksMsg []scanner.Network
type clientsMsg []scanner.Client
type statusMsg struct {
	text  string
	color string
}
type errMsg error

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(), m.startScan())
}

func (m Model) startScan() tea.Cmd {
	return func() tea.Msg {
		if err := m.monitor.Enable(); err != nil {
			return errMsg(err)
		}
		go m.scanner.ScanNetworks([]int{})
		return statusMsg{text: "Scanning...", color: "green"}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		if m.scanning {
			m.networks = m.scanner.GetNetworks()
			m.clients = m.scanner.GetClients()
			m.lastUpdate = time.Now()
		}
		return m, tick()

	case statusMsg:
		m.status = msg.text
		m.statusColor = msg.color
		m.scanning = true
		return m, nil

	case errMsg:
		m.err = msg
		m.status = fmt.Sprintf("Error: %v", msg)
		m.statusColor = "red"
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.scanner.Stop()
			m.monitor.Disable()
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
			m.cursor++
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var sb strings.Builder

	// Header
	sb.WriteString(titleStyle.Render("▶ WIFIAUDIT  ") +
		headerStyle.Render(fmt.Sprintf("Interface: %s  |  Networks: %d  |  Clients: %d  |  Updated: %s",
			m.iface,
			len(m.networks),
			len(m.clients),
			m.lastUpdate.Format("15:04:05"),
		)) + "\n\n")

	// Tabs
	tabs := []string{"[1] Networks", "[2] Clients", "[3] Captures", "[4] MACs"}
	for i, t := range tabs {
		if tab(i) == m.currentTab {
			sb.WriteString(selectedStyle.Render(" " + t + " "))
		} else {
			sb.WriteString(normalStyle.Render(" " + t + " "))
		}
		sb.WriteString("  ")
	}
	sb.WriteString("\n\n")

	// Tab content
	switch m.currentTab {
	case tabNetworks:
		sb.WriteString(m.renderNetworks())
	case tabClients:
		sb.WriteString(m.renderClients())
	case tabCaptures:
		sb.WriteString("  No captures yet. Use [capture] commands.\n")
	case tabMACs:
		sb.WriteString("  MAC management. Use [mac] commands.\n")
	}

	// Status bar
	sb.WriteString("\n\n")
	statusText := m.status
	switch m.statusColor {
	case "green":
		sb.WriteString(successStyle.Render("● ") + normalStyle.Render(statusText))
	case "red":
		sb.WriteString(dangerStyle.Render("● ") + dangerStyle.Render(statusText))
	default:
		sb.WriteString(warnStyle.Render("● ") + normalStyle.Render(statusText))
	}

	sb.WriteString(headerStyle.Render("  │  q:quit  tab:switch  ↑↓:navigate"))

	return sb.String()
}

func (m Model) renderNetworks() string {
	if len(m.networks) == 0 {
		return warnStyle.Render("  No networks found yet. Scanning...\n")
	}

	var sb strings.Builder
	header := fmt.Sprintf("  %-22s %-18s %-4s %-7s %-8s %s\n",
		"SSID", "BSSID", "CH", "SIGNAL", "ENC", "VENDOR")
	sb.WriteString(headerStyle.Render(header))
	sb.WriteString(headerStyle.Render("  " + strings.Repeat("─", 80) + "\n"))

	for i, n := range m.networks {
		ssid := n.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		if len(ssid) > 20 {
			ssid = ssid[:17] + "..."
		}

		line := fmt.Sprintf("  %-22s %-18s %-4d %-7d %-8s %s",
			ssid, n.BSSID, n.Channel, n.Signal, n.Encryption, n.Vendor)

		if i == m.cursor {
			sb.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			encColor := normalStyle
			switch n.Encryption {
			case "OPN":
				encColor = dangerStyle
			case "WEP":
				encColor = warnStyle
			}
			sb.WriteString(encColor.Render(line) + "\n")
		}
	}
	return sb.String()
}

func (m Model) renderClients() string {
	if len(m.clients) == 0 {
		return warnStyle.Render("  No clients found yet. Scanning...\n")
	}

	var sb strings.Builder
	header := fmt.Sprintf("  %-18s %-18s %-8s %s\n",
		"CLIENT MAC", "AP BSSID", "SIGNAL", "VENDOR")
	sb.WriteString(headerStyle.Render(header))
	sb.WriteString(headerStyle.Render("  " + strings.Repeat("─", 65) + "\n"))

	for i, c := range m.clients {
		line := fmt.Sprintf("  %-18s %-18s %-8d %s",
			c.MAC, c.BSSID, c.Signal, c.Vendor)

		if i == m.cursor {
			sb.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			sb.WriteString(normalStyle.Render(line) + "\n")
		}
	}
	return sb.String()
}

// Run launches the TUI
func Run(iface string) error {
	mon := monitor.New(iface)
	sc := scanner.New(mon.MonitorIface())

	m := Model{
		iface:       iface,
		monitor:     mon,
		scanner:     sc,
		networks:    []scanner.Network{},
		clients:     []scanner.Client{},
		status:      "Initializing...",
		statusColor: "yellow",
		lastUpdate:  time.Now(),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
