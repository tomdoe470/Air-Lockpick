package monitor

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Manager handles wireless interface mode management
type Manager struct {
	iface       string
	monitorIface string
	hopping     bool
	stopHop     chan struct{}
}

func New(iface string) *Manager {
	return &Manager{
		iface:       iface,
		monitorIface: iface + "mon",
		stopHop:     make(chan struct{}),
	}
}

// MonitorIface returns the name of the monitor interface
func (m *Manager) MonitorIface() string {
	return m.monitorIface
}

// Enable puts the interface in monitor mode using airmon-ng or iw
func (m *Manager) Enable() error {
	// Try airmon-ng first (preferred for full compatibility)
	if path, err := exec.LookPath("airmon-ng"); err == nil {
		out, err := exec.Command(path, "start", m.iface).CombinedOutput()
		if err != nil {
			return fmt.Errorf("airmon-ng failed: %s", string(out))
		}
		// airmon-ng may rename interface to wlan0mon
		if strings.Contains(string(out), m.iface+"mon") {
			m.monitorIface = m.iface + "mon"
		}
		return nil
	}

	// Fallback: use iw and ip commands
	cmds := [][]string{
		{"ip", "link", "set", m.iface, "down"},
		{"iw", m.iface, "set", "monitor", "none"},
		{"ip", "link", "set", m.iface, "up"},
	}

	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("command %v failed: %s", args, string(out))
		}
	}

	m.monitorIface = m.iface
	return nil
}

// Disable restores the interface to managed mode
func (m *Manager) Disable() error {
	if m.hopping {
		m.StopChannelHop()
	}

	if path, err := exec.LookPath("airmon-ng"); err == nil {
		exec.Command(path, "stop", m.monitorIface).Run()
		return nil
	}

	cmds := [][]string{
		{"ip", "link", "set", m.iface, "down"},
		{"iw", m.iface, "set", "type", "managed"},
		{"ip", "link", "set", m.iface, "up"},
	}

	for _, args := range cmds {
		exec.Command(args[0], args[1:]...).Run()
	}
	return nil
}

// GetMode returns the current mode of the interface
func (m *Manager) GetMode() (string, error) {
	out, err := exec.Command("iw", m.iface, "info").Output()
	if err != nil {
		return "", fmt.Errorf("iw info failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "type ") {
			return strings.TrimPrefix(line, "type "), nil
		}
	}
	return "unknown", nil
}

// SetChannel sets a specific channel on the interface
func (m *Manager) SetChannel(ch int) error {
	out, err := exec.Command("iw", m.monitorIface, "set", "channel", fmt.Sprintf("%d", ch)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set channel %d: %s", ch, string(out))
	}
	return nil
}

// StartChannelHop begins cycling through channels
func (m *Manager) StartChannelHop(intervalMs int) error {
	if intervalMs <= 0 {
		intervalMs = 500
	}

	// 2.4GHz channels 1-14, 5GHz common channels
	channels24 := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	channels5 := []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165}
	allChannels := append(channels24, channels5...)

	m.hopping = true
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)

	go func() {
		idx := 0
		for {
			select {
			case <-m.stopHop:
				ticker.Stop()
				return
			case <-ticker.C:
				m.SetChannel(allChannels[idx%len(allChannels)])
				idx++
			}
		}
	}()

	// Block until interrupted
	<-m.stopHop
	return nil
}

// StopChannelHop stops the channel hopping goroutine
func (m *Manager) StopChannelHop() {
	if m.hopping {
		m.stopHop <- struct{}{}
		m.hopping = false
	}
}

// KillInterfering kills processes that might interfere with monitor mode
func (m *Manager) KillInterfering() error {
	if path, err := exec.LookPath("airmon-ng"); err == nil {
		exec.Command(path, "check", "kill").Run()
		return nil
	}
	// Manually kill common interfering processes
	for _, proc := range []string{"wpa_supplicant", "dhclient", "NetworkManager"} {
		exec.Command("pkill", "-f", proc).Run()
	}
	return nil
}
