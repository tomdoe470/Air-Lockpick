package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/auditteam/wifiaudit/internal/monitor"
	"github.com/auditteam/wifiaudit/internal/scanner"
	"github.com/auditteam/wifiaudit/internal/session"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for WiFi networks and clients",
}

var scanNetworksCmd = &cobra.Command{
	Use:   "networks",
	Short: "Passive scan for access points (APs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		duration, _ := cmd.Flags().GetInt("duration")
		outputFile, _ := cmd.Flags().GetString("output")
		channels, _ := cmd.Flags().GetIntSlice("channels")

		m := monitor.New(iface)
		if err := m.Enable(); err != nil {
			return fmt.Errorf("monitor mode required: %w", err)
		}
		defer m.Disable()

		monIface := m.MonitorIface()
		sc := scanner.New(monIface)

		fmt.Printf("[*] Scanning for networks on %s", monIface)
		if len(channels) > 0 {
			fmt.Printf(" (channels: %v)", channels)
		}
		fmt.Println()
		fmt.Printf("[*] Duration: %d seconds (Ctrl+C to stop early)\n\n", duration)

		sess := session.New()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go sc.ScanNetworks(channels)

		ticker := time.NewTicker(time.Duration(duration) * time.Second)
		defer ticker.Stop()

		select {
		case <-ticker.C:
		case <-sigCh:
			fmt.Println("\n[*] Scan interrupted by user")
		}

		sc.Stop()
		networks := sc.GetNetworks()

		fmt.Printf("\n[+] Found %d networks:\n\n", len(networks))
		printNetworkTable(networks)

		sess.AddNetworks(networks)

		if outputFile != "" {
			if err := sess.SaveToFile(outputFile); err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}
			fmt.Printf("\n[+] Session saved to: %s\n", outputFile)
		}
		return nil
	},
}

var scanClientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "Scan for connected clients on a specific BSSID",
	RunE: func(cmd *cobra.Command, args []string) error {
		bssid, _ := cmd.Flags().GetString("bssid")
		duration, _ := cmd.Flags().GetInt("duration")
		channel, _ := cmd.Flags().GetInt("channel")

		if bssid == "" {
			return fmt.Errorf("--bssid is required")
		}

		m := monitor.New(iface)
		if err := m.Enable(); err != nil {
			return fmt.Errorf("monitor mode required: %w", err)
		}
		defer m.Disable()

		if channel > 0 {
			m.SetChannel(channel)
		}

		monIface := m.MonitorIface()
		sc := scanner.New(monIface)

		fmt.Printf("[*] Scanning clients on BSSID: %s\n", bssid)
		go sc.ScanClients(bssid)

		time.Sleep(time.Duration(duration) * time.Second)
		sc.Stop()

		clients := sc.GetClients()
		fmt.Printf("\n[+] Found %d clients:\n\n", len(clients))
		printClientTable(clients)
		return nil
	},
}

func printNetworkTable(networks []scanner.Network) {
	fmt.Printf("%-20s %-18s %-6s %-8s %-12s %s\n",
		"SSID", "BSSID", "CH", "SIGNAL", "ENC", "VENDOR")
	fmt.Println("─────────────────────────────────────────────────────────────────────")
	for _, n := range networks {
		ssid := n.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		if len(ssid) > 18 {
			ssid = ssid[:15] + "..."
		}
		fmt.Printf("%-20s %-18s %-6d %-8d %-12s %s\n",
			ssid, n.BSSID, n.Channel, n.Signal, n.Encryption, n.Vendor)
	}
}

func printClientTable(clients []scanner.Client) {
	fmt.Printf("%-18s %-18s %-8s %s\n", "CLIENT MAC", "AP BSSID", "SIGNAL", "VENDOR")
	fmt.Println("──────────────────────────────────────────────────────────")
	for _, c := range clients {
		fmt.Printf("%-18s %-18s %-8d %s\n", c.MAC, c.BSSID, c.Signal, c.Vendor)
	}
}

func init() {
	scanNetworksCmd.Flags().Int("duration", 30, "Scan duration in seconds")
	scanNetworksCmd.Flags().String("output", "", "Save results to session file")
	scanNetworksCmd.Flags().IntSlice("channels", []int{}, "Specific channels to scan (default: all)")

	scanClientsCmd.Flags().String("bssid", "", "Target AP BSSID (required)")
	scanClientsCmd.Flags().Int("duration", 30, "Scan duration in seconds")
	scanClientsCmd.Flags().Int("channel", 0, "Lock to specific channel")

	scanCmd.AddCommand(scanNetworksCmd)
	scanCmd.AddCommand(scanClientsCmd)
}
