package cmd

import (
	"fmt"

	"github.com/auditteam/wifiaudit/internal/capture"
	"github.com/auditteam/wifiaudit/internal/monitor"
	"github.com/spf13/cobra"
)

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture handshakes and manage deauth attacks",
}

var captureHandshakeCmd = &cobra.Command{
	Use:   "handshake",
	Short: "Capture WPA/WPA2 handshake from a target AP",
	Long: `Captures the 4-way handshake by listening passively or triggering
deauth frames to force reconnections. For authorized testing only.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		bssid, _ := cmd.Flags().GetString("bssid")
		ssid, _ := cmd.Flags().GetString("ssid")
		channel, _ := cmd.Flags().GetInt("channel")
		client, _ := cmd.Flags().GetString("client")
		outputDir, _ := cmd.Flags().GetString("output-dir")
		deauth, _ := cmd.Flags().GetBool("deauth")
		deauthCount, _ := cmd.Flags().GetInt("deauth-count")

		if bssid == "" {
			return fmt.Errorf("--bssid is required")
		}
		if channel == 0 {
			return fmt.Errorf("--channel is required")
		}

		m := monitor.New(iface)
		if err := m.Enable(); err != nil {
			return fmt.Errorf("monitor mode required: %w", err)
		}
		defer m.Disable()

		if err := m.SetChannel(channel); err != nil {
			return fmt.Errorf("failed to set channel %d: %w", channel, err)
		}

		monIface := m.MonitorIface()
		cap := capture.New(monIface, outputDir)

		fmt.Printf("[*] Target BSSID : %s\n", bssid)
		if ssid != "" {
			fmt.Printf("[*] Target SSID  : %s\n", ssid)
		}
		fmt.Printf("[*] Channel      : %d\n", channel)
		if client != "" {
			fmt.Printf("[*] Client MAC   : %s\n", client)
		}
		fmt.Printf("[*] Output Dir   : %s\n", outputDir)

		if deauth {
			fmt.Printf("[*] Deauth mode  : %d frames\n", deauthCount)
			fmt.Println("[!] Sending deauth frames (authorized use only)...")
			if err := cap.SendDeauth(bssid, client, deauthCount); err != nil {
				fmt.Printf("[-] Deauth error: %v\n", err)
			}
		}

		fmt.Println("[*] Listening for handshake (Ctrl+C to stop)...")
		outFile, err := cap.CaptureHandshake(bssid, ssid)
		if err != nil {
			return fmt.Errorf("capture failed: %w", err)
		}

		fmt.Printf("\n[+] Handshake captured! Saved to: %s\n", outFile)
		return nil
	},
}

var captureDeauthCmd = &cobra.Command{
	Use:   "deauth",
	Short: "Send deauthentication frames to a target",
	Long:  `Sends 802.11 deauthentication frames. AUTHORIZED USE ONLY.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		bssid, _ := cmd.Flags().GetString("bssid")
		client, _ := cmd.Flags().GetString("client")
		count, _ := cmd.Flags().GetInt("count")
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
		cap := capture.New(monIface, "")

		target := client
		if target == "" {
			target = "FF:FF:FF:FF:FF:FF (broadcast)"
		}

		fmt.Printf("[!] Sending %d deauth frames to %s via AP %s\n", count, target, bssid)
		fmt.Println("[!] AUTHORIZED USE ONLY - Disrupting networks is illegal without permission")

		if err := cap.SendDeauth(bssid, client, count); err != nil {
			return fmt.Errorf("deauth failed: %w", err)
		}

		fmt.Println("[+] Deauth frames sent")
		return nil
	},
}

func init() {
	captureHandshakeCmd.Flags().String("bssid", "", "Target AP BSSID (required)")
	captureHandshakeCmd.Flags().String("ssid", "", "Target AP SSID (optional, for filename)")
	captureHandshakeCmd.Flags().Int("channel", 0, "Target channel (required)")
	captureHandshakeCmd.Flags().String("client", "", "Specific client MAC (optional, deauths all if empty)")
	captureHandshakeCmd.Flags().String("output-dir", "data/captures", "Directory to save captures")
	captureHandshakeCmd.Flags().Bool("deauth", false, "Send deauth frames to force handshake")
	captureHandshakeCmd.Flags().Int("deauth-count", 5, "Number of deauth frames to send")

	captureDeauthCmd.Flags().String("bssid", "", "Target AP BSSID (required)")
	captureDeauthCmd.Flags().String("client", "", "Specific client MAC (optional)")
	captureDeauthCmd.Flags().Int("count", 10, "Number of deauth frames to send")
	captureDeauthCmd.Flags().Int("channel", 0, "Target channel")

	captureCmd.AddCommand(captureHandshakeCmd)
	captureCmd.AddCommand(captureDeauthCmd)
}
