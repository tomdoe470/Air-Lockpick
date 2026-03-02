package cmd

import (
	"fmt"

	"github.com/auditteam/wifiaudit/internal/monitor"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Manage monitor mode on wireless interface",
}

var monitorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Enable monitor mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		m := monitor.New(iface)
		fmt.Printf("[*] Enabling monitor mode on %s...\n", iface)
		if err := m.Enable(); err != nil {
			return fmt.Errorf("failed to enable monitor mode: %w", err)
		}
		fmt.Printf("[+] Monitor mode enabled: %s\n", m.MonitorIface())
		return nil
	},
}

var monitorStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Disable monitor mode and restore managed mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		m := monitor.New(iface)
		fmt.Printf("[*] Disabling monitor mode on %s...\n", iface)
		if err := m.Disable(); err != nil {
			return fmt.Errorf("failed to disable monitor mode: %w", err)
		}
		fmt.Printf("[+] Interface restored to managed mode: %s\n", iface)
		return nil
	},
}

var monitorStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current interface mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		m := monitor.New(iface)
		mode, err := m.GetMode()
		if err != nil {
			return err
		}
		fmt.Printf("[*] Interface %s is in mode: %s\n", iface, mode)
		return nil
	},
}

var monitorHopCmd = &cobra.Command{
	Use:   "hop",
	Short: "Start channel hopping",
	RunE: func(cmd *cobra.Command, args []string) error {
		m := monitor.New(iface)
		interval, _ := cmd.Flags().GetInt("interval")
		fmt.Printf("[*] Starting channel hopping on %s (interval: %dms)...\n", iface, interval)
		return m.StartChannelHop(interval)
	},
}

func init() {
	monitorCmd.AddCommand(monitorStartCmd)
	monitorCmd.AddCommand(monitorStopCmd)
	monitorCmd.AddCommand(monitorStatusCmd)
	monitorCmd.AddCommand(monitorHopCmd)
	monitorHopCmd.Flags().Int("interval", 500, "Channel hop interval in milliseconds")
}
