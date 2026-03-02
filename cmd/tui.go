package cmd

import (
	"fmt"

	"github.com/auditteam/wifiaudit/internal/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch interactive Terminal UI dashboard",
	Long: `Launch the interactive TUI dashboard for real-time monitoring.
Provides a full-screen terminal interface with live network scanning,
client tracking, and session management.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("[*] Launching TUI dashboard...")
		return tui.Run(iface)
	},
}
