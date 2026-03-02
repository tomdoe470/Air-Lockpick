package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const banner = `
██╗    ██╗██╗███████╗██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
██║    ██║██║██╔════╝██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██║ █╗ ██║██║█████╗  ██║███████║██║   ██║██║  ██║██║   ██║   
██║███╗██║██║██╔══╝  ██║██╔══██║██║   ██║██║  ██║██║   ██║   
╚███╔███╔╝██║██║     ██║██║  ██║╚██████╔╝██████╔╝██║   ██║   
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   

  Professional WiFi Audit Framework | v1.0.0
  Use responsibly and only on authorized networks
`

var (
	iface   string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "wifiaudit",
	Short: "Professional WiFi Reconnaissance & Audit Framework",
	Long:  banner,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(banner)
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&iface, "interface", "i", "wlan0", "Wireless interface to use")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(macCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(sessionCmd)
	rootCmd.AddCommand(tuiCmd)
}
