package cmd

import (
	"fmt"

	"github.com/auditteam/wifiaudit/internal/reports"
	"github.com/auditteam/wifiaudit/internal/session"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate audit reports from session data",
}

var reportGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a report from a session file",
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionFile, _ := cmd.Flags().GetString("session")
		format, _ := cmd.Flags().GetString("format")
		outputDir, _ := cmd.Flags().GetString("output-dir")
		auditorName, _ := cmd.Flags().GetString("auditor")
		orgName, _ := cmd.Flags().GetString("org")

		if sessionFile == "" {
			return fmt.Errorf("--session is required")
		}

		sess, err := session.LoadFromFile(sessionFile)
		if err != nil {
			return fmt.Errorf("failed to load session: %w", err)
		}

		gen := reports.NewGenerator(outputDir)
		gen.SetMeta(auditorName, orgName)

		var outFile string

		switch format {
		case "json":
			outFile, err = gen.GenerateJSON(sess)
		case "html":
			outFile, err = gen.GenerateHTML(sess)
		case "txt":
			outFile, err = gen.GenerateTXT(sess)
		default:
			return fmt.Errorf("unsupported format: %s (use json, html, txt)", format)
		}

		if err != nil {
			return fmt.Errorf("report generation failed: %w", err)
		}

		fmt.Printf("[+] Report generated: %s\n", outFile)
		return nil
	},
}

var reportSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Print a quick summary of a session",
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionFile, _ := cmd.Flags().GetString("session")
		if sessionFile == "" {
			return fmt.Errorf("--session is required")
		}

		sess, err := session.LoadFromFile(sessionFile)
		if err != nil {
			return fmt.Errorf("failed to load session: %w", err)
		}

		fmt.Println("\n═══════════════════════════════════════════")
		fmt.Printf("  AUDIT SESSION SUMMARY\n")
		fmt.Println("═══════════════════════════════════════════")
		fmt.Printf("  Session ID   : %s\n", sess.ID)
		fmt.Printf("  Started      : %s\n", sess.StartTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Interface    : %s\n", sess.Interface)
		fmt.Printf("  Networks     : %d\n", len(sess.Networks))
		fmt.Printf("  Clients      : %d\n", sess.TotalClients())
		fmt.Printf("  Captures     : %d\n", len(sess.Captures))
		fmt.Println("───────────────────────────────────────────")

		// Encryption breakdown
		enc := sess.EncryptionStats()
		fmt.Println("  Encryption Breakdown:")
		for k, v := range enc {
			fmt.Printf("    %-12s : %d networks\n", k, v)
		}
		fmt.Println("═══════════════════════════════════════════\n")
		return nil
	},
}

func init() {
	reportGenerateCmd.Flags().String("session", "", "Session file path (required)")
	reportGenerateCmd.Flags().String("format", "html", "Output format: json, html, txt")
	reportGenerateCmd.Flags().String("output-dir", "data/reports", "Output directory")
	reportGenerateCmd.Flags().String("auditor", "", "Auditor name for the report")
	reportGenerateCmd.Flags().String("org", "", "Organization/client name")

	reportSummaryCmd.Flags().String("session", "", "Session file path (required)")

	reportCmd.AddCommand(reportGenerateCmd)
	reportCmd.AddCommand(reportSummaryCmd)
}
