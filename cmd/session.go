package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/auditteam/wifiaudit/internal/session"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage audit sessions",
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		sessDir := "data/sessions"
		files, err := filepath.Glob(filepath.Join(sessDir, "*.json"))
		if err != nil || len(files) == 0 {
			fmt.Println("[*] No sessions found in", sessDir)
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SESSION ID\tDATE\tINTERFACE\tNETWORKS\tCLIENTS\tFILE")
		fmt.Fprintln(w, "──────────\t────\t─────────\t────────\t───────\t────")
		for _, f := range files {
			sess, err := session.LoadFromFile(f)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
				sess.ID,
				sess.StartTime.Format("2006-01-02 15:04"),
				sess.Interface,
				len(sess.Networks),
				sess.TotalClients(),
				filepath.Base(f),
			)
		}
		w.Flush()
		return nil
	},
}

var sessionNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new empty session",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		sess := session.New()
		sess.Interface = iface
		if name != "" {
			sess.Name = name
		}

		filename := fmt.Sprintf("data/sessions/session_%s_%s.json",
			time.Now().Format("20060102_150405"), sess.ID[:8])

		if err := sess.SaveToFile(filename); err != nil {
			return err
		}
		fmt.Printf("[+] Session created: %s\n", filename)
		fmt.Printf("[+] Session ID: %s\n", sess.ID)
		return nil
	},
}

var sessionMergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merge multiple session files into one",
	RunE: func(cmd *cobra.Command, args []string) error {
		files, _ := cmd.Flags().GetStringSlice("files")
		output, _ := cmd.Flags().GetString("output")

		if len(files) < 2 {
			return fmt.Errorf("at least 2 --files required to merge")
		}
		if output == "" {
			return fmt.Errorf("--output is required")
		}

		merged := session.New()
		for _, f := range files {
			sess, err := session.LoadFromFile(f)
			if err != nil {
				fmt.Printf("[-] Skipping %s: %v\n", f, err)
				continue
			}
			merged.Merge(sess)
			fmt.Printf("[*] Merged: %s (%d networks)\n", f, len(sess.Networks))
		}

		if err := merged.SaveToFile(output); err != nil {
			return err
		}
		fmt.Printf("[+] Merged session saved to: %s\n", output)
		fmt.Printf("[+] Total networks: %d\n", len(merged.Networks))
		return nil
	},
}

func init() {
	sessionNewCmd.Flags().String("name", "", "Optional session name/label")
	sessionMergeCmd.Flags().StringSlice("files", []string{}, "Session files to merge (required)")
	sessionMergeCmd.Flags().String("output", "", "Output file path (required)")

	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionNewCmd)
	sessionCmd.AddCommand(sessionMergeCmd)
}
