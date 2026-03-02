package cmd

import (
	"fmt"

	"github.com/auditteam/wifiaudit/internal/macs"
	"github.com/spf13/cobra"
)

var macCmd = &cobra.Command{
	Use:   "mac",
	Short: "Manage MAC address lists (whitelist/blacklist/known)",
}

var macListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all MACs in a specific list",
	RunE: func(cmd *cobra.Command, args []string) error {
		listType, _ := cmd.Flags().GetString("type")
		m := macs.NewManager("data/macs")
		entries, err := m.List(listType)
		if err != nil {
			return err
		}
		fmt.Printf("[*] MAC List: %s (%d entries)\n\n", listType, len(entries))
		fmt.Printf("%-20s %-18s %-20s %s\n", "MAC", "VENDOR", "LABEL", "NOTES")
		fmt.Println("────────────────────────────────────────────────────────────────")
		for _, e := range entries {
			fmt.Printf("%-20s %-18s %-20s %s\n", e.MAC, e.Vendor, e.Label, e.Notes)
		}
		return nil
	},
}

var macAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a MAC to a list",
	RunE: func(cmd *cobra.Command, args []string) error {
		listType, _ := cmd.Flags().GetString("type")
		macAddr, _ := cmd.Flags().GetString("mac")
		label, _ := cmd.Flags().GetString("label")
		notes, _ := cmd.Flags().GetString("notes")

		if macAddr == "" {
			return fmt.Errorf("--mac is required")
		}

		m := macs.NewManager("data/macs")
		entry := macs.Entry{
			MAC:   macAddr,
			Label: label,
			Notes: notes,
		}
		if err := m.Add(listType, entry); err != nil {
			return err
		}
		fmt.Printf("[+] MAC %s added to %s list\n", macAddr, listType)
		return nil
	},
}

var macRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a MAC from a list",
	RunE: func(cmd *cobra.Command, args []string) error {
		listType, _ := cmd.Flags().GetString("type")
		macAddr, _ := cmd.Flags().GetString("mac")
		if macAddr == "" {
			return fmt.Errorf("--mac is required")
		}
		m := macs.NewManager("data/macs")
		if err := m.Remove(listType, macAddr); err != nil {
			return err
		}
		fmt.Printf("[+] MAC %s removed from %s list\n", macAddr, listType)
		return nil
	},
}

var macLookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Lookup a MAC address vendor and list membership",
	RunE: func(cmd *cobra.Command, args []string) error {
		macAddr, _ := cmd.Flags().GetString("mac")
		if macAddr == "" {
			return fmt.Errorf("--mac is required")
		}
		m := macs.NewManager("data/macs")
		info := m.Lookup(macAddr)
		fmt.Printf("[*] MAC Address : %s\n", macAddr)
		fmt.Printf("[*] Vendor      : %s\n", info.Vendor)
		fmt.Printf("[*] In Whitelist: %v\n", info.InWhitelist)
		fmt.Printf("[*] In Blacklist: %v\n", info.InBlacklist)
		fmt.Printf("[*] Known Device: %v\n", info.InKnown)
		if info.Label != "" {
			fmt.Printf("[*] Label       : %s\n", info.Label)
		}
		return nil
	},
}

var macImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import MACs from a file (CSV or txt)",
	RunE: func(cmd *cobra.Command, args []string) error {
		listType, _ := cmd.Flags().GetString("type")
		file, _ := cmd.Flags().GetString("file")
		if file == "" {
			return fmt.Errorf("--file is required")
		}
		m := macs.NewManager("data/macs")
		count, err := m.ImportFile(listType, file)
		if err != nil {
			return err
		}
		fmt.Printf("[+] Imported %d MAC entries into %s list\n", count, listType)
		return nil
	},
}

func init() {
	listTypes := "whitelist, blacklist, known, targets"

	macListCmd.Flags().String("type", "known", "List type: "+listTypes)
	macAddCmd.Flags().String("type", "known", "List type: "+listTypes)
	macAddCmd.Flags().String("mac", "", "MAC address (required)")
	macAddCmd.Flags().String("label", "", "Human-readable label")
	macAddCmd.Flags().String("notes", "", "Additional notes")
	macRemoveCmd.Flags().String("type", "known", "List type: "+listTypes)
	macRemoveCmd.Flags().String("mac", "", "MAC address (required)")
	macLookupCmd.Flags().String("mac", "", "MAC address to lookup (required)")
	macImportCmd.Flags().String("type", "known", "List type: "+listTypes)
	macImportCmd.Flags().String("file", "", "Path to import file (CSV or txt)")

	macCmd.AddCommand(macListCmd)
	macCmd.AddCommand(macAddCmd)
	macCmd.AddCommand(macRemoveCmd)
	macCmd.AddCommand(macLookupCmd)
	macCmd.AddCommand(macImportCmd)
}
