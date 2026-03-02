package macs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ouidb "github.com/auditteam/wifiaudit/internal/oui"
)

// Entry represents a MAC address entry in a list
type Entry struct {
	MAC    string `json:"mac"`
	Vendor string `json:"vendor,omitempty"`
	Label  string `json:"label,omitempty"`
	Notes  string `json:"notes,omitempty"`
}

// LookupResult contains all info about a MAC address
type LookupResult struct {
	MAC         string
	Vendor      string
	InWhitelist bool
	InBlacklist bool
	InKnown     bool
	InTargets   bool
	Label       string
	Notes       string
}

// Manager handles MAC address lists
type Manager struct {
	baseDir string
}

func NewManager(baseDir string) *Manager {
	os.MkdirAll(baseDir, 0755)
	// Ensure list files exist
	for _, listType := range []string{"whitelist", "blacklist", "known", "targets"} {
		path := filepath.Join(baseDir, listType+".json")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			os.WriteFile(path, []byte("[]"), 0644)
		}
	}
	return &Manager{baseDir: baseDir}
}

// List returns all entries in a specific list
func (m *Manager) List(listType string) ([]Entry, error) {
	if err := m.validateListType(listType); err != nil {
		return nil, err
	}
	return m.loadList(listType)
}

// Add adds a MAC entry to a list
func (m *Manager) Add(listType string, entry Entry) error {
	if err := m.validateListType(listType); err != nil {
		return err
	}

	entries, err := m.loadList(listType)
	if err != nil {
		return err
	}

	// Normalize MAC
	entry.MAC = strings.ToUpper(entry.MAC)

	// Check for duplicates
	for _, e := range entries {
		if strings.EqualFold(e.MAC, entry.MAC) {
			return fmt.Errorf("MAC %s already exists in %s list", entry.MAC, listType)
		}
	}

	// Auto-lookup vendor if not set
	if entry.Vendor == "" {
		entry.Vendor = ouidb.Lookup(entry.MAC)
	}

	entries = append(entries, entry)
	return m.saveList(listType, entries)
}

// Remove removes a MAC from a list
func (m *Manager) Remove(listType, mac string) error {
	if err := m.validateListType(listType); err != nil {
		return err
	}

	entries, err := m.loadList(listType)
	if err != nil {
		return err
	}

	mac = strings.ToUpper(mac)
	filtered := make([]Entry, 0, len(entries))
	found := false
	for _, e := range entries {
		if strings.EqualFold(e.MAC, mac) {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}

	if !found {
		return fmt.Errorf("MAC %s not found in %s list", mac, listType)
	}

	return m.saveList(listType, filtered)
}

// Lookup checks a MAC across all lists and returns its info
func (m *Manager) Lookup(mac string) LookupResult {
	mac = strings.ToUpper(mac)
	result := LookupResult{
		MAC:    mac,
		Vendor: ouidb.Lookup(mac),
	}

	for _, listType := range []string{"whitelist", "blacklist", "known", "targets"} {
		entries, err := m.loadList(listType)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.EqualFold(e.MAC, mac) {
				switch listType {
				case "whitelist":
					result.InWhitelist = true
				case "blacklist":
					result.InBlacklist = true
				case "known":
					result.InKnown = true
				case "targets":
					result.InTargets = true
				}
				if result.Label == "" {
					result.Label = e.Label
				}
				if result.Notes == "" {
					result.Notes = e.Notes
				}
			}
		}
	}
	return result
}

// ImportFile imports MAC addresses from a text or CSV file
func (m *Manager) ImportFile(listType, filePath string) (int, error) {
	if err := m.validateListType(listType); err != nil {
		return 0, err
	}

	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Support CSV: mac,label,notes
		parts := strings.SplitN(line, ",", 3)
		mac := strings.TrimSpace(parts[0])

		if !isValidMAC(mac) {
			continue
		}

		entry := Entry{MAC: mac}
		if len(parts) > 1 {
			entry.Label = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			entry.Notes = strings.TrimSpace(parts[2])
		}

		if err := m.Add(listType, entry); err != nil {
			// Skip duplicates silently
			continue
		}
		count++
	}
	return count, scanner.Err()
}

func (m *Manager) loadList(listType string) ([]Entry, error) {
	path := filepath.Join(m.baseDir, listType+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return []Entry{}, nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse %s list: %w", listType, err)
	}
	return entries, nil
}

func (m *Manager) saveList(listType string, entries []Entry) error {
	path := filepath.Join(m.baseDir, listType+".json")
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (m *Manager) validateListType(listType string) error {
	valid := map[string]bool{"whitelist": true, "blacklist": true, "known": true, "targets": true}
	if !valid[listType] {
		return fmt.Errorf("invalid list type: %s (use whitelist, blacklist, known, targets)", listType)
	}
	return nil
}

func isValidMAC(mac string) bool {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		// Try dash-separated
		parts = strings.Split(mac, "-")
		if len(parts) != 6 {
			return false
		}
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
	}
	return true
}

