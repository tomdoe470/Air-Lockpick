package session

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/auditteam/wifiaudit/internal/scanner"
	"github.com/google/uuid"
)

// CaptureInfo represents a captured handshake
type CaptureInfo struct {
	BSSID    string    `json:"bssid"`
	SSID     string    `json:"ssid"`
	FilePath string    `json:"file_path"`
	CapturedAt time.Time `json:"captured_at"`
}

// Session represents an audit session
type Session struct {
	ID        string              `json:"id"`
	Name      string              `json:"name,omitempty"`
	Interface string              `json:"interface"`
	StartTime time.Time           `json:"start_time"`
	EndTime   *time.Time          `json:"end_time,omitempty"`
	Networks  []scanner.Network   `json:"networks"`
	Captures  []CaptureInfo       `json:"captures"`
	Notes     string              `json:"notes,omitempty"`
	Auditor   string              `json:"auditor,omitempty"`
}

// New creates a new empty session
func New() *Session {
	return &Session{
		ID:        uuid.New().String(),
		StartTime: time.Now(),
		Networks:  []scanner.Network{},
		Captures:  []CaptureInfo{},
	}
}

// AddNetworks merges newly discovered networks into the session
func (s *Session) AddNetworks(networks []scanner.Network) {
	existing := make(map[string]int)
	for i, n := range s.Networks {
		existing[n.BSSID] = i
	}

	for _, n := range networks {
		if idx, ok := existing[n.BSSID]; ok {
			// Update existing
			s.Networks[idx] = n
		} else {
			s.Networks = append(s.Networks, n)
			existing[n.BSSID] = len(s.Networks) - 1
		}
	}
}

// AddCapture adds a handshake capture to the session
func (s *Session) AddCapture(bssid, ssid, filePath string) {
	s.Captures = append(s.Captures, CaptureInfo{
		BSSID:      bssid,
		SSID:       ssid,
		FilePath:   filePath,
		CapturedAt: time.Now(),
	})
}

// TotalClients returns the total number of unique clients across all networks
func (s *Session) TotalClients() int {
	seen := make(map[string]bool)
	for _, n := range s.Networks {
		for _, c := range n.Clients {
			seen[c.MAC] = true
		}
	}
	return len(seen)
}

// EncryptionStats returns a breakdown of encryption types
func (s *Session) EncryptionStats() map[string]int {
	stats := make(map[string]int)
	for _, n := range s.Networks {
		enc := n.Encryption
		if enc == "" {
			enc = "Unknown"
		}
		stats[enc]++
	}
	return stats
}

// Merge merges another session into this one
func (s *Session) Merge(other *Session) {
	s.AddNetworks(other.Networks)
	s.Captures = append(s.Captures, other.Captures...)
}

// SaveToFile saves the session to a JSON file
func (s *Session) SaveToFile(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.MkdirAll("data/sessions", 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// LoadFromFile loads a session from a JSON file
func LoadFromFile(path string) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("failed to parse session file: %w", err)
	}
	return &sess, nil
}
