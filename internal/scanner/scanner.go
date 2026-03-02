package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Network represents a discovered access point
type Network struct {
	SSID       string    `json:"ssid"`
	BSSID      string    `json:"bssid"`
	Channel    int       `json:"channel"`
	Signal     int       `json:"signal"`
	Encryption string    `json:"encryption"`
	Cipher     string    `json:"cipher"`
	Auth       string    `json:"auth"`
	Vendor     string    `json:"vendor"`
	Clients    []Client  `json:"clients"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Beacons    int       `json:"beacons"`
	Hidden     bool      `json:"hidden"`
}

// Client represents a connected device
type Client struct {
	MAC       string    `json:"mac"`
	BSSID     string    `json:"bssid"`
	Signal    int       `json:"signal"`
	Vendor    string    `json:"vendor"`
	Probes    []string  `json:"probes"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Frames    int       `json:"frames"`
}

// Scanner performs WiFi reconnaissance
type Scanner struct {
	iface    string
	networks map[string]*Network
	clients  map[string]*Client
	mu       sync.RWMutex
	handle   *pcap.Handle
	stop     chan struct{}
	running  bool
}

func New(iface string) *Scanner {
	return &Scanner{
		iface:    iface,
		networks: make(map[string]*Network),
		clients:  make(map[string]*Client),
		stop:     make(chan struct{}, 1),
	}
}

// ScanNetworks performs passive scanning for access points
func (s *Scanner) ScanNetworks(channels []int) error {
	handle, err := pcap.OpenLive(s.iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	s.handle = handle
	s.running = true

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-s.stop:
			handle.Close()
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			s.processPacket(packet)
		}
	}
}

// ScanClients scans for clients associated with a specific BSSID
func (s *Scanner) ScanClients(bssid string) error {
	handle, err := pcap.OpenLive(s.iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	s.handle = handle
	s.running = true

	// BPF filter for the specific BSSID
	filter := fmt.Sprintf("ether host %s", bssid)
	handle.SetBPFFilter(filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-s.stop:
			handle.Close()
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			s.processClientPacket(packet, bssid)
		}
	}
}

func (s *Scanner) processPacket(packet gopacket.Packet) {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}

	dot11, _ := dot11Layer.(*layers.Dot11)
	if dot11 == nil {
		return
	}

	// Process beacon frames
	if dot11.Type == layers.Dot11TypeMgmtBeacon {
		s.processBeacon(packet, dot11)
	}

	// Process probe responses
	if dot11.Type == layers.Dot11TypeMgmtProbeResp {
		s.processBeacon(packet, dot11)
	}

	// Process probe requests (reveals client probes)
	if dot11.Type == layers.Dot11TypeMgmtProbeReq {
		s.processProbeRequest(packet, dot11)
	}

	// Process data frames (reveals active clients)
	if dot11.Type.MainType() == layers.Dot11TypeData {
		s.processDataFrame(dot11)
	}
}

func (s *Scanner) processBeacon(packet gopacket.Packet, dot11 *layers.Dot11) {
	bssid := dot11.Address3.String()
	if bssid == "" || bssid == "00:00:00:00:00:00" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	network, exists := s.networks[bssid]
	if !exists {
		network = &Network{
			BSSID:     bssid,
			FirstSeen: time.Now(),
			Vendor:    lookupVendor(bssid),
		}
		s.networks[bssid] = network
	}

	network.LastSeen = time.Now()
	network.Beacons++

	// Extract RSSI from radio tap
	if radioTap := packet.Layer(layers.LayerTypeRadioTap); radioTap != nil {
		rt, _ := radioTap.(*layers.RadioTap)
		if rt != nil {
			network.Signal = int(int8(rt.DBMAntennaSignal))
		}
	}

	// Parse Information Elements
	mgmtLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon)
	if mgmtLayer == nil {
		mgmtLayer = packet.Layer(layers.LayerTypeDot11MgmtProbeResp)
	}

	if mgmtLayer != nil {
		if beacon, ok := mgmtLayer.(*layers.Dot11MgmtBeacon); ok {
			parseIEs(network, beacon.Contents)
		}
	}
}

func (s *Scanner) processProbeRequest(packet gopacket.Packet, dot11 *layers.Dot11) {
	clientMAC := dot11.Address2.String()
	if clientMAC == "" || clientMAC == "ff:ff:ff:ff:ff:ff" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	client, exists := s.clients[clientMAC]
	if !exists {
		client = &Client{
			MAC:       clientMAC,
			Vendor:    lookupVendor(clientMAC),
			FirstSeen: time.Now(),
		}
		s.clients[clientMAC] = client
	}
	client.LastSeen = time.Now()
	client.Frames++
}

func (s *Scanner) processDataFrame(dot11 *layers.Dot11) {
	src := dot11.Address2.String()
	dst := dot11.Address1.String()
	bssid := dot11.Address3.String()

	if src == "" || src == "ff:ff:ff:ff:ff:ff" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// src is a client if dst is AP
	if bssid != "" && src != bssid {
		client, exists := s.clients[src]
		if !exists {
			client = &Client{
				MAC:       src,
				BSSID:     bssid,
				Vendor:    lookupVendor(src),
				FirstSeen: time.Now(),
			}
			s.clients[src] = client
		}
		client.LastSeen = time.Now()
		client.Frames++
		if client.BSSID == "" {
			client.BSSID = bssid
		}
	}
	_ = dst
}

func (s *Scanner) processClientPacket(packet gopacket.Packet, bssid string) {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11, _ := dot11Layer.(*layers.Dot11)
	if dot11 == nil {
		return
	}

	src := dot11.Address2.String()
	if src == "" || strings.EqualFold(src, bssid) || src == "ff:ff:ff:ff:ff:ff" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	client, exists := s.clients[src]
	if !exists {
		client = &Client{
			MAC:       src,
			BSSID:     bssid,
			Vendor:    lookupVendor(src),
			FirstSeen: time.Now(),
		}
		s.clients[src] = client
	}

	if radioTap := packet.Layer(layers.LayerTypeRadioTap); radioTap != nil {
		rt, _ := radioTap.(*layers.RadioTap)
		if rt != nil {
			client.Signal = int(int8(rt.DBMAntennaSignal))
		}
	}
	client.LastSeen = time.Now()
	client.Frames++
}

// Stop terminates the scanning goroutine
func (s *Scanner) Stop() {
	if s.running {
		s.stop <- struct{}{}
		s.running = false
	}
	if s.handle != nil {
		s.handle.Close()
	}
}

// GetNetworks returns a slice of discovered networks
func (s *Scanner) GetNetworks() []Network {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Network, 0, len(s.networks))
	for _, n := range s.networks {
		result = append(result, *n)
	}
	return result
}

// GetClients returns a slice of discovered clients
func (s *Scanner) GetClients() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Client, 0, len(s.clients))
	for _, c := range s.clients {
		result = append(result, *c)
	}
	return result
}

// parseIEs extracts SSID, channel, and encryption from beacon/probe IEs
func parseIEs(network *Network, data []byte) {
	for i := 0; i < len(data)-2; {
		id := data[i]
		length := int(data[i+1])
		if i+2+length > len(data) {
			break
		}
		value := data[i+2 : i+2+length]

		switch id {
		case 0: // SSID
			if length == 0 {
				network.Hidden = true
			} else {
				network.SSID = string(value)
			}
		case 3: // DS Parameter Set (channel)
			if length >= 1 {
				network.Channel = int(value[0])
			}
		case 48: // RSN (WPA2)
			network.Encryption = "WPA2"
			parseRSN(network, value)
		case 221: // Vendor specific (WPA1)
			if length >= 4 && value[0] == 0x00 && value[1] == 0x50 && value[2] == 0xf2 && value[3] == 0x01 {
				if network.Encryption == "" {
					network.Encryption = "WPA"
				}
			}
		}

		i += 2 + length
	}

	if network.Encryption == "" {
		// Check if WEP by looking at capabilities
		network.Encryption = "OPN"
	}
}

func parseRSN(network *Network, data []byte) {
	if len(data) < 4 {
		return
	}
	// Parse cipher suite count and types
	if len(data) >= 8 {
		cipherCount := binary.LittleEndian.Uint16(data[4:6])
		if cipherCount > 0 && len(data) >= 10 {
			cipher := data[9] // last byte of cipher suite OUI
			switch cipher {
			case 2:
				network.Cipher = "TKIP"
			case 4:
				network.Cipher = "CCMP"
			case 8:
				network.Cipher = "GCMP"
			}
		}
	}
}

// lookupVendor does a basic OUI lookup from the first 3 bytes of a MAC
func lookupVendor(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	oui := strings.ToUpper(strings.Join(parts[:3], ""))

	// Common OUI prefixes (abbreviated list - production would use full OUI DB)
	vendors := map[string]string{
		"001A2B": "Cisco",
		"001B63": "Apple",
		"001BB9": "Apple",
		"001D7E": "Cisco-Linksys",
		"002272": "American Micro",
		"00237A": "Samsung",
		"0024B2": "Netgear",
		"002655": "Samsung",
		"00E0FC": "Huawei",
		"001CF0": "Apple",
		"34363B": "Apple",
		"3C15C2": "Apple",
		"686F2D": "Tp-Link",
		"A4C361": "Netgear",
		"B00CD1": "Tp-Link",
		"C83A35": "Asus",
		"D850E6": "Asus",
		"E894F6": "Xiaomi",
		"F4F26D": "Apple",
		"FCFBFB": "Ubiquiti",
	}

	// Try to parse MAC address bytes for OUI lookup
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return ""
	}
	ouiKey := fmt.Sprintf("%02X%02X%02X", hw[0], hw[1], hw[2])

	if vendor, ok := vendors[ouiKey]; ok {
		return vendor
	}
	return ""
}
