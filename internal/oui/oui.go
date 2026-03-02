package oui

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

var (
	db     map[string]string
	dbOnce sync.Once
)

// Lookup returns the vendor name for a MAC address.
// It loads the system IEEE OUI database on first call, falling back to a built-in table.
func Lookup(mac string) string {
	dbOnce.Do(load)
	parts := strings.FieldsFunc(strings.ToUpper(mac), func(r rune) bool {
		return r == ':' || r == '-'
	})
	if len(parts) < 3 {
		return ""
	}
	key := parts[0] + parts[1] + parts[2]
	return db[key]
}

func load() {
	db = builtinDB()
	// Kali/Debian: apt install ieee-data
	for _, path := range []string{
		"/usr/share/ieee-data/oui.txt",
		"/usr/share/misc/oui.txt",
		"/var/lib/ieee-data/oui.txt",
	} {
		if loaded, err := parseOUIFile(path); err == nil && len(loaded) > 100 {
			db = loaded
			return
		}
	}
}

// parseOUIFile parses the IEEE OUI text database.
// Target lines: "XXXXXX     (base 16)		Vendor Name"
func parseOUIFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string, 32000)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		idx := strings.Index(line, "(base 16)")
		if idx < 0 {
			continue
		}
		oui := strings.TrimSpace(line[:idx])
		vendor := strings.TrimSpace(line[idx+len("(base 16)"):])
		if len(oui) == 6 && vendor != "" {
			result[strings.ToUpper(oui)] = vendor
		}
	}
	return result, sc.Err()
}

func builtinDB() map[string]string {
	return map[string]string{
		// Apple
		"001B63": "Apple", "001BB9": "Apple", "001CF0": "Apple",
		"001D4F": "Apple", "001E52": "Apple", "001F5B": "Apple",
		"001FF3": "Apple", "002332": "Apple", "0025BC": "Apple",
		"0026BB": "Apple", "34363B": "Apple", "3C15C2": "Apple",
		"58B035": "Apple", "7C6D62": "Apple", "90CD97": "Apple",
		"A88363": "Apple", "BC926B": "Apple", "F4F26D": "Apple",
		"D0C5F3": "Apple", "40D32D": "Apple", "6C96CF": "Apple",
		"109ADD": "Apple", "A45E60": "Apple", "DC2B2A": "Apple",
		// Cisco / Cisco-Linksys
		"001A2B": "Cisco", "001C0E": "Cisco", "001CA2": "Cisco",
		"001D7E": "Cisco-Linksys", "001111": "Cisco", "001737": "Cisco",
		"0017E0": "Cisco", "001BC0": "Cisco", "002655": "Cisco",
		"00904C": "Cisco", "001310": "Linksys", "001801": "Linksys",
		"0021B2": "Linksys", "00216A": "Linksys", "C8D71A": "Linksys",
		// Samsung
		"00237A": "Samsung", "001599": "Samsung", "001632": "Samsung",
		"001D25": "Samsung", "001EE1": "Samsung", "0026E2": "Samsung",
		"78F7BE": "Samsung", "8C71F8": "Samsung", "34145F": "Samsung",
		"5C0A5B": "Samsung", "CC07AB": "Samsung", "F8042E": "Samsung",
		// Huawei
		"00E0FC": "Huawei", "001E10": "Huawei", "0025E2": "Huawei",
		"4C5499": "Huawei", "606266": "Huawei", "68A0F6": "Huawei",
		"A09354": "Huawei", "7CE9D3": "Huawei", "48DB50": "Huawei",
		"28B448": "Huawei", "F4559C": "Huawei", "9017AC": "Huawei",
		// Intel (Wi-Fi chips)
		"001517": "Intel", "001CC0": "Intel", "001999": "Intel",
		"001AA0": "Intel", "00188B": "Intel", "001E67": "Intel",
		"A4C3F0": "Intel", "4CBC98": "Intel", "8086F2": "Intel",
		"606DC6": "Intel", "D46510": "Intel", "B43A28": "Intel",
		// TP-Link
		"686F2D": "TP-Link", "B00CD1": "TP-Link", "50BD5F": "TP-Link",
		"081011": "TP-Link", "4CEBD6": "TP-Link", "C46E1F": "TP-Link",
		"EC172F": "TP-Link", "F8D111": "TP-Link", "14CC20": "TP-Link",
		"A0F3C1": "TP-Link", "9042A4": "TP-Link", "5800E3": "TP-Link",
		// Netgear
		"0024B2": "Netgear", "A4C361": "Netgear", "00146C": "Netgear",
		"001B2F": "Netgear", "20E52A": "Netgear", "206292": "Netgear",
		"6CB0CE": "Netgear", "9C3DCF": "Netgear", "C03F0E": "Netgear",
		"084F0A": "Netgear", "B0477D": "Netgear", "E091F5": "Netgear",
		// Asus
		"C83A35": "Asus", "D850E6": "Asus", "1C87D1": "Asus",
		"04D9F5": "Asus", "08606E": "Asus", "107B44": "Asus",
		"2C56DC": "Asus", "309C23": "Asus", "488D36": "Asus",
		"50465D": "Asus", "5404A6": "Asus", "AC9E17": "Asus",
		// Xiaomi
		"E894F6": "Xiaomi", "28E31F": "Xiaomi", "64B473": "Xiaomi",
		"8C97EA": "Xiaomi", "AC2374": "Xiaomi", "F048EF": "Xiaomi",
		"7C1DD9": "Xiaomi", "0C1DAF": "Xiaomi", "742344": "Xiaomi",
		"34CE00": "Xiaomi", "8CBEBE": "Xiaomi", "FC64BA": "Xiaomi",
		// Ubiquiti
		"FCFBFB": "Ubiquiti", "00156D": "Ubiquiti", "002722": "Ubiquiti",
		"0418D6": "Ubiquiti", "44D9E7": "Ubiquiti", "68D79A": "Ubiquiti",
		"78883C": "Ubiquiti", "802AA8": "Ubiquiti", "DC9FDB": "Ubiquiti",
		"24A43C": "Ubiquiti", "60224B": "Ubiquiti", "F09FC2": "Ubiquiti",
		// Google (Chromecast, Nest, Pixel)
		"54607E": "Google", "3C5AB4": "Google", "94EB2C": "Google",
		"F4F5DB": "Google", "A4770A": "Google", "1CCFA8": "Google",
		"48D6D5": "Google", "E4F0AC": "Google", "20DF3B": "Google",
		// Amazon (Echo, Fire TV)
		"40B4CD": "Amazon", "74C246": "Amazon", "FC65DE": "Amazon",
		"A002DC": "Amazon", "F0272D": "Amazon", "0C47C9": "Amazon",
		"44650D": "Amazon", "0C849F": "Amazon", "34D270": "Amazon",
		// D-Link
		"00179A": "D-Link", "00226B": "D-Link", "1CAFF7": "D-Link",
		"C8BE19": "D-Link", "F07D68": "D-Link", "B8A386": "D-Link",
		"1C7EE5": "D-Link", "A0AB1B": "D-Link", "00265A": "D-Link",
		// Mikrotik
		"4C5E0C": "Mikrotik", "6C3B6B": "Mikrotik", "B8692F": "Mikrotik",
		"CC2DE0": "Mikrotik", "D4CA6D": "Mikrotik", "E48D8C": "Mikrotik",
		"2CC8FB": "Mikrotik", "742744": "Mikrotik", "DC2C6E": "Mikrotik",
		// Aruba (HP/HPE)
		"000B86": "Aruba", "001A1E": "Aruba", "94B40F": "Aruba",
		"D8C7C8": "Aruba", "F07A57": "Aruba", "20A6CD": "Aruba",
		// Dell
		"002170": "Dell", "001A4B": "Dell", "001372": "Dell",
		"001641": "Dell", "00215A": "Dell", "F8BC12": "Dell",
		"F4CEF6": "Dell", "B083FE": "Dell",
		// HP / HPE
		"001697": "HP", "001083": "HP", "001871": "HP",
		"001E0B": "HP", "002370": "HP", "D07E28": "HP",
		"3C4A92": "HP", "9457A5": "HP",
		// Raspberry Pi Foundation
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
		"28CDC1": "Raspberry Pi",
		// Realtek (cheap adapters, dongles)
		"001017": "Realtek", "00E04C": "Realtek", "00601A": "Realtek",
		"001195": "Realtek", "00904C": "Realtek",
		// ZTE
		"002A5E": "ZTE", "040E3C": "ZTE", "2419B7": "ZTE",
		"4C09D4": "ZTE", "607B58": "ZTE", "7C39C4": "ZTE",
		"84742A": "ZTE", "A88195": "ZTE",
		// Motorola
		"000A28": "Motorola", "001C5C": "Motorola", "001858": "Motorola",
		"58402B": "Motorola", "9CD917": "Motorola", "AC3743": "Motorola",
		// Sony
		"001A80": "Sony", "001BCE": "Sony", "001EBE": "Sony",
		"30179B": "Sony", "AC9B0A": "Sony", "FC0F4B": "Sony",
		// LG Electronics
		"001C62": "LG", "002483": "LG", "002454": "LG",
		"A8B86E": "LG", "CC2D8C": "LG", "7823AE": "LG",
		// Nokia
		"000A55": "Nokia", "001D6F": "Nokia", "106F3F": "Nokia",
		"609590": "Nokia", "C4B30A": "Nokia", "F4098D": "Nokia",
		// OnePlus
		"AC1175": "OnePlus", "E8BB3D": "OnePlus", "4C1075": "OnePlus",
		// Lenovo
		"4CD98F": "Lenovo", "609C9F": "Lenovo", "54721A": "Lenovo",
		"9CBD5E": "Lenovo", "E8699B": "Lenovo",
		// OPPO
		"001E73": "OPPO", "1CBFCE": "OPPO", "3CC3C9": "OPPO",
		"580091": "OPPO", "9831B6": "OPPO",
		// Qualcomm / Atheros
		"002272": "Qualcomm", "00A0F8": "Qualcomm", "4C6005": "Qualcomm",
		// Broadcom (chipsets used in many routers)
		"001018": "Broadcom", "002275": "Broadcom",
	}
}
