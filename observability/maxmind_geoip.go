package observability

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	maxmindMu       sync.RWMutex
	maxmindOnce     sync.Once
	maxmindReader   *mmdbReader
	maxmindFilePath string
)

// InitMaxMind searches for and loads a MaxMind GeoLite2/GeoIP2 .mmdb database.
// It checks explicit paths passed in, environment variables (MAXMIND_DB, GEOIP_DB),
// and standard system locations.
func InitMaxMind(dbPaths ...string) error {
	var candidates []string

	// 1. Explicit arguments
	for _, p := range dbPaths {
		if strings.TrimSpace(p) != "" {
			candidates = append(candidates, strings.TrimSpace(p))
		}
	}

	// 2. Environment variables
	if env := strings.TrimSpace(os.Getenv("MAXMIND_DB")); env != "" {
		candidates = append(candidates, env)
	}
	if env := strings.TrimSpace(os.Getenv("GEOIP_DB")); env != "" {
		candidates = append(candidates, env)
	}

	// 3. User home directory
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".routewarden", "GeoLite2-Country.mmdb"),
			filepath.Join(home, ".routewarden", "GeoLite2-City.mmdb"),
		)
	}

	// 4. Working directory and standard system paths
	candidates = append(candidates,
		"GeoLite2-Country.mmdb",
		"geolite2-country.mmdb",
		"GeoLite2-City.mmdb",
		"geolite2-city.mmdb",
		"/usr/share/GeoIP/GeoLite2-Country.mmdb",
		"/usr/share/GeoIP/GeoLite2-City.mmdb",
		"/var/lib/GeoIP/GeoLite2-Country.mmdb",
		"/var/lib/GeoIP/GeoLite2-City.mmdb",
		"/etc/routewarden/GeoLite2-Country.mmdb",
		"/etc/routewarden/GeoLite2-City.mmdb",
		"/opt/routewarden/GeoLite2-Country.mmdb",
	)

	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil && len(data) > 0 {
			reader, err := newMMDBReader(data)
			if err == nil {
				maxmindMu.Lock()
				maxmindReader = reader
				maxmindFilePath = p
				maxmindMu.Unlock()
				return nil
			}
		}
	}

	return fmt.Errorf("no valid MaxMind .mmdb database found in search paths")
}

// LoadMaxMindData loads a MaxMind database directly from byte slice.
func LoadMaxMindData(data []byte, sourceName string) error {
	reader, err := newMMDBReader(data)
	if err != nil {
		return err
	}
	maxmindMu.Lock()
	maxmindReader = reader
	maxmindFilePath = sourceName
	maxmindMu.Unlock()
	return nil
}

// IsMaxMindLoaded returns whether a MaxMind database is currently active.
func IsMaxMindLoaded() bool {
	maxmindMu.RLock()
	defer maxmindMu.RUnlock()
	return maxmindReader != nil
}

// MaxMindDBPath returns the file path or identifier of the loaded MaxMind database.
func MaxMindDBPath() string {
	maxmindMu.RLock()
	defer maxmindMu.RUnlock()
	return maxmindFilePath
}

// ResetMaxMind unloads the currently active MaxMind database (useful for testing).
func ResetMaxMind() {
	maxmindMu.Lock()
	maxmindReader = nil
	maxmindFilePath = ""
	maxmindMu.Unlock()
}

// LookupMaxMind queries the loaded MaxMind database for the given IP.
// Returns the resolved Country Name, 2-letter ISO Country Code, and a boolean indicating success.
func LookupMaxMind(ip net.IP) (string, string, bool) {
	maxmindMu.RLock()
	reader := maxmindReader
	maxmindMu.RUnlock()

	if reader == nil || ip == nil {
		return "", "", false
	}

	code, rawName, ok := reader.Lookup(ip)
	if !ok || code == "" {
		return "", "", false
	}

	code = strings.ToUpper(strings.TrimSpace(code))
	countryName := CountryCodeToName(code)
	if rawName != "" && countryName == code {
		countryName = rawName
	}

	return countryName, code, true
}

// CountryCodeToName maps ISO 3166-1 alpha-2 country codes to full English country names.
func CountryCodeToName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if name, ok := isoCountryNames[code]; ok {
		return name
	}
	return code
}

// mmdbReader implements a high-performance, zero-dependency MaxMind MMDB binary parser.
type mmdbReader struct {
	buffer         []byte
	nodeCount      uint32
	recordSize     uint16
	ipVersion      uint16
	nodeOffsetMult uint32
	dataSection    uint32
}

func newMMDBReader(data []byte) (*mmdbReader, error) {
	marker := []byte("\xab\xcd\xefMaxMind.com")
	idx := bytes.LastIndex(data, marker)
	if idx == -1 {
		return nil, fmt.Errorf("invalid mmdb: metadata marker not found")
	}

	metaBytes := data[idx+len(marker):]
	r := &mmdbReader{buffer: data}

	r.recordSize = 28 // Default GeoLite2 fallback
	r.ipVersion = 6
	r.nodeCount = 0

	// Robust metadata discovery
	if _, after, ok := bytes.Cut(metaBytes, []byte("node_count")); ok {
		rem := after
		for j := 0; j < len(rem)-3 && j < 8; j++ {
			val := binary.BigEndian.Uint32(rem[j : j+4])
			if val > 0 && val < 50000000 {
				r.nodeCount = val
				break
			}
		}
	}

	if _, after, ok := bytes.Cut(metaBytes, []byte("record_size")); ok {
		rem := after
		for j := 0; j < len(rem)-1 && j < 8; j++ {
			val := binary.BigEndian.Uint16(rem[j : j+2])
			if val == 24 || val == 28 || val == 32 {
				r.recordSize = val
				break
			}
		}
	}

	if _, after, ok := bytes.Cut(metaBytes, []byte("ip_version")); ok {
		rem := after
		for j := 0; j < len(rem)-1 && j < 8; j++ {
			val := binary.BigEndian.Uint16(rem[j : j+2])
			if val == 4 || val == 6 {
				r.ipVersion = val
				break
			}
		}
	}

	if r.nodeCount == 0 {
		return nil, fmt.Errorf("invalid mmdb: could not parse node count")
	}

	r.nodeOffsetMult = uint32(r.recordSize) / 4
	r.dataSection = (r.nodeCount*uint32(r.recordSize)*2)/8 + 16

	return r, nil
}

func (r *mmdbReader) Lookup(ip net.IP) (string, string, bool) {
	if r == nil || len(r.buffer) == 0 {
		return "", "", false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "", "", false
	}

	node := uint32(0)
	for bitIdx := 0; bitIdx < 128; bitIdx++ {
		byteVal := ip16[bitIdx/8]
		bit := (byteVal >> (7 - (bitIdx % 8))) & 1
		next, err := r.readNode(node, bit)
		if err != nil || next == r.nodeCount {
			return "", "", false
		}
		if next > r.nodeCount {
			if next >= r.nodeCount+16 {
				return r.resolveData(next - r.nodeCount - 16)
			}
			return r.resolveData(next - r.nodeCount)
		}
		node = next
	}
	return "", "", false
}

func (r *mmdbReader) readNode(node uint32, bit byte) (uint32, error) {
	offset := node * r.nodeOffsetMult

	switch r.recordSize {
	case 24:
		if int(offset)+6 > len(r.buffer) {
			return 0, fmt.Errorf("node offset out of bounds")
		}
		if bit == 0 {
			return uint32(r.buffer[offset])<<16 | uint32(r.buffer[offset+1])<<8 | uint32(r.buffer[offset+2]), nil
		}
		return uint32(r.buffer[offset+3])<<16 | uint32(r.buffer[offset+4])<<8 | uint32(r.buffer[offset+5]), nil
	case 28:
		if int(offset)+7 > len(r.buffer) {
			return 0, fmt.Errorf("node offset out of bounds")
		}
		middle := r.buffer[offset+3]
		if bit == 0 {
			return uint32(middle>>4)<<24 | uint32(r.buffer[offset])<<16 | uint32(r.buffer[offset+1])<<8 | uint32(r.buffer[offset+2]), nil
		}
		return uint32(middle&0x0F)<<24 | uint32(r.buffer[offset+4])<<16 | uint32(r.buffer[offset+5])<<8 | uint32(r.buffer[offset+6]), nil
	case 32:
		if int(offset)+8 > len(r.buffer) {
			return 0, fmt.Errorf("node offset out of bounds")
		}
		if bit == 0 {
			return binary.BigEndian.Uint32(r.buffer[offset : offset+4]), nil
		}
		return binary.BigEndian.Uint32(r.buffer[offset+4 : offset+8]), nil
	default:
		return 0, fmt.Errorf("unsupported record size: %d", r.recordSize)
	}
}

func (r *mmdbReader) resolveData(offset uint32) (string, string, bool) {
	dataStart := r.dataSection + offset
	if int(dataStart) >= len(r.buffer) {
		return "", "", false
	}
	end := min(int(dataStart)+512, len(r.buffer))
	chunk := r.buffer[dataStart:end]

	idx := bytes.Index(chunk, []byte("iso_code"))
	if idx != -1 {
		for j := idx + 8; j <= min(idx+20, len(chunk)-2); j++ {
			c1 := chunk[j]
			c2 := chunk[j+1]
			if c1 >= 'A' && c1 <= 'Z' && c2 >= 'A' && c2 <= 'Z' {
				code := string(chunk[j : j+2])
				name := CountryCodeToName(code)
				return code, name, true
			}
		}
	}
	return "", "", false
}

var isoCountryNames = map[string]string{
	"AD": "Andorra",
	"AE": "United Arab Emirates",
	"AF": "Afghanistan",
	"AG": "Antigua and Barbuda",
	"AI": "Anguilla",
	"AL": "Albania",
	"AM": "Armenia",
	"AO": "Angola",
	"AQ": "Antarctica",
	"AR": "Argentina",
	"AS": "American Samoa",
	"AT": "Austria",
	"AU": "Australia",
	"AW": "Aruba",
	"AX": "Åland Islands",
	"AZ": "Azerbaijan",
	"BA": "Bosnia and Herzegovina",
	"BB": "Barbados",
	"BD": "Bangladesh",
	"BE": "Belgium",
	"BF": "Burkina Faso",
	"BG": "Bulgaria",
	"BH": "Bahrain",
	"BI": "Burundi",
	"BJ": "Benin",
	"BL": "Saint Barthélemy",
	"BM": "Bermuda",
	"BN": "Brunei",
	"BO": "Bolivia",
	"BQ": "Caribbean Netherlands",
	"BR": "Brazil",
	"BS": "Bahamas",
	"BT": "Bhutan",
	"BV": "Bouvet Island",
	"BW": "Botswana",
	"BY": "Belarus",
	"BZ": "Belize",
	"CA": "Canada",
	"CC": "Cocos Islands",
	"CD": "Democratic Republic of the Congo",
	"CF": "Central African Republic",
	"CG": "Republic of the Congo",
	"CH": "Switzerland",
	"CI": "Ivory Coast",
	"CK": "Cook Islands",
	"CL": "Chile",
	"CM": "Cameroon",
	"CN": "China",
	"CO": "Colombia",
	"CR": "Costa Rica",
	"CU": "Cuba",
	"CV": "Cape Verde",
	"CW": "Curaçao",
	"CX": "Christmas Island",
	"CY": "Cyprus",
	"CZ": "Czech Republic",
	"DE": "Germany",
	"DJ": "Djibouti",
	"DK": "Denmark",
	"DM": "Dominica",
	"DO": "Dominican Republic",
	"DZ": "Algeria",
	"EC": "Ecuador",
	"EE": "Estonia",
	"EG": "Egypt",
	"EH": "Western Sahara",
	"ER": "Eritrea",
	"ES": "Spain",
	"ET": "Ethiopia",
	"FI": "Finland",
	"FJ": "Fiji",
	"FK": "Falkland Islands",
	"FM": "Micronesia",
	"FO": "Faroe Islands",
	"FR": "France",
	"GA": "Gabon",
	"GB": "United Kingdom",
	"GD": "Grenada",
	"GE": "Georgia",
	"GF": "French Guiana",
	"GG": "Guernsey",
	"GH": "Ghana",
	"GI": "Gibraltar",
	"GL": "Greenland",
	"GM": "Gambia",
	"GN": "Guinea",
	"GP": "Guadeloupe",
	"GQ": "Equatorial Guinea",
	"GR": "Greece",
	"GS": "South Georgia",
	"GT": "Guatemala",
	"GU": "Guam",
	"GW": "Guinea-Bissau",
	"GY": "Guyana",
	"HK": "Hong Kong",
	"HM": "Heard and McDonald Islands",
	"HN": "Honduras",
	"HR": "Croatia",
	"HT": "Haiti",
	"HU": "Hungary",
	"ID": "Indonesia",
	"IE": "Ireland",
	"IL": "Israel",
	"IM": "Isle of Man",
	"IN": "India",
	"IO": "British Indian Ocean Territory",
	"IQ": "Iraq",
	"IR": "Iran",
	"IS": "Iceland",
	"IT": "Italy",
	"JE": "Jersey",
	"JM": "Jamaica",
	"JO": "Jordan",
	"JP": "Japan",
	"KE": "Kenya",
	"KG": "Kyrgyzstan",
	"KH": "Cambodia",
	"KI": "Kiribati",
	"KM": "Comoros",
	"KN": "Saint Kitts and Nevis",
	"KP": "North Korea",
	"KR": "South Korea",
	"KW": "Kuwait",
	"KY": "Cayman Islands",
	"KZ": "Kazakhstan",
	"LA": "Laos",
	"LB": "Lebanon",
	"LC": "Saint Lucia",
	"LI": "Liechtenstein",
	"LK": "Sri Lanka",
	"LR": "Liberia",
	"LS": "Lesotho",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"LV": "Latvia",
	"LY": "Libya",
	"MA": "Morocco",
	"MC": "Monaco",
	"MD": "Moldova",
	"ME": "Montenegro",
	"MF": "Saint Martin",
	"MG": "Madagascar",
	"MH": "Marshall Islands",
	"MK": "North Macedonia",
	"ML": "Mali",
	"MM": "Myanmar",
	"MN": "Mongolia",
	"MO": "Macau",
	"MP": "Northern Mariana Islands",
	"MQ": "Martinique",
	"MR": "Mauritania",
	"MS": "Montserrat",
	"MT": "Malta",
	"MU": "Mauritius",
	"MV": "Maldives",
	"MW": "Malawi",
	"MX": "Mexico",
	"MY": "Malaysia",
	"MZ": "Mozambique",
	"NA": "Namibia",
	"NC": "New Caledonia",
	"NE": "Niger",
	"NF": "Norfolk Island",
	"NG": "Nigeria",
	"NI": "Nicaragua",
	"NL": "Netherlands",
	"NO": "Norway",
	"NP": "Nepal",
	"NR": "Nauru",
	"NU": "Niue",
	"NZ": "New Zealand",
	"OM": "Oman",
	"PA": "Panama",
	"PE": "Peru",
	"PF": "French Polynesia",
	"PG": "Papua New Guinea",
	"PH": "Philippines",
	"PK": "Pakistan",
	"PL": "Poland",
	"PM": "Saint Pierre and Miquelon",
	"PN": "Pitcairn",
	"PR": "Puerto Rico",
	"PS": "Palestine",
	"PT": "Portugal",
	"PW": "Palau",
	"PY": "Paraguay",
	"QA": "Qatar",
	"RE": "Réunion",
	"RO": "Romania",
	"RS": "Serbia",
	"RU": "Russia",
	"RW": "Rwanda",
	"SA": "Saudi Arabia",
	"SB": "Solomon Islands",
	"SC": "Seychelles",
	"SD": "Sudan",
	"SE": "Sweden",
	"SG": "Singapore",
	"SH": "Saint Helena",
	"SI": "Slovenia",
	"SJ": "Svalbard and Jan Mayen",
	"SK": "Slovakia",
	"SL": "Sierra Leone",
	"SM": "San Marino",
	"SN": "Senegal",
	"SO": "Somalia",
	"SR": "Suriname",
	"SS": "South Sudan",
	"ST": "São Tomé and Príncipe",
	"SV": "El Salvador",
	"SX": "Sint Maarten",
	"SY": "Syria",
	"SZ": "Eswatini",
	"TC": "Turks and Caicos Islands",
	"TD": "Chad",
	"TF": "French Southern Territories",
	"TG": "Togo",
	"TH": "Thailand",
	"TJ": "Tajikistan",
	"TK": "Tokelau",
	"TL": "Timor-Leste",
	"TM": "Turkmenistan",
	"TN": "Tunisia",
	"TO": "Tonga",
	"TR": "Turkey",
	"TT": "Trinidad and Tobago",
	"TV": "Tuvalu",
	"TW": "Taiwan",
	"TZ": "Tanzania",
	"UA": "Ukraine",
	"UG": "Uganda",
	"UM": "U.S. Outlying Islands",
	"US": "United States",
	"UY": "Uruguay",
	"UZ": "Uzbekistan",
	"VA": "Vatican City",
	"VC": "Saint Vincent and the Grenadines",
	"VE": "Venezuela",
	"VG": "British Virgin Islands",
	"VI": "U.S. Virgin Islands",
	"VN": "Vietnam",
	"VU": "Vanuatu",
	"WF": "Wallis and Futuna",
	"WS": "Samoa",
	"YE": "Yemen",
	"YT": "Mayotte",
	"ZA": "South Africa",
	"ZM": "Zambia",
	"ZW": "Zimbabwe",
}
