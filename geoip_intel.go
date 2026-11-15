package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =========================================================================
// 🌍 離線 MaxMind GeoLite2 (MMDB) 解析引擎 + 惡意 IP / C2 威脅情資 (IOC) 比對庫
// =========================================================================

type GeoIPIntelResult struct {
	IP             string `json:"ip"`
	IsValid        bool   `json:"is_valid"`
	IsCIDR         bool   `json:"is_cidr,omitempty"`
	NormalizedCIDR string `json:"normalized_cidr,omitempty"`
	ProbeIP        string `json:"probe_ip,omitempty"`
	IsInternal     bool   `json:"is_internal"`
	CountryCode    string `json:"country_code"`
	CountryName    string `json:"country_name"`
	CityName       string `json:"city_name,omitempty"`
	Flag           string `json:"flag"`
	ASN            string `json:"asn"`
	Org            string `json:"org"`
	ASNType        string `json:"asn_type"`    // 雲端機房 / CDN節點 / 匿名代理 / 學術政府 / 電信骨幹 / 一般網路
	BadgeLabel     string `json:"badge_label"` // 精簡顯示標籤 (如 "🇹🇼 台灣 · HiNet AS3462")
	GeoSource      string `json:"geo_source"`  // MMDB / Builtin-CIDR
	IsMalicious    bool   `json:"is_malicious"`
	IOCType        string `json:"ioc_type,omitempty"`
	IOCName        string `json:"ioc_name,omitempty"`
	IOCSeverity    string `json:"ioc_severity,omitempty"`
	IOCSource      string `json:"ioc_source,omitempty"`
	IOCBadge       string `json:"ioc_badge,omitempty"`
}

type ThreatIntelIOCItem struct {
	ID         int    `json:"id"`
	Indicator  string `json:"indicator"`
	IOCType    string `json:"ioc_type"`
	ThreatName string `json:"threat_name"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
	Enabled    bool   `json:"enabled"`
	UpdatedAt  string `json:"updated_at"`
}

type builtinGeoCIDR struct {
	net         *net.IPNet
	countryCode string
	countryName string
	asn         string
	org         string
	asnType     string
}

type iocCIDREntry struct {
	net  *net.IPNet
	item ThreatIntelIOCItem
}

// =========================================================================
// 1. 純 Go 原生 MaxMind DB (.mmdb) 二進位格式解析器 (零外部套件依賴)
// =========================================================================

type mmdbMetadata struct {
	NodeCount              uint32
	RecordSize             uint16
	IPVersion              uint16
	DatabaseType           string
	BinaryFormatMajor      uint16
	BinaryFormatMinor      uint16
	BuildEpoch             uint64
	Description            map[string]string
	Languages              []string
}

type mmdbReader struct {
	filePath     string
	data         []byte
	meta         mmdbMetadata
	treeSize     int
	dataStart    int
	ipv4StartBit int
	ipv4Start    uint32
}

var mmdbMetadataMarker = []byte{0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'}

func openMMDBFile(path string) (*mmdbReader, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	idx := bytes.LastIndex(raw, mmdbMetadataMarker)
	if idx == -1 {
		return nil, errors.New("無效的 MMDB 檔案：找不到 MaxMind.com Metadata 標記")
	}

	r := &mmdbReader{
		filePath: path,
		data:     raw,
	}

	metaOffset := idx + len(mmdbMetadataMarker)
	val, _, err := r.decodeValue(metaOffset, 0)
	if err != nil {
		return nil, fmt.Errorf("解析 MMDB Metadata 失敗: %w", err)
	}
	metaMap, ok := val.(map[string]interface{})
	if !ok {
		return nil, errors.New("MMDB Metadata 結構異常")
	}

	r.meta.NodeCount = uint32(mmdbToUint64(metaMap["node_count"]))
	r.meta.RecordSize = uint16(mmdbToUint64(metaMap["record_size"]))
	r.meta.IPVersion = uint16(mmdbToUint64(metaMap["ip_version"]))
	r.meta.DatabaseType = fmt.Sprintf("%v", metaMap["database_type"])
	r.meta.BinaryFormatMajor = uint16(mmdbToUint64(metaMap["binary_format_major_version"]))
	r.meta.BinaryFormatMinor = uint16(mmdbToUint64(metaMap["binary_format_minor_version"]))
	r.meta.BuildEpoch = mmdbToUint64(metaMap["build_epoch"])

	if r.meta.NodeCount == 0 || (r.meta.RecordSize != 24 && r.meta.RecordSize != 28 && r.meta.RecordSize != 32) {
		return nil, fmt.Errorf("不支援的 MMDB 節點或記錄大小: nodes=%d, record_size=%d", r.meta.NodeCount, r.meta.RecordSize)
	}

	nodeByteSize := int(r.meta.RecordSize) * 2 / 8
	r.treeSize = int(r.meta.NodeCount) * nodeByteSize
	r.dataStart = r.treeSize + 16
	if r.dataStart > len(r.data) {
		return nil, errors.New("MMDB 檔案長度毀損")
	}

	// 若為 IPv6 樹，預先定位 ::/96 IPv4 映射子樹起點，加速 IPv4 查詢 96 步
	if r.meta.IPVersion == 6 {
		node := uint32(0)
		for i := 0; i < 96 && node < r.meta.NodeCount; i++ {
			node = r.readNode(node, 0)
		}
		r.ipv4Start = node
	}
	return r, nil
}

func mmdbToUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n > 0 {
			return uint64(n)
		}
	case int:
		if n > 0 {
			return uint64(n)
		}
	case float64:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

func (r *mmdbReader) readNode(node uint32, bit uint) uint32 {
	nodeByteSize := int(r.meta.RecordSize) * 2 / 8
	base := int(node) * nodeByteSize
	if base+nodeByteSize > r.treeSize {
		return r.meta.NodeCount
	}
	switch r.meta.RecordSize {
	case 24:
		if bit == 0 {
			return uint32(r.data[base])<<16 | uint32(r.data[base+1])<<8 | uint32(r.data[base+2])
		}
		return uint32(r.data[base+3])<<16 | uint32(r.data[base+4])<<8 | uint32(r.data[base+5])
	case 28:
		mid := uint32(r.data[base+3])
		if bit == 0 {
			return ((mid & 0xF0) << 20) | uint32(r.data[base])<<16 | uint32(r.data[base+1])<<8 | uint32(r.data[base+2])
		}
		return ((mid & 0x0F) << 24) | uint32(r.data[base+4])<<16 | uint32(r.data[base+5])<<8 | uint32(r.data[base+6])
	case 32:
		if bit == 0 {
			return binary.BigEndian.Uint32(r.data[base : base+4])
		}
		return binary.BigEndian.Uint32(r.data[base+4 : base+8])
	}
	return r.meta.NodeCount
}

func (r *mmdbReader) lookupIP(ip net.IP) (map[string]interface{}, bool) {
	if r == nil || ip == nil {
		return nil, false
	}
	var searchBytes []byte
	var node uint32
	if r.meta.IPVersion == 4 {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, false
		}
		searchBytes = ip4
		node = 0
	} else {
		if ip4 := ip.To4(); ip4 != nil {
			searchBytes = ip4
			node = r.ipv4Start
		} else {
			ip16 := ip.To16()
			if ip16 == nil {
				return nil, false
			}
			searchBytes = ip16
			node = 0
		}
	}

	bitLen := len(searchBytes) * 8
	for i := 0; i < bitLen; i++ {
		if node >= r.meta.NodeCount {
			break
		}
		b := searchBytes[i>>3]
		bit := uint((b >> (7 - (i & 7))) & 1)
		node = r.readNode(node, bit)
	}

	if node == r.meta.NodeCount {
		return nil, false
	}
	if node > r.meta.NodeCount {
		dataOffset := int(node-r.meta.NodeCount) - 16 + r.dataStart
		if dataOffset < r.dataStart || dataOffset >= len(r.data) {
			return nil, false
		}
		val, _, err := r.decodeValue(dataOffset, r.dataStart)
		if err != nil {
			return nil, false
		}
		if m, ok := val.(map[string]interface{}); ok {
			return m, true
		}
	}
	return nil, false
}

func (r *mmdbReader) decodeValue(offset int, pointerBase int) (interface{}, int, error) {
	if offset < 0 || offset >= len(r.data) {
		return nil, offset, errors.New("mmdb offset out of bounds")
	}
	ctrl := r.data[offset]
	offset++

	dataType := int(ctrl >> 5)
	if dataType == 0 {
		if offset >= len(r.data) {
			return nil, offset, errors.New("mmdb extended type out of bounds")
		}
		dataType = int(r.data[offset]) + 7
		offset++
	}

	// Type 1: Pointer
	if dataType == 1 {
		ptrSize := int((ctrl >> 3) & 0x3)
		valBits := uint32(ctrl & 0x7)
		var ptr uint32
		switch ptrSize {
		case 0:
			if offset >= len(r.data) {
				return nil, offset, errors.New("ptr0 eof")
			}
			ptr = (valBits << 8) | uint32(r.data[offset])
			offset++
		case 1:
			if offset+1 >= len(r.data) {
				return nil, offset, errors.New("ptr1 eof")
			}
			ptr = ((valBits << 16) | uint32(r.data[offset])<<8 | uint32(r.data[offset+1])) + 2048
			offset += 2
		case 2:
			if offset+2 >= len(r.data) {
				return nil, offset, errors.New("ptr2 eof")
			}
			ptr = ((valBits << 24) | uint32(r.data[offset])<<16 | uint32(r.data[offset+1])<<8 | uint32(r.data[offset+2])) + 526336
			offset += 3
		case 3:
			if offset+3 >= len(r.data) {
				return nil, offset, errors.New("ptr3 eof")
			}
			ptr = binary.BigEndian.Uint32(r.data[offset : offset+4])
			offset += 4
		}
		target := pointerBase + int(ptr)
		v, _, err := r.decodeValue(target, pointerBase)
		return v, offset, err
	}

	size := int(ctrl & 0x1f)
	if dataType != 14 { // Boolean stores value in size bits
		switch size {
		case 29:
			if offset >= len(r.data) {
				return nil, offset, errors.New("size29 eof")
			}
			size = 29 + int(r.data[offset])
			offset++
		case 30:
			if offset+1 >= len(r.data) {
				return nil, offset, errors.New("size30 eof")
			}
			size = 285 + int(binary.BigEndian.Uint16(r.data[offset:offset+2]))
			offset += 2
		case 31:
			if offset+2 >= len(r.data) {
				return nil, offset, errors.New("size31 eof")
			}
			size = 65821 + (int(r.data[offset])<<16 | int(r.data[offset+1])<<8 | int(r.data[offset+2]))
			offset += 3
		}
	}

	switch dataType {
	case 2: // UTF-8 String
		if offset+size > len(r.data) {
			return nil, offset, errors.New("string eof")
		}
		s := string(r.data[offset : offset+size])
		return s, offset + size, nil
	case 3: // Double (8 bytes)
		if offset+8 > len(r.data) {
			return nil, offset, errors.New("double eof")
		}
		bits := binary.BigEndian.Uint64(r.data[offset : offset+8])
		return math.Float64frombits(bits), offset + 8, nil
	case 4: // Bytes
		if offset+size > len(r.data) {
			return nil, offset, errors.New("bytes eof")
		}
		b := make([]byte, size)
		copy(b, r.data[offset:offset+size])
		return b, offset + size, nil
	case 5, 6, 9, 10: // uint16, uint32, uint64, uint128
		if offset+size > len(r.data) {
			return nil, offset, errors.New("uint eof")
		}
		if dataType == 10 {
			bi := new(big.Int).SetBytes(r.data[offset : offset+size])
			return bi.String(), offset + size, nil
		}
		var u uint64
		for i := 0; i < size; i++ {
			u = (u << 8) | uint64(r.data[offset+i])
		}
		return u, offset + size, nil
	case 8: // int32
		if offset+size > len(r.data) {
			return nil, offset, errors.New("int32 eof")
		}
		var u uint32
		for i := 0; i < size; i++ {
			u = (u << 8) | uint32(r.data[offset+i])
		}
		return int64(int32(u)), offset + size, nil
	case 7: // Map
		m := make(map[string]interface{}, size)
		cur := offset
		for i := 0; i < size; i++ {
			kVal, nextOff, err := r.decodeValue(cur, pointerBase)
			if err != nil {
				return nil, nextOff, err
			}
			vVal, nextOff2, err := r.decodeValue(nextOff, pointerBase)
			if err != nil {
				return nil, nextOff2, err
			}
			m[fmt.Sprintf("%v", kVal)] = vVal
			cur = nextOff2
		}
		return m, cur, nil
	case 11: // Array
		arr := make([]interface{}, 0, size)
		cur := offset
		for i := 0; i < size; i++ {
			elem, nextOff, err := r.decodeValue(cur, pointerBase)
			if err != nil {
				return nil, nextOff, err
			}
			arr = append(arr, elem)
			cur = nextOff
		}
		return arr, cur, nil
	case 14: // Boolean
		return size != 0, offset, nil
	case 15: // Float (4 bytes)
		if offset+4 > len(r.data) {
			return nil, offset, errors.New("float eof")
		}
		bits := binary.BigEndian.Uint32(r.data[offset : offset+4])
		return float64(math.Float32frombits(bits)), offset + 4, nil
	default:
		if offset+size > len(r.data) {
			return nil, offset, errors.New("unknown eof")
		}
		return nil, offset + size, nil
	}
}

// =========================================================================
// 2. 全域 GeoIP + Threat Intel IOC 引擎管理與 SQLite 持久化
// =========================================================================

var (
	geoIntelMux         sync.RWMutex
	geoIntelInitialized bool
	mmdbCountryReader   *mmdbReader
	mmdbASNReader       *mmdbReader
	builtinGeoRules     []builtinGeoCIDR
	iocExactIPMap       map[string]ThreatIntelIOCItem
	iocCIDRList         []iocCIDREntry
	geoLookupMemo       map[string]GeoIPIntelResult
	customInternalCIDRs []*net.IPNet
)

func getGeoIPDir() string {
	dir := filepath.Join(appDir, "geoip")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

func countryCodeToFlag(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "🌐"
	}
	r1 := rune(0x1F1E6) + rune(cc[0]-'A')
	r2 := rune(0x1F1E6) + rune(cc[1]-'A')
	return string([]rune{r1, r2})
}

var countryCodeZHMap = map[string]string{
	"TW": "台灣", "US": "美國", "JP": "日本", "KR": "韓國", "HK": "香港", "MO": "澳門",
	"SG": "新加坡", "CN": "中國", "DE": "德國", "NL": "荷蘭", "GB": "英國", "UK": "英國",
	"FR": "法國", "CA": "加拿大", "AU": "澳洲", "NZ": "紐西蘭", "RU": "俄羅斯", "IN": "印度",
	"BR": "巴西", "VN": "越南", "TH": "泰國", "ID": "印尼", "MY": "馬來西亞",
	"PH": "菲律賓", "IE": "愛爾蘭", "SE": "瑞典", "NO": "挪威", "DK": "丹麥", "FI": "芬蘭",
	"CH": "瑞士", "AT": "奧地利", "BE": "比利時", "LU": "盧森堡", "IS": "冰島",
	"IT": "義大利", "ES": "西班牙", "PT": "葡萄牙", "GR": "希臘",
	"PL": "波蘭", "CZ": "捷克", "HU": "匈牙利", "SK": "斯洛伐克", "SI": "斯洛維尼亞",
	"HR": "克羅埃西亞", "RS": "塞爾維亞", "UA": "烏克蘭", "BY": "白俄羅斯", "MD": "摩爾多瓦",
	"RO": "羅馬尼亞", "BG": "保加利亞", "LT": "立陶宛", "LV": "拉脫維亞", "EE": "愛沙尼亞",
	"TR": "土耳其", "IL": "以色列", "SA": "沙烏地阿拉伯", "AE": "阿拉伯聯合大公國",
	"QA": "卡達", "KW": "科威特", "BH": "巴林", "OM": "阿曼", "JO": "約旦", "LB": "黎巴嫩",
	"PK": "巴基斯坦", "BD": "孟加拉", "LK": "斯里蘭卡", "NP": "尼泊爾", "MV": "馬爾地夫",
	"MM": "緬甸", "KH": "柬埔寨", "LA": "寮國", "BN": "汶萊", "MN": "蒙古",
	"KZ": "哈薩克", "UZ": "烏茲別克", "KG": "吉爾吉斯", "TJ": "塔吉克", "TM": "土庫曼",
	"GE": "喬治亞", "AM": "亞美尼亞", "AZ": "亞塞拜然",
	"ZA": "南非", "EG": "埃及", "NG": "奈及利亞", "KE": "肯亞", "TZ": "坦尚尼亞",
	"ET": "衣索比亞", "GH": "迦納", "CI": "象牙海岸", "MA": "摩洛哥", "TN": "突尼西亞",
	"DZ": "阿爾及利亞", "LY": "利比亞", "SD": "蘇丹", "MU": "模里西斯", "SC": "塞席爾",
	"MX": "墨西哥", "AR": "阿根廷", "CL": "智利", "CO": "哥倫比亞", "PE": "秘魯",
	"VE": "委內瑞拉", "EC": "厄瓜多", "BO": "玻利維亞", "PY": "巴拉圭", "UY": "烏拉圭",
	"CR": "哥斯大黎加", "PA": "巴拿馬", "GT": "瓜地馬拉", "HN": "宏都拉斯", "SV": "薩爾瓦多",
	"NI": "尼加拉瓜", "DO": "多明尼加", "JM": "牙買加", "BS": "巴哈馬", "BM": "百慕達",
	"VG": "英屬維京群島", "KY": "開曼群島", "PR": "波多黎各",
	"IR": "伊朗", "IQ": "伊拉克", "SY": "敘利亞", "KP": "北韓", "CY": "賽普勒斯", "MT": "馬爾他",
}

var scToTcPhraseReplacer = strings.NewReplacer(
	"台湾", "台灣",
	"阿里云", "阿里雲",
	"腾讯云", "騰訊雲",
	"芒廷维尤", "芒廷維尤 (Mountain View)",
	"圣何塞", "聖荷西",
	"圣克拉拉", "聖塔克拉拉",
	"旧金山", "舊金山",
	"洛杉矶", "洛杉磯",
	"圣地亚哥", "聖地牙哥",
	"弗吉尼亚", "維吉尼亞",
	"新泽西", "紐澤西",
	"俄勒冈", "奧勒岡",
	"休斯顿", "休士頓",
	"菲尼克斯", "鳳凰城",
	"凤凰城", "鳳凰城",
	"蒙特利尔", "蒙特婁",
	"渥太华", "渥太華",
	"卡尔加里", "卡加利",
	"埃德蒙顿", "艾德蒙頓",
	"悉尼", "雪梨",
	"布里斯班", "布里斯本",
	"珀斯", "伯斯",
	"阿德莱德", "阿德雷德",
	"新西兰", "紐西蘭",
	"奥克兰", "奧克蘭",
	"惠灵顿", "威靈頓",
	"巴布亚新几内亚", "巴布亞紐幾內亞",
	"所罗门群岛", "索羅門群島",
	"瓦努阿图", "萬那杜",
	"帕劳", "帛琉",
	"图瓦卢", "吐瓦魯",
	"瑙鲁", "諾魯",
	"伯明翰", "伯明罕",
	"曼彻斯特", "曼徹斯特",
	"爱丁堡", "愛丁堡",
	"布鲁塞尔", "布魯塞爾",
	"苏黎世", "蘇黎世",
	"日内瓦", "日內瓦",
	"维也纳", "維也納",
	"伊斯坦布尔", "伊斯坦堡",
	"迪拜", "杜拜",
	"阿布扎比", "阿布達比",
	"多哈", "杜哈",
	"利雅得", "利雅德",
	"特拉维夫", "特拉維夫",
	"开罗", "開羅",
	"约翰内斯堡", "約翰尼斯堡",
	"开普敦", "開普敦",
	"里约热内卢", "里約熱內盧",
	"布宜诺斯艾利斯", "布宜諾斯艾利斯",
	"利马", "利馬",
	"槟城", "檳城",
	"雅加达", "雅加達",
	"巴厘岛", "峇里島",
	"河内", "河內",
	"岘港", "峴港",
	"金边", "金邊",
	"万象", "永珍",
	"老挝", "寮國",
	"朝鲜", "北韓",
	"马尔代夫", "馬爾地夫",
	"斯里兰卡", "斯里蘭卡",
	"孟加拉国", "孟加拉",
	"文莱", "汶萊",
	"沙特阿拉伯", "沙烏地阿拉伯",
	"阿拉伯联合酋长国", "阿拉伯聯合大公國",
	"格鲁吉亚", "喬治亞",
	"亚美尼亚", "亞美尼亞",
	"阿塞拜疆", "亞塞拜然",
	"哈萨克斯坦", "哈薩克",
	"乌兹别克斯坦", "烏茲別克",
	"吉尔吉斯斯坦", "吉爾吉斯",
	"塔吉克斯坦", "塔吉克",
	"土库曼斯坦", "土庫曼",
	"克罗地亚", "克羅埃西亞",
	"塞尔维亚", "塞爾維亞",
	"斯洛文尼亚", "斯洛維尼亞",
	"塞浦路斯", "賽普勒斯",
	"马耳他", "馬爾他",
	"毛里求斯", "模里西斯",
	"塞舌尔", "塞席爾",
	"肯尼亚", "肯亞",
	"坦桑尼亚", "坦尚尼亞",
	"埃塞俄比亚", "衣索比亞",
	"尼日利亚", "奈及利亞",
	"加纳", "迦納",
	"科特迪瓦", "象牙海岸",
	"突尼斯", "突尼西亞",
	"哥斯达黎加", "哥斯大黎加",
	"危地马拉", "瓜地馬拉",
	"洪都拉斯", "宏都拉斯",
	"多米尼加", "多明尼加",
	"厄瓜多尔", "厄瓜多",
	"玻利维亚", "玻利維亞",
	"开曼群岛", "開曼群島",
	"英属维尔京群岛", "英屬維京群島",
	"百慕大", "百慕達",
	"巴哈马", "巴哈馬",
	"直布罗陀", "直布羅陀",
	"安道尔", "安道爾",
	"圣马力诺", "聖馬利諾",
	"梵蒂冈", "梵蒂岡",
	"摩纳哥", "摩納哥",
	"列支敦士登", "列支敦斯登",
	"斯图加特", "斯圖加特",
	"杜塞尔多夫", "杜塞道夫",
	"巴塞罗那", "巴塞隆納",
	"斯德哥尔摩", "斯德哥爾摩",
	"奥斯陆", "奧斯陸",
	"赫尔辛基", "赫爾辛基",
	"雷克雅未克", "雷克雅維克",
	"维尔纽斯", "維爾紐斯",
	"基辅", "基輔",
	"埃里温", "葉里溫",
	"乌兰巴托", "烏蘭巴托",
	"阿拉木图", "阿拉木圖",
)

var scToTcRuneMap = map[rune]rune{
	'万': '萬', '与': '與', '丑': '醜', '专': '專', '业': '業', '丛': '叢', '东': '東', '丝': '絲', '丢': '丟', '两': '兩', '严': '嚴', '丧': '喪',
	'个': '個', '临': '臨', '为': '為', '丽': '麗', '举': '舉', '么': '麼', '义': '義', '乌': '烏', '乐': '樂', '乔': '喬', '习': '習', '乡': '鄉',
	'书': '書', '买': '買', '乱': '亂', '争': '爭', '于': '於', '亏': '虧', '云': '雲', '亚': '亞', '产': '產', '亩': '畝', '亲': '親', '亵': '褻',
	'亿': '億', '仅': '僅', '仆': '僕', '从': '從', '仑': '侖', '仓': '倉', '仪': '儀', '们': '們', '价': '價', '众': '眾', '优': '優', '伙': '夥',
	'会': '會', '伞': '傘', '伟': '偉', '传': '傳', '伤': '傷', '伦': '倫', '伪': '偽', '体': '體', '余': '餘', '佣': '傭', '佥': '僉', '侠': '俠',
	'侣': '侶', '侥': '僥', '侦': '偵', '侧': '側', '侨': '僑', '侩': '儈', '侪': '儕', '侬': '儂', '俩': '倆', '俭': '儉', '债': '債', '倾': '傾',
	'偿': '償', '兰': '蘭', '兴': '興', '制': '製', '务': '務', '动': '動', '区': '區', '医': '醫', '华': '華', '卢': '盧', '厦': '廈', '县': '縣',
	'双': '雙', '叙': '敘', '后': '後', '响': '響', '团': '團', '国': '國', '圣': '聖', '墙': '牆', '备': '備', '复': '複', '奖': '獎', '奥': '奧',
	'学': '學', '宁': '寧', '宾': '賓', '尔': '爾', '尽': '盡', '层': '層', '属': '屬', '岁': '歲', '岂': '豈', '岛': '島', '岳': '嶽', '峡': '峽',
	'峦': '巒', '帅': '帥', '师': '師', '带': '帶', '帧': '幀', '帮': '幫', '干': '幹', '并': '並', '广': '廣', '庄': '莊', '庆': '慶', '库': '庫',
	'应': '應', '庙': '廟', '庞': '龐', '废': '廢', '开': '開', '异': '異', '弃': '棄', '张': '張', '弥': '彌', '弯': '彎', '弹': '彈', '强': '強',
	'归': '歸', '当': '當', '录': '錄', '彦': '彥', '彻': '徹', '征': '徵', '径': '徑', '忆': '憶', '忏': '懺', '忧': '憂', '怀': '懷', '态': '態',
	'怂': '慫', '怄': '慪', '怅': '悵', '怆': '愴', '怜': '憐', '总': '總', '怼': '懟', '恋': '戀', '恳': '懇', '恶': '惡', '恼': '惱', '悦': '悅',
	'悬': '懸', '悯': '憫', '惊': '驚', '惧': '懼', '惨': '慘', '惩': '懲', '惫': '憊', '惭': '慚', '惮': '憚', '惯': '慣', '愤': '憤', '愿': '願',
	'慑': '懾', '懒': '懶', '懔': '懍', '戏': '戲', '战': '戰', '户': '戶', '扎': '紮', '扑': '撲', '执': '執', '扩': '擴', '扪': '捫', '扫': '掃',
	'扬': '揚', '扰': '擾', '担': '擔', '拟': '擬', '拢': '攏', '拣': '揀', '拥': '擁', '拦': '攔', '拧': '擰', '拨': '撥', '择': '擇', '挂': '掛',
	'挚': '摯', '挛': '攣', '挝': '撾', '挟': '挾', '挠': '撓', '挡': '擋', '挣': '掙', '挤': '擠', '挥': '揮', '损': '損', '捡': '撿', '换': '換',
	'捣': '搗', '据': '據', '掳': '擄', '掴': '摑', '掷': '擲', '掸': '撣', '掺': '摻', '掼': '摜', '揽': '攬', '搀': '攙', '搁': '擱', '搂': '摟',
	'搅': '攪', '携': '攜', '摄': '攝', '摆': '擺', '摇': '搖', '摈': '擯', '摊': '攤', '撑': '撐', '撵': '攆', '撷': '擷', '撸': '擼', '撺': '躥',
	'擞': '擻', '攒': '攢', '敌': '敵', '敛': '斂', '数': '數', '斋': '齋', '斗': '鬥', '断': '斷', '无': '無', '旧': '舊', '时': '時', '旷': '曠',
	'显': '顯', '晋': '晉', '晒': '曬', '晓': '曉', '暂': '暫', '术': '術', '机': '機', '杀': '殺', '杂': '雜', '权': '權', '杆': '桿', '条': '條',
	'来': '來', '杨': '楊', '杰': '傑', '松': '鬆', '极': '極', '构': '構', '枢': '樞', '枪': '槍', '枫': '楓', '柜': '櫃', '栅': '柵', '标': '標',
	'栈': '棧', '栋': '棟', '栏': '欄', '树': '樹', '栖': '棲', '样': '樣', '档': '檔', '桥': '橋', '桦': '樺', '桨': '槳', '桩': '樁', '梦': '夢',
	'检': '檢', '棱': '稜', '椭': '橢', '楼': '樓', '榄': '欖', '榇': '櫬', '榈': '櫚', '槟': '檳', '横': '橫', '樱': '櫻', '橱': '櫥', '檐': '簷',
	'檩': '檁', '欢': '歡', '欧': '歐', '歼': '殲', '殁': '歿', '殇': '殤', '残': '殘', '殒': '殞', '殓': '殮', '殚': '彈', '殡': '殯', '殴': '毆',
	'毁': '毀', '毕': '畢', '毡': '氈', '气': '氣', '氢': '氫', '汇': '匯', '汉': '漢', '污': '汙', '汤': '湯', '汹': '洶', '沈': '瀋', '沟': '溝',
	'没': '沒', '沣': '灃', '沦': '淪', '沧': '滄', '沪': '滬', '泄': '洩', '泞': '濘', '泪': '淚', '泸': '瀘', '泻': '瀉', '泼': '潑', '泽': '澤',
	'洁': '潔', '洒': '灑', '洼': '窪', '浅': '淺', '浆': '漿', '浇': '澆', '浊': '濁', '测': '測', '济': '濟', '浏': '瀏', '浑': '渾', '浓': '濃',
	'浜': '濱', '涂': '塗', '涌': '湧', '涛': '濤', '涝': '澇', '涞': '淶', '涟': '漣', '涡': '渦', '涣': '渙', '涤': '滌', '润': '潤', '涧': '澗',
	'涨': '漲', '涩': '澀', '淀': '澱', '渊': '淵', '渌': '淥', '渎': '瀆', '渐': '漸', '渔': '漁', '渗': '滲', '温': '溫', '游': '遊', '湾': '灣',
	'湿': '濕', '溃': '潰', '溅': '濺', '溆': '漵', '滚': '滾', '滞': '滯', '满': '滿', '滤': '濾', '滥': '濫', '滦': '灤', '滨': '濱', '滩': '灘',
	'潜': '潛', '潴': '瀦', '澜': '瀾', '濒': '瀕', '灭': '滅', '灯': '燈', '灵': '靈', '灾': '災', '灿': '燦', '炀': '煬', '炉': '爐', '炖': '燉',
	'炜': '煒', '点': '點', '炼': '煉', '炽': '熾', '烁': '爍', '烂': '爛', '烃': '烴', '烛': '燭', '烟': '煙', '烦': '煩', '烧': '燒', '烩': '燴',
	'烫': '燙', '烬': '燼', '热': '熱', '焕': '煥', '焖': '燜', '焘': '燾', '爱': '愛', '爷': '爺', '牍': '牘', '牵': '牽', '牺': '犧', '犊': '犢',
	'状': '狀', '犹': '猶', '狈': '狽', '独': '獨', '狭': '狹', '狮': '獅', '狰': '猙', '狱': '獄', '狲': '猻', '猎': '獵', '猕': '獼', '猪': '豬',
	'献': '獻', '琼': '瓊', '电': '電', '盖': '蓋', '盘': '盤', '离': '離', '稣': '穌', '粤': '粵', '纬': '緯', '纳': '納', '经': '經', '络': '絡',
	'维': '維', '缅': '緬', '网': '網', '罗': '羅', '联': '聯', '腊': '臘', '腾': '騰', '舰': '艦', '舱': '艙', '艰': '艱', '艳': '豔', '艺': '藝',
	'节': '節', '芜': '蕪', '芦': '蘆', '苇': '葦', '苍': '蒼', '苏': '蘇', '苹': '蘋', '范': '範', '茎': '莖', '茧': '繭', '荆': '荊', '荐': '薦',
	'荚': '莢', '荡': '蕩', '荣': '榮', '荤': '葷', '荧': '熒', '荫': '蔭', '药': '藥', '莅': '蒞', '莱': '萊', '莲': '蓮', '获': '獲', '莹': '瑩',
	'莺': '鶯', '莼': '蒓', '萝': '蘿', '萤': '螢', '营': '營', '萦': '縈', '萧': '蕭', '萨': '薩', '葱': '蔥', '蒋': '蔣', '蓝': '藍', '蓟': '薊',
	'蓦': '驀', '蔷': '薔', '蔼': '藹', '蕴': '蘊', '藓': '蘚', '虏': '虜', '虑': '慮', '虚': '虛', '虫': '蟲', '虽': '雖', '虾': '蝦', '虿': '蠆',
	'蚀': '蝕', '蚁': '蟻', '蚂': '螞', '蚕': '蠶', '蛊': '蠱', '蛮': '蠻', '蛰': '蟄', '蛱': '蛺', '蜕': '蛻', '蜗': '蝸', '蜡': '蠟', '蝇': '蠅',
	'蝉': '蟬', '蝎': '蠍', '蝾': '蠑', '补': '補', '衬': '襯', '袜': '襪', '袭': '襲', '装': '裝', '裆': '襠', '裤': '褲', '裥': '襇', '见': '見',
	'观': '觀', '规': '規', '觅': '覓', '视': '視', '览': '覽', '觉': '覺', '觊': '覬', '觋': '覡', '觌': '覿', '觎': '覦', '觐': '覲', '觞': '觴',
	'触': '觸', '誉': '譽', '计': '計', '订': '訂', '讣': '訃', '认': '認', '讥': '譏', '讦': '訐', '讧': '訌', '讨': '討', '让': '讓', '讪': '訕',
	'讫': '訖', '训': '訓', '议': '議', '讯': '訊', '记': '記', '讲': '講', '讳': '諱', '讴': '謳', '讶': '訝', '许': '許', '讹': '訛', '论': '論',
	'讼': '訟', '讽': '諷', '设': '設', '访': '訪', '诀': '訣', '证': '證', '诂': '詁', '诃': '訶', '评': '評', '诅': '詛', '识': '識', '诈': '詐',
	'诉': '訴', '诊': '診', '诋': '詆', '诌': '謅', '词': '詞', '诎': '詘', '诏': '詔', '译': '譯', '诒': '詒', '诓': '誆', '诔': '誄', '试': '試',
	'诖': '詖', '诗': '詩', '诘': '詰', '诙': '詼', '诚': '誠', '诛': '誅', '诜': '詵', '话': '話', '诞': '誕', '诟': '詬', '诠': '詮', '诡': '詭',
	'询': '詢', '诣': '詣', '诤': '諍', '该': '該', '详': '詳', '诧': '詫', '诨': '諢', '诩': '詡', '诫': '誡', '诬': '誣', '语': '語', '诮': '誚',
	'误': '誤', '诰': '誥', '诱': '誘', '诲': '誨', '诳': '誑', '说': '說', '诵': '誦', '请': '請', '诸': '諸', '诹': '諏', '诺': '諾', '读': '讀',
	'诼': '諑', '诽': '誹', '课': '課', '诿': '諉', '谀': '諛', '谁': '誰', '谂': '諗', '调': '調', '谄': '諂', '谅': '諒', '谆': '諄', '谇': '誶',
	'谈': '談', '谊': '誼', '谋': '謀', '谍': '諜', '谎': '謊', '谏': '諫', '谐': '諧', '谑': '謔', '谒': '謁', '谓': '謂', '谔': '諤', '谕': '諭',
	'谖': '諼', '谗': '讒', '谘': '諮', '谙': '諳', '谚': '諺', '谛': '諦', '谜': '謎', '谝': '諞', '谟': '謨', '谠': '讜', '谡': '謖', '谢': '謝',
	'谣': '謠', '谤': '謗', '谥': '諡', '谦': '謙', '谧': '謐', '谨': '謹', '谩': '謾', '谪': '謫', '谫': '譾', '谬': '謬', '谭': '譚', '谮': '譖',
	'谯': '譙', '谰': '讕', '谱': '譜', '谲': '譎', '谳': '讞', '谴': '譴', '谵': '譫', '谶': '讖', '贝': '貝', '贞': '貞', '负': '負', '贡': '貢',
	'财': '財', '责': '責', '贤': '賢', '败': '敗', '账': '賬', '货': '貨', '质': '質', '贩': '販', '贪': '貪', '贫': '貧', '贬': '貶', '购': '購',
	'贮': '貯', '贯': '貫', '贰': '貳', '贱': '賤', '贲': '賁', '贳': '貰', '贴': '貼', '贵': '貴', '贷': '貸', '贸': '貿', '费': '費', '贺': '賀',
	'贻': '貽', '贼': '賊', '贽': '贄', '贾': '賈', '贿': '賄', '赁': '賃', '赂': '賂', '赃': '贓', '资': '資', '赅': '賅', '赆': '贐', '赈': '賑',
	'赉': '賚', '赊': '賒', '赋': '賦', '赌': '賭', '赎': '贖', '赏': '賞', '赐': '賜', '赔': '賠', '赖': '賴', '赘': '贅', '赙': '賻', '赚': '賺',
	'赛': '賽', '赜': '蹟', '赞': '贊', '赠': '贈', '赡': '贍', '赢': '贏', '赣': '贛', '赵': '趙', '赶': '趕', '趋': '趨', '跃': '躍', '跄': '蹌',
	'践': '踐', '跷': '蹺', '跸': '蹕', '跹': '躚', '跻': '躋', '踊': '踴', '踌': '躊', '踪': '蹤', '踬': '蹕', '踯': '躑', '蹑': '躡', '蹒': '蹣',
	'蹿': '躥', '躏': '躪', '躯': '軀', '车': '車', '轧': '軋', '轨': '軌', '轩': '軒', '转': '轉', '轮': '輪', '软': '軟', '轰': '轟', '轱': '軲',
	'轲': '軻', '轻': '輕', '轼': '軾', '载': '載', '轾': '輊', '轿': '轎', '辀': '輈', '辁': '輇', '较': '較', '辄': '輒', '辅': '輔', '辆': '輛',
	'辇': '輦', '辈': '輩', '辉': '輝', '辊': '輥', '辋': '輞', '辍': '輟', '辎': '輜', '辏': '輳', '辐': '輻', '辑': '輯', '输': '輸', '辔': '轡',
	'辕': '轅', '辖': '轄', '辗': '輾', '辘': '轆', '辙': '轍', '辚': '轔', '辞': '辭', '辟': '闢', '辩': '辯', '辫': '辮', '边': '邊', '辽': '遼',
	'达': '達', '迁': '遷', '过': '過', '迈': '邁', '运': '運', '还': '還', '这': '這', '进': '進', '远': '遠', '违': '違', '连': '連', '迟': '遲',
	'迹': '跡', '适': '適', '选': '選', '逊': '遜', '递': '遞', '逦': '邐', '逻': '邏', '遗': '遺', '遥': '遙', '邓': '鄧', '邮': '郵', '邹': '鄒',
	'邻': '鄰', '郁': '鬱', '郑': '鄭', '郓': '鄆', '郸': '鄲', '酝': '醞', '酱': '醬', '酿': '釀', '释': '釋', '鉴': '鑒', '针': '針', '钉': '釘',
	'钊': '釗', '钋': '釙', '钌': '釕', '钍': '釷', '钎': '釺', '钏': '釧', '钐': '釤', '钒': '釩', '钓': '釣', '钔': '鍆', '钕': '釹', '钗': '釵',
	'钙': '鈣', '钚': '鈈', '钛': '鈦', '钜': '鉅', '钝': '鈍', '钞': '鈔', '钟': '鐘', '钠': '鈉', '钡': '鋇', '钢': '鋼', '钣': '鈑', '钤': '鈐',
	'钥': '鑰', '钦': '欽', '钧': '鈞', '钨': '鎢', '钩': '鉤', '钪': '鈧', '钫': '鈁', '钬': '鈥', '钭': '鈄', '钮': '鈕', '钯': '鈀', '钰': '鈺',
	'钱': '錢', '钳': '鉗', '钴': '鈷', '钵': '缽', '钷': '鉕', '钹': '鈸', '钺': '鉞', '钻': '鑽', '钼': '鉬', '钽': '鉭', '钾': '鉀', '钿': '鈿',
	'铀': '鈾', '铁': '鐵', '铂': '鉑', '铃': '鈴', '铄': '鑠', '铅': '鉛', '铆': '鉚', '铈': '鈰', '铉': '鉉', '铊': '鉈', '铋': '鉍', '铌': '鈮',
	'铍': '鈹', '铎': '鐸', '铐': '銬', '铑': '銠', '铒': '鉺', '铕': '銪', '铖': '鋮', '铗': '鋏', '铘': '鋣', '铙': '鐃', '铛': '鐺', '铜': '銅',
	'铝': '鋁', '铟': '銦', '铠': '鎧', '铡': '鍘', '铢': '銖', '铣': '銑', '铤': '鋌', '铥': '銩', '铧': '鏵', '铨': '銓', '铩': '鎩', '铪': '鉿',
	'铫': '銚', '铬': '鉻', '铭': '銘', '铮': '錚', '铯': '銫', '铰': '鉸', '铱': '銥', '铲': '鏟', '铳': '銃', '铴': '鐋', '铵': '銨', '银': '銀',
	'铷': '銣', '铸': '鑄', '铹': '鐒', '铺': '鋪', '铼': '錸', '铽': '鋱', '链': '鏈', '铿': '鏗', '销': '銷', '锁': '鎖', '锂': '鋰', '锃': '鋥',
	'锄': '鋤', '锅': '鍋', '锆': '鋯', '锈': '鏽', '锉': '銼', '锊': '鋝', '锋': '鋒', '锌': '鋅', '锍': '鋶', '锎': '鐦', '锏': '鐧', '锐': '銳',
	'锑': '銻', '锒': '鋃', '锓': '鋟', '锔': '鋦', '锕': '錒', '锖': '錆', '锗': '鍺', '错': '錯', '锚': '錨', '锛': '錛', '锜': '錡', '锝': '鍀',
	'锞': '錁', '锟': '錕', '锡': '錫', '锢': '錮', '锣': '鑼', '锤': '錘', '锥': '錐', '锦': '錦', '锨': '鍁', '锩': '錈', '锪': '鍃', '锫': '錇',
	'锬': '錟', '锭': '錠', '键': '鍵', '锯': '鋸', '锰': '錳', '锱': '錙', '锲': '鍥', '锴': '錯', '锵': '鏘', '锶': '鍶', '锷': '鍔', '锸': '鍤',
	'锹': '鍬', '锺': '鍾', '锻': '鍛', '锼': '鎪', '锾': '鍰', '镀': '鍍', '镁': '鎂', '镂': '鏤', '镄': '鐨', '镅': '鎇', '镆': '鏌', '镇': '鎮',
	'镉': '鎘', '镊': '鑷', '镌': '鐫', '镍': '鎳', '镎': '鎿', '镏': '鎦', '镐': '鎬', '镑': '鎊', '镒': '鎰', '镓': '鎵', '镔': '賓', '镖': '鏢',
	'镗': '鏜', '镘': '鏝', '镙': '鏍', '镛': '鏞', '镜': '鏡', '镝': '鏑', '镞': '鏃', '镟': '鏇', '镡': '鐔', '镢': '钁', '镣': '鐐', '镤': '鏷',
	'镥': '鑥', '镦': '鐓', '镧': '鑭', '镨': '鐠', '镩': '鑹', '镪': '鏹', '镫': '鐙', '镬': '鑊', '镭': '鐳', '镯': '鐲', '镰': '鐮', '镱': '鐿',
	'镲': '鑔', '镳': '鑣', '镶': '鑲', '长': '長', '门': '門', '闪': '閃', '闭': '閉', '问': '問', '闯': '闖', '闰': '閏', '闲': '閒', '间': '間',
	'闷': '悶', '闸': '閘', '闹': '鬧', '闺': '閨', '闻': '聞', '闼': '達', '闽': '閩', '闾': '閭', '阀': '閥', '阁': '閣', '阂': '閡', '阃': '閫',
	'阄': '鬮', '阅': '閱', '阆': '閬', '阈': '閾', '阉': '閹', '阊': '倡', '阋': '鬩', '阌': '閿', '阍': '閽', '阎': '閻', '阏': '閼', '阐': '闡',
	'阑': '闌', '阒': '闃', '阔': '闊', '阕': '闋', '阖': '闔', '阗': '闐', '阙': '闕', '阚': '闞', '队': '隊', '阳': '陽', '阴': '陰', '阵': '陣',
	'阶': '階', '际': '際', '陆': '陸', '陇': '隴', '陈': '陳', '陕': '陝', '陨': '隕', '险': '險', '随': '隨', '隐': '隱', '隶': '隸', '隽': '雋',
	'难': '難', '雇': '僱', '雏': '雛', '雳': '靂', '雾': '霧', '霁': '霽', '霉': '黴', '霭': '靄', '靓': '靚', '静': '靜', '韦': '韋', '韧': '韌',
	'韩': '韓', '韪': '韙', '韫': '韞', '韬': '韜', '韵': '韻', '页': '頁', '顶': '頂', '顷': '頃', '项': '項', '顺': '順', '须': '須', '顼': '頊',
	'顽': '頑', '顾': '顧', '顿': '頓', '颁': '頒', '颂': '頌', '预': '預', '颅': '顱', '领': '領', '颇': '頗', '颈': '頸', '颉': '頡', '颊': '頰',
	'颌': '頜', '颍': '潁', '颏': '頦', '颐': '頤', '频': '頻', '颓': '頹', '颔': '頷', '颖': '穎', '颗': '顆', '题': '題', '颚': '顎', '颛': '顓',
	'颜': '顏', '额': '額', '颞': '顳', '颟': '顢', '颠': '顛', '颡': '顙', '颢': '顥', '颤': '顫', '颦': '顰', '颧': '顴', '风': '風', '飒': '颯',
	'飓': '颶', '飘': '飄', '飙': '飆', '飞': '飛', '饥': '饑', '饧': '餳', '饨': '飩', '饩': '餼', '饪': '飪', '饫': '飫', '饬': '飭', '饭': '飯',
	'饮': '飲', '饯': '餞', '饰': '飾', '饱': '飽', '饲': '飼', '饳': '飿', '饴': '飴', '饵': '餌', '饶': '饒', '饷': '餉', '饺': '餃', '饻': '餏',
	'饼': '餅', '饽': '餑', '饿': '餓', '馁': '餒', '馃': '餜', '馄': '餛', '馅': '餡', '馆': '館', '馈': '饋', '馊': '餿', '馋': '饞', '馍': '饃',
	'馏': '餾', '馐': '饈', '馑': '饉', '馒': '饅', '馔': '饌', '马': '馬', '驭': '馭', '驮': '馱', '驯': '馴', '驰': '馳', '驱': '驅', '驳': '駁',
	'驴': '驢', '驵': '駔', '驶': '駛', '驷': '駟', '驸': '駙', '驹': '駒', '驺': '騶', '驻': '駐', '驼': '駝', '驽': '駑', '驾': '駕', '驿': '驛',
	'骀': '駘', '骁': '驍', '骂': '罵', '骄': '驕', '骅': '驊', '骆': '駱', '骇': '駭', '骈': '駢', '骊': '驪', '骋': '騁', '验': '驗', '骎': '駸',
	'骏': '駿', '骐': '騏', '骑': '騎', '骒': '騍', '骓': '騅', '骔': '騌', '骕': '驌', '骗': '騙', '骘': '騭', '骚': '騷', '骛': '騖', '骜': '驁',
	'骝': '騮', '骞': '騫', '骟': '騸', '骠': '驃', '骡': '騾', '骢': '驄', '骣': '驏', '骤': '驟', '骥': '驥', '骧': '驤', '髅': '髏', '髋': '髖',
	'髌': '髕', '髪': '髮', '鬓': '鬢', '鱼': '魚', '鱿': '魷', '鲁': '魯', '鲂': '魴', '鲅': '鮁', '鲆': '鮃', '鲇': '鮎', '鲈': '鱸', '鲋': '鮒',
	'鲍': '鮑', '鲐': '鮐', '鲑': '鮭', '鲒': '鮚', '鲔': '鮪', '鲕': '鮞', '鲚': '鱭', '鲛': '鮫', '鲜': '鮮', '鲞': '鮝', '鲟': '鱘', '鲠': '鯁',
	'鲡': '鱺', '鲢': '鰱', '鲣': '鰹', '鲤': '鯉', '鲥': '鰣', '鲦': '鰷', '鲧': '鯀', '鲨': '鯊', '鲩': '鯇', '鲫': '鯽', '鲭': '鯖', '鲮': '鯪',
	'鲰': '鯫', '鲱': '鯡', '鲲': '鯤', '鲳': '鯧', '鲴': '鯝', '鲵': '鯢', '鲶': '鯰', '鲷': '鯛', '鲸': '鯨', '鲻': '鯔', '鲼': '鱝', '鲽': '鰈',
	'鳃': '鰓', '鳄': '鱷', '鳅': '鰍', '鳆': '鰒', '鳇': '鰉', '鳊': '鯿', '鳋': '鰠', '鳌': '鰲', '鳍': '鰭', '鳎': '鰨', '鳏': '鰥', '鳐': '鰩',
	'鳓': '鰳', '鳔': '鰾', '鳕': '鱈', '鳗': '鰻', '鳘': '鰵', '鳙': '鱅', '鳝': '鱔', '鳞': '鱗', '鳟': '鱒', '鳢': '鱧', '鸟': '鳥', '鸠': '鳩',
	'鸡': '雞', '鸢': '鳶', '鸣': '鳴', '鸥': '鷗', '鸦': '鴉', '鸨': '鴇', '鸩': '鴆', '鸪': '鴣', '鸫': '鶇', '鸬': '鸕', '鸭': '鴨', '鸮': '鴞',
	'鸯': '鴦', '鸱': '鴟', '鸲': '鴝', '鸳': '鴛', '鸵': '鴕', '鸶': '鷥', '鸷': '鷙', '鸸': '鴯', '鸹': '鴰', '鸺': '鵂', '鸽': '鴿', '鸾': '鸞',
	'鸿': '鴻', '鹁': '鵓', '鹂': '鸝', '鹃': '鵑', '鹄': '鵠', '鹅': '鵝', '鹆': '鵒', '鹇': '鷳', '鹈': '鵜', '鹉': '鵡', '鹊': '鵲', '鹋': '鶓',
	'鹌': '鵪', '鹏': '鵬', '鹑': '鶉', '鹕': '鶘', '鹗': '鶚', '鹘': '鶻', '鹙': '鶖', '鹚': '鶿', '鹛': '鶥', '鹜': '鶩', '鹞': '鷂', '鹣': '鶼',
	'鹤': '鶴', '鹦': '鸚', '鹧': '鷓', '鹨': '鷚', '鹩': '鷯', '鹪': '鷦', '鹫': '鷲', '鹬': '鷸', '鹭': '鷺', '鹰': '鷹', '鹱': '鸌', '鹳': '鸛',
	'鹾': '鹺', '麦': '麥', '麸': '麩', '黄': '黃', '齐': '齊', '齿': '齒', '龄': '齡', '龙': '龍', '龟': '龜',
}

// simplifiedToTraditionalZH 將 GeoIP / 線上 API 回傳之簡體中文地名與組織名稱轉換為台灣習慣之正體中文
func simplifiedToTraditionalZH(s string) string {
	if s == "" {
		return s
	}
	replaced := scToTcPhraseReplacer.Replace(s)
	var b strings.Builder
	b.Grow(len(replaced))
	for _, r := range replaced {
		if tc, ok := scToTcRuneMap[r]; ok {
			b.WriteRune(tc)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatCountryZH(cc, fallbackName string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if zh, ok := countryCodeZHMap[cc]; ok {
		return zh
	}
	if fallbackName != "" && fallbackName != "<nil>" {
		return simplifiedToTraditionalZH(fallbackName)
	}
	if cc != "" {
		return cc
	}
	return "未知國家"
}

func classifyASNType(org string, defaultType string) string {
	low := strings.ToLower(org)
	proxyKeywords := []string{
		"tor ", "tor-", "exit", "vpn", "proxy", "m247", "nord", "mullvad",
		"expressvpn", "proton", "private internet", "surfshark", "cyberghost",
		"anonym", "tzulo", "datacamp", "frantech", "buyvm", "leaseweb",
	}
	for _, kw := range proxyKeywords {
		if strings.Contains(low, kw) {
			return "匿名代理/VPN"
		}
	}
	cloudKeywords := []string{
		"amazon", "aws", "google", "microsoft", "azure", "cloudflare",
		"digitalocean", "linode", "akamai", "vultr", "choopa", "hetzner",
		"ovh", "alibaba", "aliyun", "tencent", "oracle", "fastly",
		"hosting", "cloud", "datacenter", "data center", "server", "vps",
		"contabo", "scaleway", "rackspace", "softlayer", "ibm", "equinix",
	}
	for _, kw := range cloudKeywords {
		if strings.Contains(low, kw) {
			return "雲端機房"
		}
	}
	eduGovKeywords := []string{"education", "academic", "tanet", "university", "government", "gsn", "ministry", "教育", "學術", "政府"}
	for _, kw := range eduGovKeywords {
		if strings.Contains(low, kw) {
			return "學術/政府"
		}
	}
	if defaultType != "" {
		return defaultType
	}
	if org != "" {
		return "電信/ISP"
	}
	return ""
}

func buildBuiltinGeoCIDRs() []builtinGeoCIDR {
	rawDefs := []struct {
		cidr, cc, cname, asn, org, atype string
	}{
		// 台灣主要網段與 ASN
		{"163.21.0.0/16", "TW", "台灣", "AS7539", "臺北市教育網路中心", "學術/政府"},
		{"163.20.0.0/16", "TW", "台灣", "AS7539", "新北市教育網路中心", "學術/政府"},
		{"140.111.0.0/16", "TW", "台灣", "AS1659", "教育部 TANet 學術網路", "學術/政府"},
		{"163.28.0.0/16", "TW", "台灣", "AS1659", "TANet 臺灣學術網路", "學術/政府"},
		{"140.109.0.0/16", "TW", "台灣", "AS9264", "中央研究院 Academia Sinica", "學術/政府"},
		{"140.112.0.0/16", "TW", "台灣", "AS17716", "國立臺灣大學 NTU", "學術/政府"},
		{"210.69.0.0/16", "TW", "台灣", "AS4782", "行政院 GSN 政府骨幹網", "學術/政府"},
		{"210.70.0.0/15", "TW", "台灣", "AS4782", "臺灣政府網際服務網 GSN", "學術/政府"},
		{"168.95.0.0/16", "TW", "台灣", "AS3462", "中華電信 HiNet", "電信/ISP"},
		{"1.160.0.0/12", "TW", "台灣", "AS3462", "中華電信 HiNet", "電信/ISP"},
		{"36.224.0.0/12", "TW", "台灣", "AS3462", "中華電信 HiNet", "電信/ISP"},
		{"61.216.0.0/13", "TW", "台灣", "AS3462", "中華電信 HiNet", "電信/ISP"},
		{"114.32.0.0/11", "TW", "台灣", "AS3462", "中華電信 HiNet", "電信/ISP"},
		{"220.128.0.0/12", "TW", "台灣", "AS3462", "中華電信 HiNet", "電信/ISP"},
		{"49.216.0.0/14", "TW", "台灣", "AS24158", "台灣大哥大 Taiwan Mobile", "電信/ISP"},
		{"101.10.0.0/15", "TW", "台灣", "AS24158", "台灣大哥大 Taiwan Mobile", "電信/ISP"},
		{"27.242.0.0/15", "TW", "台灣", "AS4780", "遠傳電信 FarEasTone", "電信/ISP"},
		{"39.8.0.0/13", "TW", "台灣", "AS4780", "遠傳電信 FarEasTone", "電信/ISP"},
		{"203.74.0.0/16", "TW", "台灣", "AS3462", "中華電信數據分公司", "電信/ISP"},

		// 已知匿名代理 / VPN / Tor Exit 節點網段
		{"185.220.100.0/22", "NL", "荷蘭", "AS205100", "Tor Exit Node / 匿名路由", "匿名代理/VPN"},
		{"185.100.84.0/22", "NL", "荷蘭", "AS200052", "Tor / 匿名代理節點", "匿名代理/VPN"},
		{"199.249.230.0/24", "US", "美國", "AS53667", "FranTech / Tor Exit 節點", "匿名代理/VPN"},
		{"209.141.32.0/19", "US", "美國", "AS53667", "FranTech / VPN 匿名主機", "匿名代理/VPN"},
		{"146.70.0.0/16", "CH", "瑞士", "AS9009", "M247 / 商業 VPN 出口", "匿名代理/VPN"},
		{"193.32.126.0/23", "NL", "荷蘭", "AS9009", "M247 / 商業 VPN 出口", "匿名代理/VPN"},
		{"89.234.157.0/24", "FR", "法國", "AS208323", "Tor Exit Relay 節點", "匿名代理/VPN"},

		// 全球雲端機房與 CDN 節點
		{"1.1.1.0/24", "US", "美國", "AS13335", "Cloudflare CDN/DNS", "雲端機房"},
		{"1.0.0.0/24", "US", "美國", "AS13335", "Cloudflare CDN/DNS", "雲端機房"},
		{"104.16.0.0/12", "US", "美國", "AS13335", "Cloudflare CDN", "雲端機房"},
		{"172.64.0.0/13", "US", "美國", "AS13335", "Cloudflare CDN", "雲端機房"},
		{"162.158.0.0/15", "US", "美國", "AS13335", "Cloudflare CDN", "雲端機房"},
		{"8.8.8.0/24", "US", "美國", "AS15169", "Google Public DNS", "雲端機房"},
		{"8.8.4.0/24", "US", "美國", "AS15169", "Google Public DNS", "雲端機房"},
		{"142.250.0.0/15", "US", "美國", "AS15169", "Google Cloud / Services", "雲端機房"},
		{"172.217.0.0/16", "US", "美國", "AS15169", "Google Cloud / Services", "雲端機房"},
		{"34.64.0.0/10", "US", "美國", "AS396982", "Google Cloud Platform", "雲端機房"},
		{"35.184.0.0/13", "US", "美國", "AS15169", "Google Cloud Platform", "雲端機房"},
		{"3.0.0.0/8", "US", "美國", "AS16509", "Amazon AWS Cloud", "雲端機房"},
		{"13.32.0.0/11", "US", "美國", "AS16509", "Amazon AWS CloudFront", "雲端機房"},
		{"18.128.0.0/9", "US", "美國", "AS16509", "Amazon AWS Cloud", "雲端機房"},
		{"52.0.0.0/11", "US", "美國", "AS16509", "Amazon AWS Cloud", "雲端機房"},
		{"54.64.0.0/11", "US", "美國", "AS16509", "Amazon AWS Cloud", "雲端機房"},
		{"13.64.0.0/11", "US", "美國", "AS8075", "Microsoft Azure Cloud", "雲端機房"},
		{"20.0.0.0/11", "US", "美國", "AS8075", "Microsoft Azure Cloud", "雲端機房"},
		{"40.64.0.0/10", "US", "美國", "AS8075", "Microsoft Azure Cloud", "雲端機房"},
		{"52.96.0.0/12", "US", "美國", "AS8075", "Microsoft 365 / Azure", "雲端機房"},
		{"104.131.0.0/16", "US", "美國", "AS14061", "DigitalOcean Cloud", "雲端機房"},
		{"134.122.0.0/16", "US", "美國", "AS14061", "DigitalOcean Cloud", "雲端機房"},
		{"157.230.0.0/16", "US", "美國", "AS14061", "DigitalOcean Cloud", "雲端機房"},
		{"159.65.0.0/16", "US", "美國", "AS14061", "DigitalOcean Cloud", "雲端機房"},
		{"165.22.0.0/16", "SG", "新加坡", "AS14061", "DigitalOcean Cloud", "雲端機房"},
		{"178.128.0.0/16", "US", "美國", "AS14061", "DigitalOcean Cloud", "雲端機房"},
		{"45.33.0.0/16", "US", "美國", "AS63949", "Akamai / Linode Cloud", "雲端機房"},
		{"139.162.0.0/16", "JP", "日本", "AS63949", "Akamai / Linode Cloud", "雲端機房"},
		{"172.104.0.0/15", "JP", "日本", "AS63949", "Akamai / Linode Cloud", "雲端機房"},
		{"45.32.0.0/16", "US", "美國", "AS20473", "Vultr / Choopa Cloud", "雲端機房"},
		{"45.76.0.0/15", "US", "美國", "AS20473", "Vultr / Choopa Cloud", "雲端機房"},
		{"108.61.0.0/16", "US", "美國", "AS20473", "Vultr / Choopa Cloud", "雲端機房"},
		{"149.28.0.0/16", "US", "美國", "AS20473", "Vultr / Choopa Cloud", "雲端機房"},
		{"5.9.0.0/16", "DE", "德國", "AS24940", "Hetzner Online GmbH", "雲端機房"},
		{"88.198.0.0/16", "DE", "德國", "AS24940", "Hetzner Online GmbH", "雲端機房"},
		{"95.216.0.0/15", "FI", "芬蘭", "AS24940", "Hetzner Online GmbH", "雲端機房"},
		{"135.181.0.0/16", "FI", "芬蘭", "AS24940", "Hetzner Online GmbH", "雲端機房"},
		{"51.38.0.0/16", "FR", "法國", "AS16276", "OVHcloud Hosting", "雲端機房"},
		{"51.68.0.0/16", "FR", "法國", "AS16276", "OVHcloud Hosting", "雲端機房"},
		{"145.239.0.0/16", "FR", "法國", "AS16276", "OVHcloud Hosting", "雲端機房"},
		{"47.52.0.0/14", "HK", "香港", "AS45102", "Alibaba Cloud 阿里雲", "雲端機房"},
		{"47.88.0.0/13", "US", "美國", "AS45102", "Alibaba Cloud 阿里雲", "雲端機房"},
		{"47.96.0.0/11", "CN", "中國", "AS37963", "Alibaba Cloud 阿里雲", "雲端機房"},
		{"43.128.0.0/13", "SG", "新加坡", "AS132203", "Tencent Cloud 騰訊雲", "雲端機房"},
		{"49.232.0.0/14", "CN", "中國", "AS45090", "Tencent Cloud 騰訊雲", "雲端機房"},
		{"119.28.0.0/15", "HK", "香港", "AS132203", "Tencent Cloud 騰訊雲", "雲端機房"},
		{"129.226.0.0/16", "HK", "香港", "AS132203", "Tencent Cloud 騰訊雲", "雲端機房"},
		{"17.0.0.0/8", "US", "美國", "AS714", "Apple Inc. Services", "雲端機房"},
		{"157.240.0.0/16", "US", "美國", "AS32934", "Meta / Facebook", "雲端機房"},
		{"31.13.64.0/18", "US", "美國", "AS32934", "Meta / Facebook", "雲端機房"},
		{"23.32.0.0/11", "US", "美國", "AS20940", "Akamai CDN", "雲端機房"},
		{"151.101.0.0/16", "US", "美國", "AS54113", "Fastly CDN", "雲端機房"},

		// 區域性廣域國家網段保底
		{"133.0.0.0/8", "JP", "日本", "AS2516", "KDDI / Japan Network", "電信/ISP"},
		{"210.128.0.0/9", "JP", "日本", "AS2497", "IIJ / Japan Network", "電信/ISP"},
		{"126.0.0.0/8", "JP", "日本", "AS17676", "SoftBank Japan", "電信/ISP"},
		{"121.128.0.0/10", "KR", "韓國", "AS4766", "Korea Telecom (KT)", "電信/ISP"},
		{"211.32.0.0/11", "KR", "韓國", "AS9318", "SK Broadband Korea", "電信/ISP"},
		{"58.14.0.0/15", "CN", "中國", "AS4837", "China Unicom 中國聯通", "電信/ISP"},
		{"116.224.0.0/12", "CN", "中國", "AS4134", "China Telecom 中國電信", "電信/ISP"},
		{"223.64.0.0/11", "CN", "中國", "AS9808", "China Mobile 中國移動", "電信/ISP"},
		{"5.188.0.0/14", "RU", "俄羅斯", "AS49505", "Selectel / Russia Network", "雲端機房"},
		{"91.108.0.0/16", "NL", "荷蘭", "AS62041", "Telegram Messenger Network", "雲端機房"},
		{"149.154.160.0/20", "NL", "荷蘭", "AS62041", "Telegram Messenger Network", "雲端機房"},
	}

	var list []builtinGeoCIDR
	for _, d := range rawDefs {
		if _, ipNet, err := net.ParseCIDR(d.cidr); err == nil {
			list = append(list, builtinGeoCIDR{
				net:         ipNet,
				countryCode: d.cc,
				countryName: d.cname,
				asn:         d.asn,
				org:         d.org,
				asnType:     d.atype,
			})
		}
	}
	// 最長前綴優先 (Longest Prefix Match)
	sort.Slice(list, func(i, j int) bool {
		oi, _ := list[i].net.Mask.Size()
		oj, _ := list[j].net.Mask.Size()
		return oi > oj
	})
	return list
}

// ensureThreatIntelTable 建立 SQLite 惡意 IP / C2 黑名單資料表並預置基礎威脅情資
func ensureThreatIntelTable(db *sql.DB) error {
	if db == nil {
		return errors.New("db is nil")
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS threat_intel_iocs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			indicator TEXT UNIQUE NOT NULL,
			ioc_type TEXT DEFAULT 'C2',
			threat_name TEXT DEFAULT '',
			severity TEXT DEFAULT 'CRITICAL',
			source TEXT DEFAULT 'Built-in IOC',
			enabled INTEGER DEFAULT 1,
			updated_at TEXT DEFAULT ''
		);
	`); err != nil {
		return err
	}

	var cnt int
	_ = db.QueryRow("SELECT COUNT(*) FROM threat_intel_iocs").Scan(&cnt)
	if cnt == 0 {
		nowStr := time.Now().Format("2006-01-02 15:04:05")
		seeds := []struct {
			ind, iType, name, sev, src string
		}{
			{"185.220.101.0/24", "TorExit", "Tor 匿名出口高風險節點", "HIGH", "Built-in IOC"},
			{"185.220.100.0/24", "TorExit", "Tor 匿名出口高風險節點", "HIGH", "Built-in IOC"},
			{"45.155.205.0/24", "Scanner", "高頻暴力破解與漏洞掃描網段", "HIGH", "Built-in IOC"},
			{"91.240.118.0/24", "Botnet", "Mirai / Mozi 殭屍網路控制節點", "CRITICAL", "Built-in IOC"},
			{"194.26.135.0/24", "C2", "CobaltStrike / Sliver C2 惡意中繼", "CRITICAL", "Built-in IOC"},
			{"185.234.218.0/24", "C2", "Abuse.ch Feodo / QakBot C2 網段", "CRITICAL", "Abuse.ch"},
			{"45.146.164.0/24", "Scanner", "Masscan / Log4j 惡意探測源", "HIGH", "Built-in IOC"},
			{"193.142.146.0/24", "Malware", "惡意軟體分發與釣魚中繼站", "CRITICAL", "Built-in IOC"},
			{"80.82.77.0/24", "Scanner", "全網高危埠自動化掃描器", "MEDIUM", "Built-in IOC"},
			{"162.142.125.0/24", "Scanner", "Censys 外部資產測繪掃描器", "MEDIUM", "Built-in IOC"},
		}
		for _, s := range seeds {
			_, _ = db.Exec(`
				INSERT OR IGNORE INTO threat_intel_iocs (indicator, ioc_type, threat_name, severity, source, enabled, updated_at)
				VALUES (?, ?, ?, ?, ?, 1, ?)
			`, s.ind, s.iType, s.name, s.sev, s.src, nowStr)
		}
	}
	return nil
}

// InitGeoIPAndThreatIntel 初始化或熱重載 MaxMind MMDB 檔案與 SQLite 惡意情資黑名單
func InitGeoIPAndThreatIntel() {
	geoIntelMux.Lock()
	defer geoIntelMux.Unlock()

	if len(builtinGeoRules) == 0 {
		builtinGeoRules = buildBuiltinGeoCIDRs()
	}

	// 解析 pa1420key.txt 中的 INTERNAL_SUBNETS (空白分隔)
	reloadCustomInternalCIDRsLocked(parseInternalSubnetsFromConfigFile())

	// 1. 掃描 geoip/ 與 appDir 下的 MaxMind MMDB 檔案
	geoDir := getGeoIPDir()
	searchDirs := []string{geoDir, appDir}
	var newCountryMMDB, newASNMMDB *mmdbReader

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".mmdb") {
				continue
			}
			fullPath := filepath.Join(dir, e.Name())
			lowName := strings.ToLower(e.Name())
			if strings.Contains(lowName, "asn") {
				if newASNMMDB == nil {
					if r, err := openMMDBFile(fullPath); err == nil {
						newASNMMDB = r
						fmt.Printf("🌍 [GeoIP MMDB] 已載入離線 ASN 資料庫: %s (節點: %d)\n", e.Name(), r.meta.NodeCount)
					}
				}
			} else if strings.Contains(lowName, "city") || strings.Contains(lowName, "country") || strings.Contains(lowName, "geoip") || strings.Contains(lowName, "dbip") {
				if newCountryMMDB == nil {
					if r, err := openMMDBFile(fullPath); err == nil {
						newCountryMMDB = r
						fmt.Printf("🌍 [GeoIP MMDB] 已載入離線國家/城市資料庫: %s (%s, 節點: %d)\n", e.Name(), r.meta.DatabaseType, r.meta.NodeCount)
					}
				}
			}
		}
	}

	mmdbCountryReader = newCountryMMDB
	mmdbASNReader = newASNMMDB

	// 2. 載入 SQLite 惡意 IP / C2 黑名單至記憶體高速索引
	newExact := make(map[string]ThreatIntelIOCItem)
	var newCIDRs []iocCIDREntry

	if db, err := initDB(); err == nil && db != nil {
		_ = ensureThreatIntelTable(db)
		if rows, qErr := db.Query(`
			SELECT id, indicator, COALESCE(ioc_type, 'C2'), COALESCE(threat_name, ''), COALESCE(severity, 'CRITICAL'), COALESCE(source, 'Custom'), COALESCE(enabled, 1), COALESCE(updated_at, '')
			FROM threat_intel_iocs
			WHERE enabled = 1
		`); qErr == nil {
			for rows.Next() {
				var it ThreatIntelIOCItem
				var en int
				if err := rows.Scan(&it.ID, &it.Indicator, &it.IOCType, &it.ThreatName, &it.Severity, &it.Source, &en, &it.UpdatedAt); err == nil {
					it.Enabled = (en == 1)
					ind := strings.TrimSpace(it.Indicator)
					if strings.Contains(ind, "/") {
						if _, ipNet, pErr := net.ParseCIDR(ind); pErr == nil {
							newCIDRs = append(newCIDRs, iocCIDREntry{net: ipNet, item: it})
						}
					} else if parsed := net.ParseIP(ind); parsed != nil {
						newExact[parsed.String()] = it
					}
				}
			}
			rows.Close()
		}
	}

	iocExactIPMap = newExact
	iocCIDRList = newCIDRs
	geoLookupMemo = make(map[string]GeoIPIntelResult, 4096)
	geoIntelInitialized = true
}

func parseInternalSubnetsFromConfigFile() []string {
	cfgPath := paConfigFile
	if cfgPath == "" {
		cfgPath = "pa1420key.txt"
	}
	var subs []string
	if content, err := os.ReadFile(cfgPath); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if len(line) >= 17 && strings.EqualFold(line[:17], "INTERNAL_SUBNETS=") {
				val := strings.TrimSpace(line[17:])
				subs = append(subs, strings.Fields(val)...)
			}
		}
	}
	return subs
}

func reloadCustomInternalCIDRsLocked(subs []string) {
	var parsed []*net.IPNet
	for _, p := range subs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			p = p + "/32"
		}
		if _, ipnet, err := net.ParseCIDR(p); err == nil {
			parsed = append(parsed, ipnet)
		}
	}
	customInternalCIDRs = parsed
	if geoLookupMemo != nil {
		geoLookupMemo = make(map[string]GeoIPIntelResult, 4096)
	}
}

func reloadCustomInternalCIDRs(subs []string) {
	geoIntelMux.Lock()
	defer geoIntelMux.Unlock()
	reloadCustomInternalCIDRsLocked(subs)
}

func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// CGNAT 100.64.0.0/10
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}

	// 判斷 pa1420key.txt 自訂內網
	geoIntelMux.RLock()
	cidrs := customInternalCIDRs
	geoIntelMux.RUnlock()
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func cidrOverlaps(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func parseLookupTarget(rawInput string) (probeIP net.IP, ipNet *net.IPNet, isCIDR bool, normCIDR string, valid bool) {
	clean := strings.TrimSpace(rawInput)
	if clean == "" || clean == "-" {
		return nil, nil, false, "", false
	}
	if strings.Contains(clean, "/") {
		_, parsedNet, err := net.ParseCIDR(clean)
		if err != nil || parsedNet == nil {
			return nil, nil, true, "", false
		}
		ones, bits := parsedNet.Mask.Size()
		repIP := make(net.IP, len(parsedNet.IP))
		copy(repIP, parsedNet.IP)
		// 若網段主機位數足夠 (如 /16, /24)，取第一個可用主機位址 (.1) 作為 GeoIP/線上反查代表節點
		if bits-ones >= 2 && len(repIP) > 0 {
			repIP[len(repIP)-1] |= 1
			if !parsedNet.Contains(repIP) {
				copy(repIP, parsedNet.IP)
			}
		}
		return repIP, parsedNet, true, parsedNet.String(), true
	}
	parsed := net.ParseIP(clean)
	if parsed == nil {
		return nil, nil, false, "", false
	}
	return parsed, nil, false, "", true
}

func isCIDRInternal(ipNet *net.IPNet, probeIP net.IP) bool {
	if isPrivateOrLocalIP(probeIP) || (ipNet != nil && isPrivateOrLocalIP(ipNet.IP)) {
		return true
	}
	if ipNet == nil {
		return false
	}
	geoIntelMux.RLock()
	cidrs := customInternalCIDRs
	geoIntelMux.RUnlock()
	for _, c := range cidrs {
		if cidrOverlaps(ipNet, c) {
			return true
		}
	}
	return false
}

// LookupGeoIPAndIOC 查詢單一 IP 或 CIDR 網段的離線 GeoIP 國家/城市、ASN 屬性與惡意情資 (IOC) 命中狀態
func LookupGeoIPAndIOC(rawIP string) GeoIPIntelResult {
	cleanIP := strings.TrimSpace(rawIP)
	if cleanIP == "" || cleanIP == "-" {
		return GeoIPIntelResult{IP: cleanIP}
	}

	geoIntelMux.RLock()
	inited := geoIntelInitialized
	if inited {
		if cached, ok := geoLookupMemo[cleanIP]; ok {
			geoIntelMux.RUnlock()
			return cached
		}
	}
	geoIntelMux.RUnlock()

	if !inited {
		InitGeoIPAndThreatIntel()
	}

	parsed, ipNet, isCIDR, normCIDR, valid := parseLookupTarget(cleanIP)
	if !valid || parsed == nil {
		return GeoIPIntelResult{IP: cleanIP, IsValid: false, IsCIDR: isCIDR}
	}

	internalFlag := isPrivateOrLocalIP(parsed)
	if isCIDR {
		internalFlag = isCIDRInternal(ipNet, parsed)
	}

	res := GeoIPIntelResult{
		IP:             cleanIP,
		IsValid:        true,
		IsCIDR:         isCIDR,
		NormalizedCIDR: normCIDR,
		ProbeIP:        parsed.String(),
		IsInternal:     internalFlag,
	}

	geoIntelMux.RLock()
	cReader := mmdbCountryReader
	aReader := mmdbASNReader
	exactIOC, hasExactIOC := iocExactIPMap[parsed.String()]
	if !hasExactIOC && isCIDR && ipNet != nil {
		for exactIPStr, item := range iocExactIPMap {
			if ep := net.ParseIP(exactIPStr); ep != nil && ipNet.Contains(ep) {
				exactIOC = item
				hasExactIOC = true
				break
			}
		}
	}
	var matchedCIDRIOC *ThreatIntelIOCItem
	if !hasExactIOC {
		for i := range iocCIDRList {
			if iocCIDRList[i].net.Contains(parsed) || (isCIDR && ipNet != nil && cidrOverlaps(ipNet, iocCIDRList[i].net)) {
				matchedCIDRIOC = &iocCIDRList[i].item
				break
			}
		}
	}
	geoIntelMux.RUnlock()

	// 1. 檢查是否命中惡意情資 (IOC) 黑名單（內外網 IP 皆可檢測）
	if hasExactIOC {
		res.IsMalicious = true
		res.IOCType = exactIOC.IOCType
		res.IOCName = exactIOC.ThreatName
		res.IOCSeverity = exactIOC.Severity
		res.IOCSource = exactIOC.Source
	} else if matchedCIDRIOC != nil {
		res.IsMalicious = true
		res.IOCType = matchedCIDRIOC.IOCType
		res.IOCName = matchedCIDRIOC.ThreatName
		res.IOCSeverity = matchedCIDRIOC.Severity
		res.IOCSource = matchedCIDRIOC.Source
	}
	if res.IsMalicious {
		lbl := res.IOCName
		if lbl == "" {
			lbl = res.IOCType
		}
		res.IOCBadge = fmt.Sprintf("☠️ %s: %s", res.IOCType, lbl)
	}

	if res.IsInternal {
		res.CountryCode = "LAN"
		res.CountryName = "內網"
		res.Flag = "🏢"
		res.BadgeLabel = ""
	} else {
		// 2. 優先查詢 MaxMind GeoLite2 Country / City MMDB
		if cReader != nil {
			if rec, ok := cReader.lookupIP(parsed); ok {
				res.GeoSource = "MMDB"
				if countryMap, ok := rec["country"].(map[string]interface{}); ok {
					if iso, ok := countryMap["iso_code"].(string); ok {
						res.CountryCode = strings.ToUpper(iso)
					}
					if names, ok := countryMap["names"].(map[string]interface{}); ok {
						if zh, ok := names["zh-CN"].(string); ok && zh != "" {
							res.CountryName = zh
						} else if en, ok := names["en"].(string); ok {
							res.CountryName = en
						}
					}
				}
				if cityMap, ok := rec["city"].(map[string]interface{}); ok {
					if names, ok := cityMap["names"].(map[string]interface{}); ok {
						if zh, ok := names["zh-CN"].(string); ok && zh != "" {
							res.CityName = simplifiedToTraditionalZH(zh)
						} else if en, ok := names["en"].(string); ok {
							res.CityName = en
						}
					}
				}
			}
		}

		// 3. 查詢 MaxMind GeoLite2 ASN MMDB
		if aReader != nil {
			if rec, ok := aReader.lookupIP(parsed); ok {
				asnNum := mmdbToUint64(rec["autonomous_system_number"])
				if asnNum > 0 {
					res.ASN = fmt.Sprintf("AS%d", asnNum)
				}
				if org, ok := rec["autonomous_system_organization"].(string); ok {
					res.Org = strings.TrimSpace(org)
				}
				if res.GeoSource == "" {
					res.GeoSource = "MMDB-ASN"
				}
			}
		}

		// 4. 若尚未安裝外部 MMDB 或 MMDB 缺漏該網段，使用內建離線 GeoIP + ASN 知識庫補齊
		if res.CountryCode == "" || res.Org == "" {
			for _, rule := range builtinGeoRules {
				if rule.net.Contains(parsed) {
					if res.CountryCode == "" {
						res.CountryCode = rule.countryCode
						res.CountryName = rule.countryName
					}
					if res.ASN == "" {
						res.ASN = rule.asn
					}
					if res.Org == "" {
						res.Org = rule.org
					}
					if res.ASNType == "" {
						res.ASNType = rule.asnType
					}
					if res.GeoSource == "" {
						res.GeoSource = "Builtin-Offline"
					}
					break
				}
			}
		}

		if res.CountryCode != "" {
			res.CountryName = formatCountryZH(res.CountryCode, res.CountryName)
			res.Flag = countryCodeToFlag(res.CountryCode)
		} else {
			res.Flag = "🌐"
			res.CountryName = "公網 IP"
		}

		res.ASNType = classifyASNType(res.Org, res.ASNType)

		// 組裝精簡高可讀性徽章標籤
		var parts []string
		if res.CountryName != "" {
			loc := res.Flag + " " + res.CountryName
			if res.CityName != "" && res.CityName != res.CountryName {
				loc += "·" + res.CityName
			}
			parts = append(parts, loc)
		}
		if res.Org != "" {
			shortOrg := res.Org
			if len([]rune(shortOrg)) > 18 {
				shortOrg = string([]rune(shortOrg)[:17]) + "…"
			}
			if res.ASN != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", shortOrg, res.ASN))
			} else {
				parts = append(parts, shortOrg)
			}
		} else if res.ASN != "" {
			parts = append(parts, res.ASN)
		}
		res.BadgeLabel = strings.Join(parts, " · ")
	}

	geoIntelMux.Lock()
	if len(geoLookupMemo) >= 20000 {
		geoLookupMemo = make(map[string]GeoIPIntelResult, 4096)
	}
	geoLookupMemo[cleanIP] = res
	geoIntelMux.Unlock()

	return res
}

// GetGeoIPAndIOCStatus 回傳目前離線 MMDB 資料庫與惡意情資黑名單筆數狀態
func GetGeoIPAndIOCStatus() map[string]interface{} {
	if !geoIntelInitialized {
		InitGeoIPAndThreatIntel()
	}
	geoIntelMux.RLock()
	defer geoIntelMux.RUnlock()

	countryFile := ""
	countryNodes := uint32(0)
	if mmdbCountryReader != nil {
		countryFile = filepath.Base(mmdbCountryReader.filePath)
		countryNodes = mmdbCountryReader.meta.NodeCount
	}
	asnFile := ""
	asnNodes := uint32(0)
	if mmdbASNReader != nil {
		asnFile = filepath.Base(mmdbASNReader.filePath)
		asnNodes = mmdbASNReader.meta.NodeCount
	}

	return map[string]interface{}{
		"geoip_dir":          getGeoIPDir(),
		"country_mmdb_loaded": mmdbCountryReader != nil,
		"country_mmdb_file":   countryFile,
		"country_mmdb_nodes":  countryNodes,
		"asn_mmdb_loaded":     mmdbASNReader != nil,
		"asn_mmdb_file":       asnFile,
		"asn_mmdb_nodes":      asnNodes,
		"builtin_cidr_count":  len(builtinGeoRules),
		"ioc_exact_count":     len(iocExactIPMap),
		"ioc_cidr_count":      len(iocCIDRList),
		"ioc_total_active":    len(iocExactIPMap) + len(iocCIDRList),
	}
}

// ListThreatIntelIOCs 列出 SQLite 內所有威脅情資 IOC 條目
func ListThreatIntelIOCs(keyword string) ([]ThreatIntelIOCItem, error) {
	db, err := initDB()
	if err != nil || db == nil {
		return nil, err
	}
	_ = ensureThreatIntelTable(db)

	var rows *sql.Rows
	if keyword != "" {
		kw := "%" + keyword + "%"
		rows, err = db.Query(`
			SELECT id, indicator, COALESCE(ioc_type, 'C2'), COALESCE(threat_name, ''), COALESCE(severity, 'CRITICAL'), COALESCE(source, 'Custom'), COALESCE(enabled, 1), COALESCE(updated_at, '')
			FROM threat_intel_iocs
			WHERE indicator LIKE ? OR threat_name LIKE ? OR ioc_type LIKE ? OR source LIKE ?
			ORDER BY id DESC LIMIT 500
		`, kw, kw, kw, kw)
	} else {
		rows, err = db.Query(`
			SELECT id, indicator, COALESCE(ioc_type, 'C2'), COALESCE(threat_name, ''), COALESCE(severity, 'CRITICAL'), COALESCE(source, 'Custom'), COALESCE(enabled, 1), COALESCE(updated_at, '')
			FROM threat_intel_iocs
			ORDER BY id DESC LIMIT 500
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]ThreatIntelIOCItem, 0)
	for rows.Next() {
		var it ThreatIntelIOCItem
		var en int
		if err := rows.Scan(&it.ID, &it.Indicator, &it.IOCType, &it.ThreatName, &it.Severity, &it.Source, &en, &it.UpdatedAt); err == nil {
			it.Enabled = (en == 1)
			list = append(list, it)
		}
	}
	return list, nil
}

// BulkImportThreatIntelIOCs 支援純文字列表（每行一個 IP/CIDR）或 CSV (indicator,type,name,severity) 批次匯入惡意情資
func BulkImportThreatIntelIOCs(rawText, defaultType, defaultName, defaultSeverity, source string) (int, int, error) {
	db, err := initDB()
	if err != nil || db == nil {
		return 0, 0, err
	}
	_ = ensureThreatIntelTable(db)

	if defaultType == "" {
		defaultType = "C2"
	}
	if defaultSeverity == "" {
		defaultSeverity = "CRITICAL"
	}
	if source == "" {
		source = "Custom Import"
	}
	nowStr := time.Now().Format("2006-01-02 15:04:05")

	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO threat_intel_iocs (indicator, ioc_type, threat_name, severity, source, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(indicator) DO UPDATE SET
			ioc_type = excluded.ioc_type,
			threat_name = CASE WHEN excluded.threat_name != '' THEN excluded.threat_name ELSE threat_intel_iocs.threat_name END,
			severity = excluded.severity,
			source = excluded.source,
			enabled = 1,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()

	imported := 0
	skipped := 0
	scanner := bufio.NewScanner(strings.NewReader(rawText))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// 去除行尾註解
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.Split(line, ",")
		ind := strings.TrimSpace(parts[0])
		if strings.EqualFold(ind, "ip") || strings.EqualFold(ind, "indicator") {
			continue
		}

		valid := false
		if strings.Contains(ind, "/") {
			if _, _, err := net.ParseCIDR(ind); err == nil {
				valid = true
			}
		} else if p := net.ParseIP(ind); p != nil {
			ind = p.String()
			valid = true
		}
		if !valid {
			skipped++
			continue
		}

		iType := defaultType
		tName := defaultName
		sev := strings.ToUpper(defaultSeverity)
		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			iType = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			tName = strings.TrimSpace(parts[2])
		}
		if len(parts) >= 4 && strings.TrimSpace(parts[3]) != "" {
			sev = strings.ToUpper(strings.TrimSpace(parts[3]))
		}
		if tName == "" {
			tName = fmt.Sprintf("惡意情資黑名單 (%s)", iType)
		}

		if _, err := stmt.Exec(ind, iType, tName, sev, source, nowStr); err == nil {
			imported++
		} else {
			skipped++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	InitGeoIPAndThreatIntel()
	return imported, skipped, nil
}

// SaveUploadedMMDBFile 儲存管理員上傳的 MaxMind GeoLite2 .mmdb 檔案至 geoip/ 目錄並立即熱重載
func SaveUploadedMMDBFile(fileName string, reader io.Reader) error {
	base := filepath.Base(strings.TrimSpace(fileName))
	if !strings.HasSuffix(strings.ToLower(base), ".mmdb") {
		return errors.New("僅接受 .mmdb 格式的 MaxMind GeoLite2 資料庫檔案")
	}
	geoDir := getGeoIPDir()
	destPath := filepath.Join(geoDir, base)
	tmpPath := destPath + ".tmp"

	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, reader); err != nil {
		out.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	out.Close()

	// 驗證是否為合法 MMDB 二進位檔
	if testR, err := openMMDBFile(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("MMDB 檔案格式驗證失敗: %w", err)
	} else {
		_ = testR
	}

	_ = os.Remove(destPath)
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	InitGeoIPAndThreatIntel()
	return nil
}

// =========================================================================
// 3. 線上自動更新排程器 (Auto-Sync Scheduler) & 按需線上深度情資查詢
// =========================================================================

type GeoIntelSyncConfig struct {
	AutoEnabled    bool   `json:"auto_enabled"`
	SyncHour       int    `json:"sync_hour"`       // 每日自動更新小時 (0~23，預設 3 點)
	SyncIOC        bool   `json:"sync_ioc"`        // 是否同步開源 IOC 惡意 IP/C2 黑名單
	SyncMMDB       bool   `json:"sync_mmdb"`       // 是否同步 MaxMind GeoLite2 MMDB 資料庫
	CountryMMDBURL string `json:"country_mmdb_url"`
	ASNMMDBURL     string `json:"asn_mmdb_url"`
}

type GeoIntelSyncStatus struct {
	IsRunning       bool               `json:"is_running"`
	LastSyncTime    string             `json:"last_sync_time"`
	LastSyncStatus  string             `json:"last_sync_status"` // idle / running / success / partial / error
	LastSyncSummary string             `json:"last_sync_summary"`
	NextRunTime     string             `json:"next_run_time"`
	Logs            []string           `json:"logs"`
	Config          GeoIntelSyncConfig `json:"config"`
}

type openSourceIOCFeed struct {
	Name       string
	URL        string
	IOCType    string
	ThreatName string
	Severity   string
}

var defaultOpenSourceIOCFeeds = []openSourceIOCFeed{
	{
		Name:       "Abuse.ch Feodo",
		URL:        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		IOCType:    "C2",
		ThreatName: "Abuse.ch Feodo 殭屍網路 C2 中繼站",
		Severity:   "CRITICAL",
	},
	{
		Name:       "Abuse.ch SSLBL",
		URL:        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
		IOCType:    "C2",
		ThreatName: "Abuse.ch 惡意 SSL 憑證 C2 伺服器",
		Severity:   "CRITICAL",
	},
	{
		Name:       "Spamhaus DROP",
		URL:        "https://www.spamhaus.org/drop/drop.txt",
		IOCType:    "Botnet",
		ThreatName: "Spamhaus DROP 高風險惡意劫持網段",
		Severity:   "HIGH",
	},
	{
		Name:       "Spamhaus EDROP",
		URL:        "https://www.spamhaus.org/drop/edrop.txt",
		IOCType:    "Botnet",
		ThreatName: "Spamhaus EDROP 延伸惡意網段",
		Severity:   "HIGH",
	},
	{
		Name:       "Emerging Threats",
		URL:        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
		IOCType:    "Malware",
		ThreatName: "Emerging Threats 攻擊者黑名單",
		Severity:   "HIGH",
	},
}

const (
	defaultCountryMMDBPrimary  = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
	defaultCountryMMDBFallback = "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb"
	defaultASNMMDBPrimary      = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
	defaultASNMMDBFallback     = "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-ASN.mmdb"
)

var (
	geoSyncRunMux      sync.Mutex
	geoSyncStateMux    sync.RWMutex
	geoSyncIsRunning   bool
	geoSyncLastTime    string
	geoSyncLastStatus  = "idle"
	geoSyncLastSummary = "尚未執行線上同步"
	geoSyncLogs        []string
	geoSchedulerOnce   sync.Once
)

func appendGeoSyncLog(msg string) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	fmt.Println("🌐 [GeoIP/IOC 線上更新]", line)
	geoSyncStateMux.Lock()
	geoSyncLogs = append(geoSyncLogs, line)
	if len(geoSyncLogs) > 80 {
		geoSyncLogs = geoSyncLogs[len(geoSyncLogs)-80:]
	}
	geoSyncStateMux.Unlock()
}

// GetGeoIntelSyncConfig 從 SQLite system_settings 讀取線上自動更新設定
func GetGeoIntelSyncConfig() GeoIntelSyncConfig {
	cfg := GeoIntelSyncConfig{
		AutoEnabled:    true,
		SyncHour:       3,
		SyncIOC:        true,
		SyncMMDB:       true,
		CountryMMDBURL: defaultCountryMMDBPrimary,
		ASNMMDBURL:     defaultASNMMDBPrimary,
	}

	db, err := initDB()
	if err != nil || db == nil {
		return cfg
	}

	readKey := func(k string) (string, bool) {
		var v string
		if err := db.QueryRow("SELECT value FROM system_settings WHERE key = ?", k).Scan(&v); err == nil {
			return strings.TrimSpace(v), true
		}
		return "", false
	}

	if v, ok := readKey("geoip_sync_auto_enabled"); ok {
		cfg.AutoEnabled = (v == "1" || strings.EqualFold(v, "true"))
	}
	if v, ok := readKey("geoip_sync_hour"); ok {
		if h, err := strconv.Atoi(v); err == nil && h >= 0 && h <= 23 {
			cfg.SyncHour = h
		}
	}
	if v, ok := readKey("geoip_sync_ioc"); ok {
		cfg.SyncIOC = (v == "1" || strings.EqualFold(v, "true"))
	}
	if v, ok := readKey("geoip_sync_mmdb"); ok {
		cfg.SyncMMDB = (v == "1" || strings.EqualFold(v, "true"))
	}
	if v, ok := readKey("geoip_country_mmdb_url"); ok && v != "" {
		cfg.CountryMMDBURL = v
	}
	if v, ok := readKey("geoip_asn_mmdb_url"); ok && v != "" {
		cfg.ASNMMDBURL = v
	}
	if v, ok := readKey("geoip_last_sync_time"); ok && v != "" {
		geoSyncStateMux.Lock()
		if geoSyncLastTime == "" {
			geoSyncLastTime = v
		}
		geoSyncStateMux.Unlock()
	}
	if v, ok := readKey("geoip_last_sync_summary"); ok && v != "" {
		geoSyncStateMux.Lock()
		if geoSyncLastSummary == "尚未執行線上同步" {
			geoSyncLastSummary = v
		}
		geoSyncStateMux.Unlock()
	}

	return cfg
}

// SaveGeoIntelSyncConfig 儲存線上自動更新排程設定至 SQLite system_settings
func SaveGeoIntelSyncConfig(cfg GeoIntelSyncConfig) error {
	if cfg.SyncHour < 0 || cfg.SyncHour > 23 {
		cfg.SyncHour = 3
	}
	if strings.TrimSpace(cfg.CountryMMDBURL) == "" {
		cfg.CountryMMDBURL = defaultCountryMMDBPrimary
	}
	if strings.TrimSpace(cfg.ASNMMDBURL) == "" {
		cfg.ASNMMDBURL = defaultASNMMDBPrimary
	}

	db, err := initDB()
	if err != nil || db == nil {
		return errors.New("資料庫連線失敗")
	}

	boolToStr := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}

	pairs := map[string]string{
		"geoip_sync_auto_enabled": boolToStr(cfg.AutoEnabled),
		"geoip_sync_hour":         strconv.Itoa(cfg.SyncHour),
		"geoip_sync_ioc":          boolToStr(cfg.SyncIOC),
		"geoip_sync_mmdb":         boolToStr(cfg.SyncMMDB),
		"geoip_country_mmdb_url":  strings.TrimSpace(cfg.CountryMMDBURL),
		"geoip_asn_mmdb_url":      strings.TrimSpace(cfg.ASNMMDBURL),
	}

	for k, v := range pairs {
		if _, err := db.Exec("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", k, v); err != nil {
			return err
		}
	}
	return nil
}

func computeNextGeoSyncTime(cfg GeoIntelSyncConfig) string {
	if !cfg.AutoEnabled {
		return "已停用自動排程 (僅手動觸發)"
	}
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), cfg.SyncHour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Format("2006-01-02 15:04")
}

// GetGeoIntelSyncStatus 回傳目前排程器設定、執行進度與近期日誌
func GetGeoIntelSyncStatus() GeoIntelSyncStatus {
	cfg := GetGeoIntelSyncConfig()
	geoSyncStateMux.RLock()
	defer geoSyncStateMux.RUnlock()

	logsCopy := make([]string, len(geoSyncLogs))
	copy(logsCopy, geoSyncLogs)

	lastT := geoSyncLastTime
	if lastT == "" {
		lastT = "-"
	}

	return GeoIntelSyncStatus{
		IsRunning:       geoSyncIsRunning,
		LastSyncTime:    lastT,
		LastSyncStatus:  geoSyncLastStatus,
		LastSyncSummary: geoSyncLastSummary,
		NextRunTime:     computeNextGeoSyncTime(cfg),
		Logs:            logsCopy,
		Config:          cfg,
	}
}

// downloadURLWithUA 透過標準 HTTPS/HTTP 下載資源（含合理 User-Agent 與 90 秒逾時）
func downloadURLWithUA(targetURL string, timeout time.Duration) ([]byte, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		return nil, fmt.Errorf("不支援的 URL 協定: %s", targetURL)
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PA-Monitor-ThreatIntel-Updater/2.2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d (%s)", resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// syncSingleIOCFeed 下載單一開源 IOC 黑名單並與 SQLite 同步（保留手動匯入項目，清除該來源已下架的舊規則）
func syncSingleIOCFeed(feed openSourceIOCFeed) (int, error) {
	rawBytes, err := downloadURLWithUA(feed.URL, 30*time.Second)
	if err != nil {
		return 0, err
	}

	type parsedIOC struct {
		indicator string
		comment   string
	}
	var parsedList []parsedIOC
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(rawBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		comment := ""
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			comment = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.Split(line, ",")
		ind := strings.TrimSpace(parts[0])
		if ind == "" || strings.EqualFold(ind, "ip") || strings.EqualFold(ind, "indicator") {
			continue
		}

		if strings.Contains(ind, "/") {
			if _, ipNet, err := net.ParseCIDR(ind); err == nil {
				ind = ipNet.String()
			} else {
				continue
			}
		} else if p := net.ParseIP(ind); p != nil {
			ind = p.String()
		} else {
			continue
		}

		if !seen[ind] {
			seen[ind] = true
			parsedList = append(parsedList, parsedIOC{indicator: ind, comment: comment})
		}
	}

	if len(parsedList) == 0 {
		return 0, errors.New("來源清單內容為空或格式無法解析")
	}

	db, err := initDB()
	if err != nil || db == nil {
		return 0, errors.New("資料庫連線失敗")
	}
	_ = ensureThreatIntelTable(db)

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 先清除該自動更新來源的舊條目，避免長期累積已解除封鎖的過期 IP
	_, _ = tx.Exec("DELETE FROM threat_intel_iocs WHERE source = ?", feed.Name)

	stmt, err := tx.Prepare(`
		INSERT INTO threat_intel_iocs (indicator, ioc_type, threat_name, severity, source, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(indicator) DO UPDATE SET
			ioc_type = excluded.ioc_type,
			threat_name = excluded.threat_name,
			severity = excluded.severity,
			source = excluded.source,
			enabled = 1,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	inserted := 0
	for _, item := range parsedList {
		desc := feed.ThreatName
		if item.comment != "" && len(item.comment) <= 48 {
			desc = fmt.Sprintf("%s (%s)", feed.ThreatName, item.comment)
		}
		if _, err := stmt.Exec(item.indicator, feed.IOCType, desc, feed.Severity, feed.Name, nowStr); err == nil {
			inserted++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

// downloadAndInstallMMDB 從指定 URL（支援 .mmdb 與 .mmdb.gz）下載、驗證並原子替換本地 MMDB 檔
func downloadAndInstallMMDB(destFileName string, urls []string) (int64, error) {
	var lastErr error
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		raw, err := downloadURLWithUA(u, 90*time.Second)
		if err != nil {
			lastErr = err
			continue
		}

		// 若為 GZIP 壓縮檔 (.gz 或檔頭 0x1f 0x8b)，自動解壓縮
		if strings.HasSuffix(strings.ToLower(u), ".gz") || (len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b) {
			gzReader, gzErr := gzip.NewReader(bytes.NewReader(raw))
			if gzErr != nil {
				lastErr = fmt.Errorf("GZIP 解壓縮失敗: %w", gzErr)
				continue
			}
			decompressed, readErr := io.ReadAll(gzReader)
			gzReader.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("讀取解壓縮串流失敗: %w", readErr)
				continue
			}
			raw = decompressed
		}

		if err := SaveUploadedMMDBFile(destFileName, bytes.NewReader(raw)); err != nil {
			lastErr = err
			continue
		}
		return int64(len(raw)), nil
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, errors.New("未提供有效的 MMDB 下載網址")
}

// TriggerGeoIPAndIOCSyncNow 執行線上情資與 MMDB 同步（mode: "all" | "ioc" | "mmdb"）
func TriggerGeoIPAndIOCSyncNow(mode string) bool {
	if !geoSyncRunMux.TryLock() {
		return false
	}

	go func(syncMode string) {
		defer geoSyncRunMux.Unlock()

		cfg := GetGeoIntelSyncConfig()
		doIOC := (syncMode == "all" || syncMode == "ioc" || (syncMode == "" && cfg.SyncIOC))
		doMMDB := (syncMode == "all" || syncMode == "mmdb" || (syncMode == "" && cfg.SyncMMDB))
		if !doIOC && !doMMDB {
			doIOC = true
			doMMDB = true
		}

		geoSyncStateMux.Lock()
		geoSyncIsRunning = true
		geoSyncLastStatus = "running"
		geoSyncLogs = nil
		geoSyncStateMux.Unlock()

		startT := time.Now()
		appendGeoSyncLog(fmt.Sprintf("🚀 啟動線上威脅情資與 GeoIP 同步作業 (模式: %s)...", strings.ToUpper(syncMode)))

		var totalIOCRules int
		var iocSuccessFeeds, iocFailFeeds int
		var mmdbSuccessCount, mmdbFailCount int

		// 1. 同步開源惡意 IP / C2 黑名單
		if doIOC {
			for _, feed := range defaultOpenSourceIOCFeeds {
				appendGeoSyncLog(fmt.Sprintf("⏳ 正在下載情資清單 [%s]...", feed.Name))
				cnt, err := syncSingleIOCFeed(feed)
				if err != nil {
					iocFailFeeds++
					appendGeoSyncLog(fmt.Sprintf("⚠️ [%s] 下載失敗: %v", feed.Name, err))
				} else {
					iocSuccessFeeds++
					totalIOCRules += cnt
					appendGeoSyncLog(fmt.Sprintf("✅ [%s] 同步完成，更新 %d 筆惡意指標", feed.Name, cnt))
				}
			}
			InitGeoIPAndThreatIntel()
		}

		// 2. 同步 MaxMind GeoLite2 MMDB 離線資料庫 (Country + ASN)
		if doMMDB {
			countryURLs := []string{cfg.CountryMMDBURL}
			if cfg.CountryMMDBURL == defaultCountryMMDBPrimary {
				countryURLs = append(countryURLs, defaultCountryMMDBFallback)
			}
			appendGeoSyncLog("⏳ 正在下載並驗證 GeoLite2-Country.mmdb...")
			if sz, err := downloadAndInstallMMDB("GeoLite2-Country.mmdb", countryURLs); err != nil {
				mmdbFailCount++
				appendGeoSyncLog(fmt.Sprintf("⚠️ GeoLite2-Country.mmdb 更新失敗: %v", err))
			} else {
				mmdbSuccessCount++
				appendGeoSyncLog(fmt.Sprintf("✅ GeoLite2-Country.mmdb 已熱重載 (%.2f MB)", float64(sz)/1024/1024))
			}

			asnURLs := []string{cfg.ASNMMDBURL}
			if cfg.ASNMMDBURL == defaultASNMMDBPrimary {
				asnURLs = append(asnURLs, defaultASNMMDBFallback)
			}
			appendGeoSyncLog("⏳ 正在下載並驗證 GeoLite2-ASN.mmdb...")
			if sz, err := downloadAndInstallMMDB("GeoLite2-ASN.mmdb", asnURLs); err != nil {
				mmdbFailCount++
				appendGeoSyncLog(fmt.Sprintf("⚠️ GeoLite2-ASN.mmdb 更新失敗: %v", err))
			} else {
				mmdbSuccessCount++
				appendGeoSyncLog(fmt.Sprintf("✅ GeoLite2-ASN.mmdb 已熱重載 (%.2f MB)", float64(sz)/1024/1024))
			}
		}

		elapsed := time.Since(startT).Seconds()
		nowStr := time.Now().Format("2006-01-02 15:04:05")
		statusStr := "success"
		if (iocFailFeeds > 0 || mmdbFailCount > 0) && (iocSuccessFeeds > 0 || mmdbSuccessCount > 0) {
			statusStr = "partial"
		} else if iocSuccessFeeds == 0 && mmdbSuccessCount == 0 {
			statusStr = "error"
		}

		summary := fmt.Sprintf("IOC 成功 %d/%d 源 (共 %d 條)｜MMDB 成功 %d 檔｜耗時 %.1fs",
			iocSuccessFeeds, len(defaultOpenSourceIOCFeeds), totalIOCRules, mmdbSuccessCount, elapsed)
		appendGeoSyncLog("🏁 同步作業結束：" + summary)

		geoSyncStateMux.Lock()
		geoSyncIsRunning = false
		geoSyncLastTime = nowStr
		geoSyncLastStatus = statusStr
		geoSyncLastSummary = summary
		geoSyncStateMux.Unlock()

		if db, err := initDB(); err == nil && db != nil {
			_, _ = db.Exec("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('geoip_last_sync_time', ?)", nowStr)
			_, _ = db.Exec("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('geoip_last_sync_summary', ?)", summary)
			_, _ = db.Exec("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('geoip_last_sync_date', ?)", time.Now().Format("2006-01-02"))
		}
	}(mode)

	return true
}

// StartGeoIPAndIOCAutoUpdater 啟動背景每日自動排程器（每分鐘檢查是否抵達設定小時且當日尚未更新）
func StartGeoIPAndIOCAutoUpdater() {
	geoSchedulerOnce.Do(func() {
		go func() {
			time.Sleep(20 * time.Second)
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()

			for range ticker.C {
				cfg := GetGeoIntelSyncConfig()
				if !cfg.AutoEnabled {
					continue
				}
				now := time.Now()
				if now.Hour() != cfg.SyncHour {
					continue
				}

				todayStr := now.Format("2006-01-02")
				alreadyRanToday := false
				if db, err := initDB(); err == nil && db != nil {
					var lastDate string
					if err := db.QueryRow("SELECT value FROM system_settings WHERE key = 'geoip_last_sync_date'").Scan(&lastDate); err == nil {
						if strings.TrimSpace(lastDate) == todayStr {
							alreadyRanToday = true
						}
					}
				}
				if !alreadyRanToday {
					TriggerGeoIPAndIOCSyncNow("all")
				}
			}
		}()
	})
}

// LookupOnlineGeoIPDeep 按需呼叫免費開源 ip-api.com 進行單一外部 IP 或 CIDR 網段代表節點深度交叉查詢（含 Proxy/Hosting 偵測）
func LookupOnlineGeoIPDeep(rawIP string) map[string]interface{} {
	localRes := LookupGeoIPAndIOC(rawIP)
	out := map[string]interface{}{
		"local":          localRes,
		"online_enabled": false,
	}

	parsed, _, isCIDR, normCIDR, valid := parseLookupTarget(rawIP)
	if !valid || parsed == nil {
		out["online_note"] = "格式錯誤：請輸入有效的 IPv4/IPv6 位址或 CIDR 網段（例如 34.96.0.0/16）"
		return out
	}
	if localRes.IsInternal {
		out["online_note"] = "內網私有位址/網段無需發送外部查詢"
		return out
	}
	if isCIDR {
		out["cidr_note"] = fmt.Sprintf("網段 %s 已自動取代表節點 %s 進行交叉驗證", normCIDR, parsed.String())
	}

	apiURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting&lang=zh-CN", parsed.String())
	raw, err := downloadURLWithUA(apiURL, 5*time.Second)
	if err != nil {
		out["online_note"] = "線上查詢連線逾時或受限: " + err.Error()
		return out
	}

	var apiResp map[string]interface{}
	if err := json.Unmarshal(raw, &apiResp); err == nil && fmt.Sprintf("%v", apiResp["status"]) == "success" {
		cc := strings.ToUpper(strings.TrimSpace(fmt.Sprintf("%v", apiResp["countryCode"])))
		rawCountry := fmt.Sprintf("%v", apiResp["country"])
		if rawCountry == "<nil>" {
			rawCountry = ""
		}
		apiResp["country"] = formatCountryZH(cc, rawCountry)
		for _, field := range []string{"regionName", "city", "isp", "org"} {
			if v, ok := apiResp[field].(string); ok && v != "" {
				apiResp[field] = simplifiedToTraditionalZH(v)
			}
		}
		out["online_enabled"] = true
		out["online"] = apiResp
	} else {
		out["online_note"] = fmt.Sprintf("線上查詢未回傳有效結果: %v", apiResp["message"])
	}
	return out
}
