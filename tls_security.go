package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// =========================================================================
// 🔒 TLS 1.2+ HTTPS 憑證自動簽發與高強度加密組態
// =========================================================================

// ensureServerTLSCertificates 檢查並自動產生 ECDSA P-256 自簽憑證（支援所有本機網卡 IP SAN）
func ensureServerTLSCertificates(certPath, keyPath string) error {
	if fiC, errC := os.Stat(certPath); errC == nil && fiC.Size() > 0 {
		if fiK, errK := os.Stat(keyPath); errK == nil && fiK.Size() > 0 {
			if _, loadErr := tls.LoadX509KeyPair(certPath, keyPath); loadErr == nil {
				return nil
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("建立憑證目錄失敗: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("產生 ECDSA P-256 私鑰失敗: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("產生憑證序號失敗: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "pa-monitor.local"
	}

	dnsNames := []string{"localhost", hostname}
	ipAddrs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	// 自動納入本機所有網卡 IPv4 / IPv6 位址至 SAN，避免瀏覽器憑證主機名稱不符警告
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() {
					ipAddrs = append(ipAddrs, ip)
				}
			}
		}
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"PA Monitor Security Operations"},
			OrganizationalUnit: []string{"NGFW Log Lakehouse"},
			CommonName:         hostname,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0), // 10 年效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("簽發 X.509 憑證失敗: %w", err)
	}

	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("寫入憑證檔失敗: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("序列化 EC 私鑰失敗: %w", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("寫入私鑰檔失敗: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}

	return nil
}

// buildStrictTLSConfig 建立強制 TLS 1.2 以上（支援 TLS 1.2 / TLS 1.3）且僅允許 AEAD 強加密套件的 TLS 組態
func buildStrictTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12, // 強制最低 TLS 1.2，完全封鎖 SSLv3 / TLS 1.0 / TLS 1.1
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

// securityHeadersMiddleware 為所有 HTTP/HTTPS 回應加上縱深防禦安全標頭
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

// =========================================================================
// 🛡️ 綜合查詢欄嚴格語法解析器與防注入攻擊驗證引擎
// =========================================================================

type ValidatedTrafficFilter struct {
	StartDate       string
	EndDate         string
	Days            int
	Src             string
	NatSrc          string
	Dst             string
	NatDst          string
	Dport           string
	App             string
	Action          string
	Zone            string
	Rule            string
	Reason          string
	TimeLeq         string
	TimeGeq         string
	ShowDailyRollup bool
}

var (
	reStrictDate     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reSafeAppToken   = regexp.MustCompile(`^[a-zA-Z0-9._\-*]{1,64}$`)
	reSafeZoneToken  = regexp.MustCompile(`^[a-zA-Z0-9._\-]{1,64}$`)
	reSafeRuleToken  = regexp.MustCompile(`^[a-zA-Z0-9._\-\s\p{Han}]{1,128}$`)
	reSafeReasonTok  = regexp.MustCompile(`^[a-zA-Z0-9._\-\s]{1,64}$`)
	reIPWildcardTok  = regexp.MustCompile(`^[0-9a-fA-F:.*/?]{1,64}$`)
	reDportRangeTok  = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?$`)
	reDateOnlyTok    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})$`)
	reDateHourTok    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{1,2})$`)
	reDateHourMinTok = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{1,2}):(\d{2})$`)
	reDateFullTok    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{1,2}):(\d{2}):(\d{2})$`)
	reTimeOnlyHTok   = regexp.MustCompile(`^(\d{1,2})$`)
	reTimeOnlyHMTok  = regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)
	reTimeOnlyHMSTok = regexp.MustCompile(`^(\d{1,2}):(\d{2}):(\d{2})$`)
	reSQLInjectProbe = regexp.MustCompile(`(?i)(?:--|/\*|\*/|;|\x00|\bunion\b\s+\bselect\b|\bdrop\b\s+\btable\b|\bdelete\b\s+\bfrom\b|\binsert\b\s+\binto\b|\bupdate\b\s+\w+\s+\bset\b|\battach\b\s+|\bpragma\b\s+|\bread_parquet\b|\bcopy\b\s*\(|\bload_extension\b|\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?)`)
)

// escapeSQLLikeLiteral 安全跳脫 SQL LIKE 特殊萬用字元 (\, %, _) 與單引號
func escapeSQLLikeLiteral(val string) string {
	s := strings.ReplaceAll(val, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// normalizeFlexibleDateTimeBound 解析並正規化日期與時間邊界（支援 YYYY-MM-DD、YYYY-MM-DD HH、YYYY-MM-DD HH:MM、YYYY-MM-DD HH:MM:SS，以及純時間 22 / 22:10 / 22:10:10）
// 回傳：(解析出的日期部分若有, 正規化後的完整時間字串 YYYY-MM-DD HH:MM:SS, 錯誤)
func normalizeFlexibleDateTimeBound(raw, fallbackDate string, isUpperBound bool) (string, string, error) {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "T", " ")
	s = strings.ReplaceAll(s, "@", " ")
	s = strings.Join(strings.Fields(s), " ")

	validateHMS := func(hStr, mStr, secStr string) (int, int, int, error) {
		h, err1 := strconv.Atoi(hStr)
		m, err2 := strconv.Atoi(mStr)
		sec, err3 := strconv.Atoi(secStr)
		if err1 != nil || err2 != nil || err3 != nil || h < 0 || h > 23 || m < 0 || m > 59 || sec < 0 || sec > 59 {
			return 0, 0, 0, fmt.Errorf("時間數值超出合法範圍（時 0~23、分 0~59、秒 0~59）：%s", raw)
		}
		return h, m, sec, nil
	}

	// 1. 純日期：YYYY-MM-DD
	if m := reDateOnlyTok.FindStringSubmatch(s); len(m) == 2 {
		if !isValidDateStr(m[1]) {
			return "", "", fmt.Errorf("無效的日曆日期：%s", m[1])
		}
		if isUpperBound {
			return m[1], m[1] + " 23:59:59", nil
		}
		return m[1], m[1] + " 00:00:00", nil
	}

	// 2. 日期 + 小時：YYYY-MM-DD HH (例如 2026-11-14 22)
	if m := reDateHourTok.FindStringSubmatch(s); len(m) == 3 {
		if !isValidDateStr(m[1]) {
			return "", "", fmt.Errorf("無效的日曆日期：%s", m[1])
		}
		h, _, _, err := validateHMS(m[2], "00", "00")
		if err != nil {
			return "", "", err
		}
		if isUpperBound {
			return m[1], fmt.Sprintf("%s %02d:59:59", m[1], h), nil
		}
		return m[1], fmt.Sprintf("%s %02d:00:00", m[1], h), nil
	}

	// 3. 日期 + 時:分：YYYY-MM-DD HH:MM (例如 2026-11-14 22:10)
	if m := reDateHourMinTok.FindStringSubmatch(s); len(m) == 4 {
		if !isValidDateStr(m[1]) {
			return "", "", fmt.Errorf("無效的日曆日期：%s", m[1])
		}
		h, minVal, _, err := validateHMS(m[2], m[3], "00")
		if err != nil {
			return "", "", err
		}
		if isUpperBound {
			return m[1], fmt.Sprintf("%s %02d:%02d:59", m[1], h, minVal), nil
		}
		return m[1], fmt.Sprintf("%s %02d:%02d:00", m[1], h, minVal), nil
	}

	// 4. 日期 + 時:分:秒：YYYY-MM-DD HH:MM:SS (例如 2026-11-14 22:10:10)
	if m := reDateFullTok.FindStringSubmatch(s); len(m) == 5 {
		if !isValidDateStr(m[1]) {
			return "", "", fmt.Errorf("無效的日曆日期：%s", m[1])
		}
		h, minVal, secVal, err := validateHMS(m[2], m[3], m[4])
		if err != nil {
			return "", "", err
		}
		return m[1], fmt.Sprintf("%s %02d:%02d:%02d", m[1], h, minVal, secVal), nil
	}

	// 5. 純小時：22（自動套用基準日期）
	if m := reTimeOnlyHTok.FindStringSubmatch(s); len(m) == 2 {
		h, _, _, err := validateHMS(m[1], "00", "00")
		if err != nil {
			return "", "", err
		}
		if isUpperBound {
			return "", fmt.Sprintf("%s %02d:59:59", fallbackDate, h), nil
		}
		return "", fmt.Sprintf("%s %02d:00:00", fallbackDate, h), nil
	}

	// 6. 純時:分：22:10（自動套用基準日期）
	if m := reTimeOnlyHMTok.FindStringSubmatch(s); len(m) == 3 {
		h, minVal, _, err := validateHMS(m[1], m[2], "00")
		if err != nil {
			return "", "", err
		}
		if isUpperBound {
			return "", fmt.Sprintf("%s %02d:%02d:59", fallbackDate, h, minVal), nil
		}
		return "", fmt.Sprintf("%s %02d:%02d:00", fallbackDate, h, minVal), nil
	}

	// 7. 純時:分:秒：22:10:10（自動套用基準日期）
	if m := reTimeOnlyHMSTok.FindStringSubmatch(s); len(m) == 4 {
		h, minVal, secVal, err := validateHMS(m[1], m[2], m[3])
		if err != nil {
			return "", "", err
		}
		return "", fmt.Sprintf("%s %02d:%02d:%02d", fallbackDate, h, minVal, secVal), nil
	}

	return "", "", fmt.Errorf("時間格式不合法（%s），支援格式：'2026-11-14'、'2026-11-14 22'、'2026-11-14 22:10'、'2026-11-14 22:10:10' 或純時間 '22' / '22:10' / '22:10:10'", raw)
}

// isValidDateStr 驗證 YYYY-MM-DD 是否為合法日曆日期
func isValidDateStr(d string) bool {
	if !reStrictDate.MatchString(d) {
		return false
	}
	_, err := time.Parse("2006-01-02", d)
	return err == nil
}

// validateIPFilterValue 嚴格檢查 IP / CIDR / 萬用字元格式
func validateIPFilterValue(field, val string) error {
	if len(val) > 64 || !reIPWildcardTok.MatchString(val) {
		return fmt.Errorf("欄位「%s」的 IP 格式不合法（%s），僅允許 IPv4/IPv6、CIDR（如 192.168.1.0/24）或萬用字元（如 192.168.1.*）", field, val)
	}
	if strings.Contains(val, "/") {
		if _, _, err := net.ParseCIDR(val); err != nil {
			return fmt.Errorf("欄位「%s」的 CIDR 網段不合法（%s），正確範例：192.168.1.0/24", field, val)
		}
		return nil
	}
	if strings.ContainsAny(val, "*?") {
		return nil
	}
	if net.ParseIP(val) != nil {
		return nil
	}
	// 允許 IPv4 前綴片段（如 192.168.1 或 10.50）
	parts := strings.Split(val, ".")
	if len(parts) >= 2 && len(parts) <= 4 {
		allNum := true
		for _, p := range parts {
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				allNum = false
				break
			}
		}
		if allNum {
			return nil
		}
	}
	return fmt.Errorf("欄位「%s」的 IP 位址不合法（%s），請輸入有效 IP（如 192.168.1.10）、CIDR 或萬用字元", field, val)
}

// validateSingleFieldValue 針對單一預設欄位執行白名單型別與防注入驗證
func validateSingleFieldValue(key, val string, out *ValidatedTrafficFilter) error {
	if val == "" {
		return fmt.Errorf("欄位「%s」不可為空值，請於冒號後方輸入對應條件（例如 %s:範例值）", key, key)
	}
	if reSQLInjectProbe.MatchString(val) || strings.ContainsAny(val, ";\x00\r\n`$<>|") {
		return fmt.Errorf("偵測到不安全的特殊字元或疑似注入語法於欄位「%s」，系統已主動攔截", key)
	}

	switch key {
	case "src":
		if err := validateIPFilterValue("src", val); err != nil {
			return err
		}
		out.Src = val
	case "natsrc":
		if err := validateIPFilterValue("natsrc", val); err != nil {
			return err
		}
		out.NatSrc = val
	case "dst":
		if err := validateIPFilterValue("dst", val); err != nil {
			return err
		}
		out.Dst = val
	case "natdst":
		if err := validateIPFilterValue("natdst", val); err != nil {
			return err
		}
		out.NatDst = val
	case "dport":
		m := reDportRangeTok.FindStringSubmatch(val)
		if len(m) == 0 {
			return fmt.Errorf("欄位「dport」格式錯誤（%s），請輸入 1~65535 的連接埠號（如 dport:443 或 dport:8000-9000）", val)
		}
		p1, _ := strconv.Atoi(m[1])
		if p1 < 1 || p1 > 65535 {
			return fmt.Errorf("欄位「dport」連接埠超出有效範圍 1~65535（%s）", val)
		}
		if m[2] != "" {
			p2, _ := strconv.Atoi(m[2])
			if p2 < 1 || p2 > 65535 || p1 > p2 {
				return fmt.Errorf("欄位「dport」連接埠區間不合法（%s），起始埠須小於或等於結束埠", val)
			}
		}
		out.Dport = val
	case "app":
		if !reSafeAppToken.MatchString(val) {
			return fmt.Errorf("欄位「app」格式不合法（%s），僅允許英數字、連字號、底線與萬用字元（如 app:ssl 或 app:web-browsing）", val)
		}
		out.App = val
	case "action":
		act := strings.ToLower(val)
		switch act {
		case "allow", "deny", "drop", "deny_drop", "reset-both", "reset-client", "reset-server":
			out.Action = act
		default:
			return fmt.Errorf("欄位「action」僅接受 allow、deny、drop、deny_drop、reset-both、reset-client 或 reset-server（目前輸入：%s）", val)
		}
	case "zone":
		if !reSafeZoneToken.MatchString(val) {
			return fmt.Errorf("欄位「zone」格式不合法（%s），僅允許英數字、底線與連字號（如 zone:LAN 或 zone:WAN）", val)
		}
		out.Zone = val
	case "rule":
		if !reSafeRuleToken.MatchString(val) {
			return fmt.Errorf("欄位「rule」包含不允許的特殊符號（%s），若規則名稱含空白請以雙引號包覆（如 rule:\"Allow Outbound\"）", val)
		}
		out.Rule = val
	case "reason":
		if !reSafeReasonTok.MatchString(val) {
			return fmt.Errorf("欄位「reason」格式不合法（%s），僅允許英數字與連字號（如 reason:tcp-fin 或 reason:aged-out）", val)
		}
		out.Reason = val
	case "date":
		norm := strings.ReplaceAll(val, "/", "-")
		var parts []string
		if strings.Contains(norm, "..") {
			parts = strings.Split(norm, "..")
		} else if strings.Contains(norm, "~") {
			parts = strings.Split(norm, "~")
		} else {
			parts = []string{norm}
		}
		if len(parts) == 1 {
			if !isValidDateStr(parts[0]) {
				return fmt.Errorf("欄位「date」日期格式錯誤（%s），正確格式為 YYYY-MM-DD 或 YYYY-MM-DD..YYYY-MM-DD", val)
			}
			out.StartDate = parts[0]
			out.EndDate = parts[0]
		} else if len(parts) == 2 {
			if !isValidDateStr(parts[0]) || !isValidDateStr(parts[1]) {
				return fmt.Errorf("欄位「date」跨日區間日期格式錯誤（%s），正確範例：date:2026-11-10..2026-11-14", val)
			}
			t1, _ := time.Parse("2006-01-02", parts[0])
			t2, _ := time.Parse("2006-01-02", parts[1])
			if t1.After(t2) {
				return fmt.Errorf("欄位「date」起始日期（%s）不可晚於結束日期（%s）", parts[0], parts[1])
			}
			if int(t2.Sub(t1).Hours()/24)+1 > 90 {
				return fmt.Errorf("跨日區間查詢上限為 90 天，請縮小查詢日期範圍")
			}
			out.StartDate = parts[0]
			out.EndDate = parts[1]
			if out.StartDate != out.EndDate {
				out.ShowDailyRollup = true
			}
		} else {
			return fmt.Errorf("欄位「date」格式錯誤（%s），正確範例：date:2026-11-10..2026-11-14", val)
		}
	case "days":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 90 {
			return fmt.Errorf("欄位「days」必須為 1~90 的整數天數（例如 days:7 或 days:30），目前輸入：%s", val)
		}
		out.Days = n
		if n > 1 {
			out.ShowDailyRollup = true
		}
	case "summary":
		sv := strings.ToLower(val)
		if sv != "daily" && sv != "rollup" {
			return fmt.Errorf("欄位「summary」目前僅支援 summary:daily（每日預聚合統計表），目前輸入：%s", val)
		}
		out.ShowDailyRollup = true
	case "leq", "time_leq":
		fallback := out.EndDate
		if fallback == "" {
			fallback = time.Now().Format("2006-01-02")
		}
		parsedDate, fullTS, err := normalizeFlexibleDateTimeBound(val, fallback, true)
		if err != nil {
			return err
		}
		out.TimeLeq = fullTS
		if parsedDate != "" {
			out.EndDate = parsedDate
			if out.TimeGeq == "" && out.Days == 0 && parsedDate < out.StartDate {
				out.StartDate = parsedDate
			}
		}
	case "geq", "time_geq":
		fallback := out.StartDate
		if fallback == "" {
			fallback = time.Now().Format("2006-01-02")
		}
		parsedDate, fullTS, err := normalizeFlexibleDateTimeBound(val, fallback, false)
		if err != nil {
			return err
		}
		out.TimeGeq = fullTS
		if parsedDate != "" {
			out.StartDate = parsedDate
			if out.TimeLeq == "" && out.Days == 0 && parsedDate > out.EndDate {
				out.EndDate = parsedDate
			}
		}
	case "time":
		var parts []string
		if strings.Contains(val, "..") {
			parts = strings.SplitN(val, "..", 2)
		} else if strings.Contains(val, "~") {
			parts = strings.SplitN(val, "~", 2)
		} else {
			parts = []string{val, val}
		}
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("欄位「time」格式錯誤（%s），正確範例：time:22:00..22:30 或 time:'2026-11-12..2026-11-14'", val)
		}
		if err := validateSingleFieldValue("geq", strings.TrimSpace(parts[0]), out); err != nil {
			return err
		}
		if err := validateSingleFieldValue("leq", strings.TrimSpace(parts[1]), out); err != nil {
			return err
		}
	case "time_generated":
		_ = val
	default:
		return fmt.Errorf("不支援的查詢欄位「%s」！允許欄位：src、natsrc、dst、natdst、dport、app、action、zone、rule、reason、date、days、summary、leq、geq", key)
	}
	return nil
}

// validateAndParseTrafficQuery 嚴格解析綜合查詢字串並驗證所有欄位（防語法錯誤與任何注入攻擊）
func validateAndParseTrafficQuery(rawQuery, baseDate string) (*ValidatedTrafficFilter, error) {
	out := &ValidatedTrafficFilter{
		Action: "all",
		Zone:   "all",
	}

	if baseDate != "" {
		cleanBase := strings.ReplaceAll(strings.TrimSpace(baseDate), "/", "-")
		if !isValidDateStr(cleanBase) {
			return nil, fmt.Errorf("基準日期格式不合法（%s），請使用 YYYY-MM-DD 格式", baseDate)
		}
		out.StartDate = cleanBase
		out.EndDate = cleanBase
	} else {
		today := time.Now().Format("2006-01-02")
		out.StartDate = today
		out.EndDate = today
	}

	q := strings.TrimSpace(rawQuery)
	if q == "" {
		return out, nil
	}

	if len(q) > 1024 {
		return nil, fmt.Errorf("查詢字串長度超過上限（1024 字元），請精簡查詢條件")
	}

	if reSQLInjectProbe.MatchString(q) || strings.ContainsAny(q, ";\x00\r\n`$<>|") {
		return nil, fmt.Errorf("偵測到不合法的特殊字元或疑似 SQL/指令注入語法，查詢已被安全機制攔截")
	}

	// 逐字元詞法掃描（支援引號包覆空白值，例如 rule:"Allow Web"）
	var tokens []string
	var cur strings.Builder
	inQuote := byte(0)

	for i := 0; i < len(q); i++ {
		ch := q[i]
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
				cur.WriteByte(ch)
			} else {
				cur.WriteByte(ch)
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			cur.WriteByte(ch)
			continue
		}
		if ch == ' ' || ch == '\t' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if inQuote != 0 {
		return nil, fmt.Errorf("查詢條件中的引號未正確閉合，請檢查雙引號或單引號是否成對")
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}

	expectCondition := true
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		upperTok := strings.ToUpper(tok)
		if upperTok == "AND" {
			if expectCondition {
				return nil, fmt.Errorf("邏輯運算子「AND」位置錯誤，不可連續出現或置於查詢開頭")
			}
			expectCondition = true
			continue
		}
		if upperTok == "OR" {
			return nil, fmt.Errorf("綜合查詢欄目前僅支援「AND」多條件交集組合，不支援「OR」運算子")
		}
		if !expectCondition {
			return nil, fmt.Errorf("條件「%s」前方缺少「AND」連接詞（正確範例：src:192.168.1.10 and dport:443）", tok)
		}

		// 🌟 支援精簡時間區間語法：leq 'YYYY-MM-DD HH:MM:SS' / geq 'YYYY-MM-DD HH:MM:SS'（同時相容舊版 time_generated leq/geq）
		if strings.EqualFold(tok, "leq") || strings.EqualFold(tok, "geq") {
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("「%s」後方缺少日期或時間值！正確範例：%s '2026-11-14 18:30:00'", strings.ToLower(tok), strings.ToLower(tok))
			}
			rawTS := strings.TrimSpace(tokens[i+1])
			if len(rawTS) >= 2 && ((rawTS[0] == '"' && rawTS[len(rawTS)-1] == '"') || (rawTS[0] == '\'' && rawTS[len(rawTS)-1] == '\'')) {
				rawTS = strings.TrimSpace(rawTS[1 : len(rawTS)-1])
			}
			if err := validateSingleFieldValue(strings.ToLower(tok), rawTS, out); err != nil {
				return nil, err
			}
			i += 1
			expectCondition = false
			continue
		}
		if strings.EqualFold(tok, "time_generated") {
			if i+2 >= len(tokens) {
				return nil, fmt.Errorf("時間語法不完整！建議使用精簡寫法：leq '2026-11-14 18:30:00'")
			}
			op := strings.ToLower(tokens[i+1])
			rawTS := strings.TrimSpace(tokens[i+2])
			if len(rawTS) >= 2 && ((rawTS[0] == '"' && rawTS[len(rawTS)-1] == '"') || (rawTS[0] == '\'' && rawTS[len(rawTS)-1] == '\'')) {
				rawTS = strings.TrimSpace(rawTS[1 : len(rawTS)-1])
			}
			switch op {
			case "leq", "<=", "lt", "<":
				if err := validateSingleFieldValue("leq", rawTS, out); err != nil {
					return nil, err
				}
			case "geq", ">=", "gt", ">":
				if err := validateSingleFieldValue("geq", rawTS, out); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("時間運算子僅支援 leq（小於等於）或 geq（大於等於），目前輸入：%s", tokens[i+1])
			}
			i += 2
			expectCondition = false
			continue
		}

		sepIdx := strings.IndexAny(tok, ":=")
		if sepIdx <= 0 {
			return nil, fmt.Errorf("查詢項目「%s」未指定預設欄位名稱！所有條件皆須符合「欄位:值」格式（例如 src:192.168.1.1 或 app:ssl）", tok)
		}
		key := strings.ToLower(strings.TrimSpace(tok[:sepIdx]))
		val := strings.TrimSpace(tok[sepIdx+1:])
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = strings.TrimSpace(val[1 : len(val)-1])
		}

		if err := validateSingleFieldValue(key, val, out); err != nil {
			return nil, err
		}
		expectCondition = false
	}

	if expectCondition {
		return nil, fmt.Errorf("「AND」後方缺少查詢條件，請補上「欄位:值」或移除尾端的 AND")
	}

	// 若指定了 days:N（且未另外指定 date:START..END），以基準結束日往回推算 N 天
	if out.Days > 0 {
		endT, err := time.Parse("2006-01-02", out.EndDate)
		if err != nil {
			endT = time.Now()
			out.EndDate = endT.Format("2006-01-02")
		}
		out.StartDate = endT.AddDate(0, 0, -(out.Days - 1)).Format("2006-01-02")
	}

	if out.StartDate != "" && out.EndDate != "" {
		t1, e1 := time.Parse("2006-01-02", out.StartDate)
		t2, e2 := time.Parse("2006-01-02", out.EndDate)
		if e1 == nil && e2 == nil {
			if t1.After(t2) {
				return nil, fmt.Errorf("起始日期時間（%s）不可晚於結束日期時間（%s）", out.StartDate, out.EndDate)
			}
			if int(t2.Sub(t1).Hours()/24)+1 > 90 {
				return nil, fmt.Errorf("跨日區間查詢上限為 90 天，請縮小查詢日期範圍")
			}
		}
	}

	return out, nil
}

// validateTrafficParamsFromHTTP 供後端 /api/traffic-query 驗證所有傳入參數（防直接呼叫 API 繞過前端）
func validateTrafficParamsFromHTTP(date, rawQuery, src, dst, app, action, zone string) (*ValidatedTrafficFilter, error) {
	// 1. 若有 raw_query，先走完整綜合查詢欄語法與安全驗證
	vf, err := validateAndParseTrafficQuery(rawQuery, date)
	if err != nil {
		return nil, err
	}

	// 2. 若前端另外傳入獨立參數（向後相容），逐一嚴格驗證
	if src != "" {
		if err := validateSingleFieldValue("src", src, vf); err != nil {
			return nil, err
		}
	}
	if dst != "" {
		if err := validateSingleFieldValue("dst", dst, vf); err != nil {
			return nil, err
		}
	}
	if action != "" && strings.ToLower(action) != "all" {
		if err := validateSingleFieldValue("action", action, vf); err != nil {
			return nil, err
		}
	}
	if zone != "" && strings.ToLower(zone) != "all" {
		if err := validateSingleFieldValue("zone", zone, vf); err != nil {
			return nil, err
		}
	}

	if app != "" {
		cleanApp := app
		if idx := strings.Index(app, "__EXT__"); idx != -1 {
			cleanApp = app[:idx]
			extJSON := app[idx+7:]
			var extMap map[string]string
			if err := json.Unmarshal([]byte(extJSON), &extMap); err != nil {
				return nil, fmt.Errorf("擴充查詢參數格式異常，已拒絕執行")
			}
			for k, v := range extMap {
				vTrim := strings.TrimSpace(v)
				if vTrim == "" {
					continue
				}
				switch strings.ToLower(k) {
				case "natsrc", "natdst", "dport", "rule", "reason", "date", "days", "summary", "leq", "geq", "time", "time_leq", "time_geq", "time_generated":
					if err := validateSingleFieldValue(strings.ToLower(k), vTrim, vf); err != nil {
						return nil, err
					}
				default:
					return nil, fmt.Errorf("擴充查詢包含不允許的欄位「%s」", k)
				}
			}
		}
		if strings.TrimSpace(cleanApp) != "" {
			if err := validateSingleFieldValue("app", strings.TrimSpace(cleanApp), vf); err != nil {
				return nil, err
			}
		}
	}

	return vf, nil
}
