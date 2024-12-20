package main

var (
	ServerURL               string //服务器URL
	ChallengePassword       string //质询密码
	PKeyPath                string //私钥路径
	CertPath                string //证书路径
	KeySize                 int    //密钥大小
	Org                     string //证书组织
	CName                   string //证书通用名称
	OU                      string //证书组织单位
	Loc                     string //证书所在地
	Province                string //证书省份
	Country                 string //证书国家
	CACertMessage           string //GetCACert 操作发送的消息
	DNSName                 string //要包含在证书中的 DNS 名称（SAN）
	CAFingerprint           string //NDES 服务器的 CA 证书的 SHA-256 摘要。注意：从 MD5 更改。
	KeyEnciphermentSelector bool   //按密钥加密用途过滤 CA 证书
	DebugLogging            bool   //启用调试日志
	logFmt                  string //使用 JSON 输出日志
)

func init() {
	clientCmd.Flags().StringVarP(&ServerURL, "server-url", "s", "http://localhost:8000/api/v1/scep", "SCEP server URL")
	clientCmd.Flags().StringVarP(&ChallengePassword, "challenge-password", "c", "", "Challenge password")
	clientCmd.Flags().StringVarP(&PKeyPath, "private-key", "k", ".", "Private key path")
	clientCmd.Flags().StringVarP(&CertPath, "certificate", "t", "", "Certificate path")
	clientCmd.Flags().IntVarP(&KeySize, "key-size", "z", 2048, "Key size")
	clientCmd.Flags().StringVarP(&Org, "organization", "o", "", "Certificate organization")
	clientCmd.Flags().StringVarP(&CName, "common-name", "n", "", "Certificate common name")
	clientCmd.Flags().StringVarP(&OU, "organizational-unit", "u", "", "Certificate organizational unit")
	clientCmd.Flags().StringVarP(&Loc, "location", "l", "", "Certificate location")
	clientCmd.Flags().StringVarP(&Province, "province", "p", "", "Certificate province")
	clientCmd.Flags().StringVarP(&Country, "country", "y", "", "Certificate country")
	clientCmd.Flags().StringVarP(&CACertMessage, "ca-cert-message", "m", "", "GetCACert operation message")
	clientCmd.Flags().StringVarP(&DNSName, "dns-name", "d", "", "DNS name to include in the certificate (SAN)")
	clientCmd.Flags().StringVarP(&CAFingerprint, "ca-fingerprint", "f", "", "SHA-256 digest of the CA certificate of the NDES server. Note: changed from MD5.")
	clientCmd.Flags().BoolVarP(&KeyEnciphermentSelector, "key-encipherment-selector", "e", false, "Filter CA certificates by key encipherment purpose")
	clientCmd.Flags().BoolVarP(&DebugLogging, "debug-logging", "g", false, "Enable debug logging")
	clientCmd.Flags().StringVarP(&logFmt, "log-json", "j", "console", "Use JSON output for logs")
}
