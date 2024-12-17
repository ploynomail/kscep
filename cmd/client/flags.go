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
	errTrace                bool   //打印错误堆栈
	issuer                  string //颁发者
	serial                  string //序列号
)

func init() {
	ReqCmd.Flags().StringVarP(&ServerURL, "server-url", "s", "http://localhost:8000/api/v1/scep", "SCEP server URL")
	ReqCmd.Flags().StringVarP(&PKeyPath, "private-key", "k", ".", "Private key path")
	ReqCmd.Flags().StringVarP(&CertPath, "certificate", "t", "", "Certificate path")
	ReqCmd.Flags().IntVarP(&KeySize, "key-size", "z", 2048, "Key size")
	ReqCmd.Flags().StringVarP(&Org, "organization", "o", "", "Certificate organization")
	ReqCmd.Flags().StringVarP(&CName, "common-name", "n", "", "Certificate common name")
	ReqCmd.Flags().StringVarP(&OU, "organizational-unit", "u", "", "Certificate organizational unit")
	ReqCmd.Flags().StringVarP(&Loc, "location", "l", "", "Certificate location")
	ReqCmd.Flags().StringVarP(&Province, "province", "p", "", "Certificate province")
	ReqCmd.Flags().StringVarP(&Country, "country", "y", "", "Certificate country")
	ReqCmd.Flags().StringVarP(&CACertMessage, "ca-cert-message", "m", "", "GetCACert operation message")
	ReqCmd.Flags().StringVarP(&DNSName, "dns-name", "d", "", "DNS name to include in the certificate (SAN)")
	ReqCmd.Flags().StringVarP(&CAFingerprint, "ca-fingerprint", "f", "", "SHA-256 digest of the CA certificate of the NDES server. Note: changed from MD5.")
	ReqCmd.Flags().BoolVarP(&KeyEnciphermentSelector, "key-encipherment-selector", "e", false, "Filter CA certificates by key encipherment purpose")
	ReqCmd.Flags().BoolVarP(&DebugLogging, "debug-logging", "g", false, "Enable debug logging")
	ReqCmd.Flags().StringVarP(&logFmt, "log-json", "j", "console", "Use JSON output for logs")
	ReqCmd.Flags().BoolVarP(&errTrace, "error-trace", "r", false, "Print error stack traces")

	GetCmd.Flags().StringVarP(&issuer, "issuer", "", "", "Issuer")
	GetCmd.Flags().StringVarP(&serial, "serial", "", "", "Serial")
	GetCmd.Flags().StringVarP(&ServerURL, "server-url", "", "http://localhost:8000/api/v1/scep", "SCEP server URL")
	GetCmd.Flags().StringVarP(&PKeyPath, "private-key", "", ".", "Private key path")
	// clientCmd.Flags().StringVarP(&ChallengePassword, "challenge-password", "c", "", "Challenge password")
}
