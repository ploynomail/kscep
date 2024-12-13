package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ploynomail/scep"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var version = "0.0.1"

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(ReqCmd)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "version subcommand show client version info.",

	Run: func(cmd *cobra.Command, args []string) {
		os.Stdout.WriteString(fmt.Sprintf("version: %s\n", version))
	},
}

// client command
var ReqCmd = &cobra.Command{
	Use:   "signer",
	Short: "signer subcommand is a client for SCEP protocol",
	Long:  "signer subcommand is a client for SCEP protocol",
	PreRun: func(cmd *cobra.Command, args []string) {
		InitializeLogger(logFmt)
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateFlags(PKeyPath, ServerURL, CAFingerprint, KeyEnciphermentSelector); err != nil {
			logger.Error("error validating flags", zap.Error(err))
			os.Exit(1)
		}

		caCertsSelector := scep.NopCertsSelector()
		switch {
		case CAFingerprint != "":
			hash, err := validateFingerprint(CAFingerprint)
			if err != nil {
				logger.Error("error validating fingerprint", zap.Error(err))
				os.Exit(1)
			}
			caCertsSelector = scep.FingerprintCertsSelector(fingerprintHashType, hash)
		case KeyEnciphermentSelector:
			caCertsSelector = scep.EnciphermentCertsSelector()
		}
		dir := filepath.Dir(PKeyPath)
		csrPath := dir + "/csr.pem"
		selfSignPath := dir + "/self.pem"
		if CertPath == "" {
			CertPath = dir + "/client.pem"
		}

		// cfg is an instance of runCfg struct that holds configuration settings for the client.
		// It includes paths for various certificate and key files, server URL, and details for
		// generating a certificate signing request (CSR). The configuration also includes logging
		// settings and challenge password for certificate authority (CA) interactions.
		//
		// Fields:
		// - dir: Directory path for storing generated files.
		// - selfSignPath: Path to the self-signed certificate.
		// - certPath: Path to the certificate file.
		// - csrPath: Path to the certificate signing request file.
		// - keyPath: Path to the private key file.
		// - keyBits: Size of the private key in bits.
		// - serverURL: URL of the server to connect to.
		// - country: Country name for the CSR.
		// - province: Province name for the CSR.
		// - org: Organization name for the CSR.
		// - ou: Organizational unit name for the CSR.
		// - cn: Common name for the CSR.
		// - locality: Locality name for the CSR.
		// - dnsName: DNS name for the CSR.
		// - caCertMsg: Message related to the CA certificate.
		// - caCertsSelector: Selector for CA certificates.
		// - challenge: Challenge password for CA interactions.
		// - logfmt: Format for logging output.
		// - debug: Flag to enable or disable debug logging.
		cfg := runCfg{
			dir:          dir,
			selfSignPath: selfSignPath,
			certPath:     CertPath,
			csrPath:      csrPath,
			keyPath:      PKeyPath,
			keyBits:      KeySize,

			serverURL: ServerURL,

			country:  Country,
			province: Province,
			org:      Org,
			ou:       OU,
			cn:       CName,
			locality: Loc,
			dnsName:  DNSName,

			caCertMsg:       CACertMessage,
			caCertsSelector: caCertsSelector,

			logfmt: logFmt,
			debug:  DebugLogging,
		}

		if err := run(cfg); err != nil {
			logger.Error("error running client", zap.Error(err))
			os.Exit(1)
		}
	},
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scep-client",
	Short: "scep-client is a client for SCEP protocol",
	Long:  "scep-client is a client for SCEP protocol",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func main() {
	Execute()
}
