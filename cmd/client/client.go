package main

import (
	"context"
	"crypto/x509"
	"kscep/internal/client"
	"kscep/internal/utils"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ploynomail/scep"
	"go.uber.org/zap"
)

type runCfg struct {
	dir          string
	csrPath      string
	keyPath      string
	keyBits      int
	selfSignPath string
	certPath     string

	country  string
	province string
	org      string
	ou       string
	cn       string
	locality string
	dnsName  string

	challenge       string
	serverURL       string
	caCertsSelector scep.CertsSelector
	caCertMsg       string

	logfmt string
	debug  bool
}

func run(cfg runCfg) error {
	ctx := context.Background()
	client, err := client.NewClient(cfg.serverURL, logger)
	if err != nil {
		return err
	}
	key, err := utils.LoadOrMakeKey(cfg.keyPath, cfg.keyBits)
	if err != nil {
		return err
	}

	opts := &utils.CsrOptions{
		Country:   strings.ToUpper(cfg.country),
		Province:  cfg.province,
		Org:       cfg.org,
		OU:        cfg.ou,
		Cn:        cfg.cn,
		Locality:  cfg.locality,
		DnsName:   cfg.dnsName,
		Key:       key,
		Challenge: cfg.challenge,
	}

	csr, err := utils.LoadOrMakeCSR(cfg.csrPath, opts)
	if err != nil {
		return err
	}

	var self *x509.Certificate
	cert, err := utils.LoadPEMCertFromFile(cfg.certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		s, err := utils.LoadOrSign(cfg.selfSignPath, key, csr)
		if err != nil {
			return err
		}
		self = s
	}

	resp, certNum, err := client.GetCACert(ctx, cfg.caCertMsg)
	if err != nil {
		return err
	}
	var caCerts []*x509.Certificate
	{
		if certNum > 1 {
			caCerts, err = scep.CACerts(resp)
			if err != nil {
				return err
			}
		} else {
			caCerts, err = x509.ParseCertificates(resp)
			if err != nil {
				return err
			}
		}
	}
	var signerCert *x509.Certificate
	{
		if cert != nil {
			signerCert = cert
		} else {
			signerCert = self
		}
	}

	var msgType scep.MessageType
	{
		// TODO validate CA and set UpdateReq if needed
		if cert != nil {
			msgType = scep.RenewalReq
		} else {
			msgType = scep.PKCSReq
		}
	}

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  caCerts,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	if cfg.challenge != "" && msgType == scep.PKCSReq {
		tmpl.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: cfg.challenge,
		}
	}

	msg, err := scep.NewCSRRequest(csr, tmpl, scep.WithCertsSelector(cfg.caCertsSelector))
	if err != nil {
		return errors.Wrap(err, "creating csr pkiMessage")
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
		if err != nil {
			return errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			logger.Info("pkiStatus", zap.String("status", "PENDING"), zap.String("msg", "sleeping for 30 seconds, then trying again."))
			time.Sleep(30 * time.Second)
			continue
		}
		logger.Info("pkiStatus", zap.String("status", "SUCCESS"), zap.String("msg", "server returned a certificate."))
		break // on scep.SUCCESS
	}

	if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
		return errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	}

	respCert := respMsg.CertRepMessage.Certificate
	if err := os.WriteFile(cfg.certPath, utils.PemCert(respCert.Raw), 0666); err != nil {
		return err
	}

	// remove self signer if used
	if self != nil {
		if err := os.Remove(cfg.selfSignPath); err != nil {
			return err
		}
	}

	return nil
}
