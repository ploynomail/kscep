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

	// challenge       string
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
		logger.Error("creating client", zap.Error(err))
		return err
	}
	key, err := utils.LoadOrMakeKey(cfg.keyPath, cfg.keyBits)
	if err != nil {
		logger.Error("loading or making key", zap.Error(err))
		return err
	}

	opts := &utils.CsrOptions{
		Country:  strings.ToUpper(cfg.country),
		Province: cfg.province,
		Org:      cfg.org,
		OU:       cfg.ou,
		Cn:       cfg.cn,
		Locality: cfg.locality,
		DnsName:  cfg.dnsName,
		Key:      key,
		// Challenge: cfg.challenge,
	}

	csr, err := utils.LoadOrMakeCSR(cfg.csrPath, opts)
	if err != nil {
		logger.Error("loading or making csr", zap.Error(err))
		return err
	}

	var self *x509.Certificate
	cert, err := utils.LoadPEMCertFromFile(cfg.certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("loading cert", zap.Error(err))
			return err
		}
		s, err := utils.LoadOrSign(cfg.selfSignPath, key, csr)
		if err != nil {
			logger.Error("loading or signing self signed cert", zap.Error(err))
			return err
		}
		self = s
	}

	resp, certNum, err := client.GetCACert(ctx, cfg.caCertMsg)
	if err != nil {
		logger.Error("getting ca cert", zap.Error(err))
		return err
	}
	var caCerts []*x509.Certificate
	{
		if certNum > 1 {
			caCerts, err = scep.CACerts(resp)
			if err != nil {
				logger.Error("parsing ca certs", zap.Error(err))
				return err
			}
		} else {
			caCerts, err = x509.ParseCertificates(resp)
			if err != nil {
				logger.Error("parsing ca cert", zap.Error(err))
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
		// TODO: validate CA and set UpdateReq if needed
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
	// TODO: 这里是不是应该先查询证书是否存在，如果存在则不再做签发请求

	// if cfg.challenge != "" && msgType == scep.PKCSReq {
	// 	tmpl.CSRReqMessage = &scep.CSRReqMessage{
	// 		ChallengePassword: cfg.challenge,
	// 	}
	// }
	msg, err := scep.NewCSRRequest(csr, tmpl, scep.WithCertsSelector(cfg.caCertsSelector), scep.WithLogger(utils.LoggerSCEPWapperWithZap(logger)))
	if err != nil {
		logger.Error("creating csr pkiMessage", zap.Error(err))
		return errors.Wrap(err, "creating csr pkiMessage")
	}
	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			logger.Error("PKIOperation", zap.Error(err))
			return errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
		if err != nil {
			logger.Error("parsing pkiMessage response", zap.Error(err))
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

func get(issuer, serial string, cfg runCfg) error {
	ctx := context.Background()
	client, err := client.NewClient(cfg.serverURL, logger)
	if err != nil {
		logger.Error("creating client", zap.Error(err))
		return err
	}
	key, err := utils.LoadOrMakeKey(cfg.keyPath, cfg.keyBits)
	if err != nil {
		logger.Error("loading or making key", zap.Error(err))
		return err
	}
	resp, certNum, err := client.GetCACert(ctx, cfg.caCertMsg)
	if err != nil {
		logger.Error("getting ca cert", zap.Error(err))
		return err
	}
	opts := &utils.CsrOptions{
		Country:  strings.ToUpper(cfg.country),
		Province: cfg.province,
		Org:      cfg.org,
		OU:       cfg.ou,
		Cn:       cfg.cn,
		Locality: cfg.locality,
		DnsName:  cfg.dnsName,
		Key:      key,
		// Challenge: cfg.challenge,
	}
	csr, err := utils.LoadOrMakeCSR(cfg.csrPath, opts)
	if err != nil {
		logger.Error("loading or making csr", zap.Error(err))
		return err
	}
	var self *x509.Certificate
	s, err := utils.LoadOrSign(cfg.selfSignPath, key, csr)
	if err != nil {
		logger.Error("loading or signing self signed cert", zap.Error(err))
		return err
	}
	self = s
	var caCerts []*x509.Certificate
	{
		if certNum > 1 {
			caCerts, err = scep.CACerts(resp)
			if err != nil {
				logger.Error("parsing ca certs", zap.Error(err))
				return err
			}
		} else {
			caCerts, err = x509.ParseCertificates(resp)
			if err != nil {
				logger.Error("parsing ca cert", zap.Error(err))
				return err
			}
		}
	}
	var signerCert *x509.Certificate
	{
		signerCert = self
	}

	msgType := scep.GetCert

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  caCerts,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	msg, err := scep.NewGetCertRequest(csr, issuer, serial, tmpl, scep.WithLogger(utils.LoggerSCEPWapperWithZap(logger)))
	if err != nil {
		logger.Error("creating csr pkiMessage", zap.Error(err))
		return errors.Wrap(err, "creating csr pkiMessage")
	}
	var respMsg *scep.PKIMessage

	respBytes, err := client.PKIOperation(ctx, msg.Raw)
	if err != nil {
		logger.Error("PKIOperation", zap.Error(err))
		return errors.Wrapf(err, "PKIOperation for %s", msgType)
	}

	respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
	if err != nil {
		logger.Error("parsing pkiMessage response", zap.Error(err))
		return errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
	}

	if respMsg.PKIStatus == scep.FAILURE {
		return errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)

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
