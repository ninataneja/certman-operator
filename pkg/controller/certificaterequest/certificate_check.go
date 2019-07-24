package certificaterequest

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"
	certmanv1alpha1 "github.com/openshift/certman-operator/pkg/apis/certman/v1alpha1"
)

func loadDomains(reqLogger logr.Logger, cr *certmanv1alpha1.CertificateRequest) []string {
	var listDomains []string

	baseDomain := string(cr.Spec.ACMEDNSDomain)
	reqLogger.Info(fmt.Sprintf("BASE DOMAIN  %v:", baseDomain))

	//for _, domain := range testingList {
	for _, domain := range cr.Spec.DnsNames {
		reqLogger.Info(fmt.Sprintf("EXAMINING DOMAINS"))
		domain = strings.TrimPrefix(domain, "*.")
		reqLogger.Info(fmt.Sprintf("Current domain %v :", domain))

		if strings.Compare(domain, baseDomain) == 0 {
			listDomains = append(listDomains, domain)
			reqLogger.Info(fmt.Sprintf("API domain matching found"))
		} else {
			listDomains = append(listDomains, domain)
			reqLogger.Info(fmt.Sprintf("not matching Console Domain found"))
		}

	}

	var testingList []string
	testingList = append(testingList, "api.tparikh-quay-poc.a0a0.s1.devshift.org")
	testingList = append(testingList, "console-openshift-console.apps.tparikh-quay-poc.a0a0.s1.devshift.org")
	reqLogger.Info(fmt.Sprintf("testingList values: %v , %s", testingList[0], testingList[1]))
	return testingList

	//6443 for api
}

func (r *ReconcileCertificateRequest) CertificateComparison(reqLogger logr.Logger, cr *certmanv1alpha1.CertificateRequest) {

	reqLogger.Info(fmt.Sprintf("CALLING COMPARISON FUNCTION"))
	if cr != nil {
		certificate, err := GetCertificate(r.client, cr)
		if err != nil {
			reqLogger.Error(err, "can't load certificate data")
		}
		if certificate == nil {
			reqLogger.Error(err, "no certificate found")
		}

		secretSerialNumber := certificate.SerialNumber.String()
		listComparisonDomains := loadDomains(reqLogger, cr)
		reqLogger.Info(fmt.Sprintf("Calling domain function"))
		for _, domain := range listComparisonDomains {
			reqLogger.Info(fmt.Sprintf("dialing domain %v", domain))
			domain = domain + ":443"
			cfg := tls.Config{}
			dialer := net.Dialer{
				Timeout: 30 * time.Second,
			}
			conn, err := tls.DialWithDialer(&dialer, "tcp", domain, &cfg)
			if err != nil {
				reqLogger.Error(err, "ERROR!!! Could not find certificate")
			}
			if len(conn.ConnectionState().PeerCertificates) == 0 {
				reqLogger.Error(err, "No peer certificates found")
			}
			certChain := conn.ConnectionState().PeerCertificates
			cert := certChain[0]
			strCertSerialNum := cert.SerialNumber.String()
			if strings.Compare(secretSerialNumber, strCertSerialNum) != 0 {
				reqLogger.Info(fmt.Sprintf("MISMATCH!!!!! Certificates don't match for %v", cr.Name))
			}
		}
	}
}
