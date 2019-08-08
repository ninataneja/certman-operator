/*
Copyright 2019 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificaterequest

import (
	"fmt"
	"time"

	"github.com/go-logr/logr"
	certmanv1alpha1 "github.com/openshift/certman-operator/pkg/apis/certman/v1alpha1"
	"github.com/openshift/certman-operator/pkg/localmetrics"
	corev1 "k8s.io/api/core/v1"
)

func (r *ReconcileCertificateRequest) ShouldRenewOrReIssue(reqLogger logr.Logger, cr *certmanv1alpha1.CertificateRequest) (bool, error) {
	localmetrics.UpdateCertExpiryDateMetric(reqLogger, cr.Name, cr.Spec.ACMEDNSDomain, -1)

	renewBeforeDays := cr.Spec.RenewBeforeDays

	if renewBeforeDays <= 0 {
		renewBeforeDays = RenewCertificateBeforeDays
	}

	reqLogger.Info(fmt.Sprintf("certificate is configured to be renewed %d days before expiry", renewBeforeDays))

	crtSecret, err := GetSecret(r.client, cr.Spec.CertificateSecret.Name, cr.Namespace)
	if err != nil {
		return false, err
	}

	data := crtSecret.Data[corev1.TLSCertKey]
	if data == nil {
		reqLogger.Info(fmt.Sprintf("certificate data was not found in secret %v", cr.Spec.CertificateSecret.Name))
		return true, nil
	}

	certificate, err := ParseCertificateData(data)
	if err != nil {
		reqLogger.Error(err, err.Error())
		return false, err
	}

	if certificate != nil {

		notAfter := certificate.NotAfter
		currentTime := time.Now().In(time.UTC)
		timeDiff := notAfter.Sub(currentTime)
		daysCertificateValidFor := int(timeDiff.Hours() / 24)
		shouldRenew := daysCertificateValidFor <= renewBeforeDays

		localmetrics.UpdateCertExpiryDateMetric(reqLogger, cr.Name, cr.Spec.ACMEDNSDomain, daysCertificateValidFor)

		if shouldRenew {
			reqLogger.Info(fmt.Sprintf("certificate is valid from (notBefore) %v and until (notAfter) %v and is valid for %d days and will be renewed", certificate.NotBefore.String(), certificate.NotAfter.String(), daysCertificateValidFor))
		} else {
			reqLogger.Info(fmt.Sprintf("certificate is valid from (notBefore) %v and until (notAfter) %v and is valid for %d days and will NOT be renewed", certificate.NotBefore.String(), certificate.NotAfter.String(), daysCertificateValidFor))
		}

		return shouldRenew, nil
	}

	return false, nil
}
