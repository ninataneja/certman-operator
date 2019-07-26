package clusterdeployment

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	certmanv1alpha1 "github.com/openshift/certman-operator/pkg/apis/certman/v1alpha1"
	"github.com/openshift/certman-operator/pkg/controller/controllerutils"

	hivev1alpha1 "github.com/openshift/hive/pkg/apis/hive/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	logr "github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_clusterdeployment")

const (
	controllerName                = "clusterdeployment"
	ClusterDeploymentManagedLabel = "api.openshift.com/managed"
)

// Add creates a new ClusterDeployment Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileClusterDeployment{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerName+"-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource ClusterDeployment
	err = c.Watch(&source.Kind{Type: &hivev1alpha1.ClusterDeployment{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileClusterDeployment{}

// ReconcileClusterDeployment reconciles a ClusterDeployment object
type ReconcileClusterDeployment struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a ClusterDeployment object and sets up
// any needed CertificateRequest objects.
func (r *ReconcileClusterDeployment) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("reconciling ClusterDeployment")

	// Fetch the ClusterDeployment instance
	cd := &hivev1alpha1.ClusterDeployment{}
	err := r.client.Get(context.TODO(), request.NamespacedName, cd)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		reqLogger.Error(err, "error looking up clusterDeployment")
		return reconcile.Result{}, err
	}

	if !cd.Status.Installed {
		reqLogger.Info(fmt.Sprintf("cluster %v is not yet in installed state", cd.Name))
		return reconcile.Result{}, nil
	}

	// Do not make certificate request if the cluster is not a Red Hat managed cluster.
	if val, ok := cd.Labels[ClusterDeploymentManagedLabel]; ok {
		if val != "true" {
			reqLogger.Info("not a managed cluster")
			return reconcile.Result{}, nil
		}
	} else {
		// Managed tag is not present which implies it is not a managed cluster
		reqLogger.Info("not a managed cluster")
		return reconcile.Result{}, nil
	}

	if cd.DeletionTimestamp.IsZero() {
		// add finalizer
		if !controllerutils.ContainsString(cd.ObjectMeta.Finalizers, certmanv1alpha1.CertmanOperatorFinalizerLabel) {
			reqLogger.Info("adding CertmanOperator finalizer to the ClusterDeployment")
			cd.ObjectMeta.Finalizers = append(cd.ObjectMeta.Finalizers, certmanv1alpha1.CertmanOperatorFinalizerLabel)
			if err := r.client.Update(context.TODO(), cd); err != nil {
				return reconcile.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if controllerutils.ContainsString(cd.ObjectMeta.Finalizers, certmanv1alpha1.CertmanOperatorFinalizerLabel) {
			reqLogger.Info("deleting the CertificateRequest for the ClusterDeployment")
			if err := r.handleDelete(cd, reqLogger); err != nil {
				reqLogger.Error(err, "error deleting CertificateRequests")
				return reconcile.Result{}, err
			}

			reqLogger.Info("removing CertmanOperator finalizer from the ClusterDeployment")
			cd.ObjectMeta.Finalizers = controllerutils.RemoveString(cd.ObjectMeta.Finalizers, certmanv1alpha1.CertmanOperatorFinalizerLabel)
			if err := r.client.Update(context.TODO(), cd); err != nil {
				return reconcile.Result{}, err
			}
		}
		return reconcile.Result{}, nil
	}

	if err := r.syncCertificateRequests(cd, reqLogger); err != nil {
		reqLogger.Error(err, "error syncing CertificateRequests")
		return reconcile.Result{}, err
	}

	reqLogger.Info("done syncing")
	return reconcile.Result{}, nil
}

func (r *ReconcileClusterDeployment) syncCertificateRequests(cd *hivev1alpha1.ClusterDeployment, logger logr.Logger) error {
	desiredCRs := []certmanv1alpha1.CertificateRequest{}

	// get a list of current CertificateRequests
	currentCRs, err := r.getCurrentCertificateRequests(cd, logger)
	if err != nil {
		logger.Error(err, err.Error())
		return err
	}

	// for each certbundle with generate==true make a CertificateRequest
	for _, cb := range cd.Spec.CertificateBundles {

		logger.Info(fmt.Sprintf("processing certificate bundle %v", cb.Name),
			"CertificateBundleName", cb.Name,
			"GenerateCertificate", cb.Generate,
		)

		if cb.Generate == true {
			domains := getDomainsForCertBundle(cb, cd, logger)

			emailAddress, err := controllerutils.GetDefaultNotificationEmailAddress(r.client)
			if err != nil {
				logger.Error(err, err.Error())
				return err
			}

			if len(domains) > 0 {
				certReq := createCertificateRequest(cb.Name, cb.SecretRef.Name, domains, cd, emailAddress)
				desiredCRs = append(desiredCRs, certReq)
			} else {
				err := fmt.Errorf("no domains provided for certificate bundle %v in the cluster deployment %v", cb.Name, cd.Name)
				logger.Error(err, err.Error())
			}
		}
	}

	deleteCRs := []certmanv1alpha1.CertificateRequest{}

	// find any extra certificateRequests and mark them for deletion
	for i, currentCR := range currentCRs {
		found := false
		for _, desiredCR := range desiredCRs {
			if desiredCR.Name == currentCR.Name {
				found = true
				break
			}
		}
		if !found {
			deleteCRs = append(deleteCRs, currentCRs[i])
		}
	}

	// create/update the desired certificaterequests
	for _, desiredCR := range desiredCRs {
		currentCR := &certmanv1alpha1.CertificateRequest{}
		searchKey := types.NamespacedName{Name: desiredCR.Name, Namespace: desiredCR.Namespace}

		if err := r.client.Get(context.TODO(), searchKey, currentCR); err != nil {
			if errors.IsNotFound(err) {
				// create
				if err := controllerutil.SetControllerReference(cd, &desiredCR, r.scheme); err != nil {
					logger.Error(err, "error setting owner reference", "certrequest", desiredCR.Name)
					return err
				}

				logger.Info(fmt.Sprintf("creating CertificateRequest resource config %v", desiredCR.Name))
				if err := r.client.Create(context.TODO(), &desiredCR); err != nil {
					logger.Error(err, "error creating certificaterequest")
					return err
				}
			} else {
				logger.Error(err, "error checking for existing certificaterequest")
				return err
			}
		} else {
			// update or no update needed
			if !reflect.DeepEqual(currentCR.Spec, desiredCR.Spec) {
				currentCR.Spec = desiredCR.Spec
				if err := r.client.Update(context.TODO(), currentCR); err != nil {
					logger.Error(err, "error updating certificaterequest", "certrequest", currentCR.Name)
					return err
				}
			} else {
				logger.Info("no update needed for certificaterequest", "certrequest", desiredCR.Name)
			}
		}
	}

	// delete the  certificaterequests
	for _, deleteCR := range deleteCRs {
		logger.Info(fmt.Sprintf("deleting CertificateRequest resource config  %v", deleteCR.Name))
		if err := r.client.Delete(context.TODO(), &deleteCR); err != nil {
			logger.Error(err, "error deleting CertificateRequest that is no longer needed", "certrequest", deleteCR.Name)
			return err
		}
	}

	return nil
}

func (r *ReconcileClusterDeployment) getCurrentCertificateRequests(cd *hivev1alpha1.ClusterDeployment, logger logr.Logger) ([]certmanv1alpha1.CertificateRequest, error) {
	certReqsForCluster := []certmanv1alpha1.CertificateRequest{}

	// get all CRs in the cluster's namespace
	currentCRs := &certmanv1alpha1.CertificateRequestList{}
	if err := r.client.List(context.TODO(), &client.ListOptions{Namespace: cd.Namespace}, currentCRs); err != nil {
		logger.Error(err, "error listing current CertificateRequests")
		return certReqsForCluster, err
	}

	// now filter out the ones that are owned by the cluster we're processing
	for i, cr := range currentCRs.Items {
		if metav1.IsControlledBy(&cr, cd) {
			certReqsForCluster = append(certReqsForCluster, currentCRs.Items[i])
		}
	}

	return certReqsForCluster, nil
}

func getDomainsForCertBundle(cb hivev1alpha1.CertificateBundleSpec, cd *hivev1alpha1.ClusterDeployment, logger logr.Logger) []string {
	domains := []string{}
	dLogger := logger.WithValues("CertificateBundle", cb.Name)

	// first check for the special-case default control plane reference
	if cd.Spec.ControlPlaneConfig.ServingCertificates.Default == cb.Name {
		controlPlaneCertDomain := fmt.Sprintf("api.%s.%s", cd.Spec.ClusterName, cd.Spec.BaseDomain)
		dLogger.Info("control plane config DNS name: " + controlPlaneCertDomain)
		domains = append(domains, controlPlaneCertDomain)
	}

	// now check the rest of the control plane
	for _, additionalCert := range cd.Spec.ControlPlaneConfig.ServingCertificates.Additional {
		if additionalCert.Name == cb.Name {
			dLogger.Info("additional domain added to certificate request: " + additionalCert.Domain)
			domains = append(domains, additionalCert.Domain)
		}
	}

	// and lastly the ingress list
	for _, ingress := range cd.Spec.Ingress {
		if ingress.ServingCertificate == cb.Name {
			ingressDomain := ingress.Domain

			// always request wildcard certificates for the ingress domain
			if !strings.HasPrefix(ingressDomain, "*.") {
				ingressDomain = fmt.Sprintf("*.%s", ingress.Domain)
			}

			dLogger.Info("ingress domain added to certificate request: " + ingressDomain)
			domains = append(domains, ingressDomain)
		}
	}

	return domains
}

func createCertificateRequest(certBundleName string, secretName string, domains []string, cd *hivev1alpha1.ClusterDeployment, emailAddress string) certmanv1alpha1.CertificateRequest {
	name := fmt.Sprintf("%s-%s", cd.Name, certBundleName)
	name = strings.ToLower(name)

	cr := certmanv1alpha1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cd.Namespace,
		},
		Spec: certmanv1alpha1.CertificateRequestSpec{
			ACMEDNSDomain: cd.Spec.BaseDomain,
			CertificateSecret: corev1.ObjectReference{
				Kind:      "secret",
				Namespace: cd.Namespace,
				Name:      secretName,
			},
			PlatformSecrets: certmanv1alpha1.PlatformSecrets{
				AWS: &certmanv1alpha1.AWSPlatformSecrets{
					Credentials: corev1.LocalObjectReference{
						Name: cd.Spec.PlatformSecrets.AWS.Credentials.Name,
					},
				},
			},
			DnsNames:      domains,
			Email:         emailAddress,
			APIURL:        cd.Status.APIURL,
			WebConsoleURL: cd.Status.WebConsoleURL,
		},
	}

	return cr
}
