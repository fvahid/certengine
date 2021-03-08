/*


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

package controllers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/cpu/goacmedns"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/go-logr/logr"
	"github.com/prometheus/common/log"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certenginev1 "certengine.kubebuilder.domain/api/v1"
	v1 "k8s.io/api/batch/v1"
	kbatch "k8s.io/api/batch/v1beta1"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreV1Types "k8s.io/client-go/kubernetes/typed/core/v1"
)

var secretSpec coreV1.Secret
var configSpec coreV1.ConfigMap
var cronjob *kbatch.CronJob
var secretsClient coreV1Types.SecretInterface
var secret *coreV1.Secret

var Privatekey string
var Publickey string

// CertEngineReconciler reconciles a CertEngine object
type CertEngineReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// lego lib
// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

var (
	domain             = "devops-acme.domain.ir"
	acmetest           bool
	acmeaccountemail   = "test@yours.com"
	acmednsaddress     = "https://auth.acme-dns.io"
	acmednsstoragepath = "/tmp/storage.json"
)

type DNSACMEDNSProvider struct {
	acmeDNSClient  goacmedns.Client
	acmeDNSStorage goacmedns.Storage
}

func ACMEDNSProvider() (*DNSACMEDNSProvider, error) {
	client := goacmedns.NewClient(acmednsaddress)
	// Initialize the storage. If the file does not exist, it will be
	// automatically created.
	storage := goacmedns.NewFileStorage(acmednsstoragepath, 0600)

	// Check if credentials were previously saved for your domain
	account, err := storage.Fetch(domain)

	if err != nil && err != goacmedns.ErrDomainNotFound {
		log.Fatal(err)
	} else if err == goacmedns.ErrDomainNotFound {
		// The account did not exist. Let's create a new one
		// The whitelisted networks parameter is optional and can be nil
		newAcct, err := client.RegisterAccount(nil)
		if err != nil {
			log.Fatal(err)
		}
		// Save it

		err = storage.Put(domain, newAcct)
		if err != nil {
			log.Fatalf("Failed to put account in storage: %v", err)
		}
		err = storage.Save()
		if err != nil {
			log.Fatalf("Failed to save storage: %v", err)
		}
		account = newAcct

	}

	// Update the acme-dns TXT record

	err = client.UpdateTXTRecord(account, "___validation_token_recieved_from_the_ca___")
	if err != nil {
		log.Fatal(err)
	}

	return &DNSACMEDNSProvider{acmeDNSClient: client,
		acmeDNSStorage: storage}, nil
}

func (d *DNSACMEDNSProvider) Present(domain, token, keyAuth string) error {
	// Compute the challenge response FQDN and TXT value for the domain based
	// on the keyAuth.
	_, value := dns01.GetRecord(domain, keyAuth)

	// Check if credentials were previously saved for this domain.
	account, err := d.acmeDNSStorage.Fetch(domain)
	// Errors other than goacmeDNS.ErrDomainNotFound are unexpected.
	if err != nil && !errors.Is(err, goacmedns.ErrDomainNotFound) {
		return err
	}
	if errors.Is(err, goacmedns.ErrDomainNotFound) {
		// The account did not exist. Create a new one and return an error
		// indicating the required one-time manual CNAME setup.
		// return d.register(domain, fqdn)
		return err

	}

	// Update the acme-dns TXT record.
	return d.acmeDNSClient.UpdateTXTRecord(account, value)
}

func (d *DNSACMEDNSProvider) CleanUp(domain, token, keyAuth string) error {
	// clean up any state you created in Present, like removing the TXT record
	return nil
}

func LegoClient(acemStage bool) (string, string, string, error) {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
		return "nil", "nil", "nil", err
	}

	myUser := MyUser{
		Email: acmeaccountemail,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.

	//acmeTest := certengine.Spec.ACMETest
	if acemStage == true {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	config.Certificate.KeyType = certcrypto.RSA2048
	// config.Certificate.Timeout = 30 * time.Second

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
		return "nil", "nil", "nil", err
	}

	acmeDNS, err := ACMEDNSProvider()
	if err != nil {
		log.Fatal(err)
		return "nil", "nil", "nil", err
	}

	client.Challenge.SetDNS01Provider(acmeDNS)

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
		return "nil", "nil", "nil", err
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	// var stderr bytes.Buffer
	if err != nil {
		return "nil", "nil", "nil", err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	// fmt.Printf("%#v\n", certificates)
	Privatekey = string(certificates.PrivateKey)
	Publickey = string(certificates.Certificate)

	publicKey := &privateKey.PublicKey
	encPriv, _ := encode(privateKey, publicKey)

	type JsonDomain struct {
		Domain        string
		CertUrl       string
		CertStableUrl string
	}

	basket := &JsonDomain{
		Domain:        certificates.Domain,
		CertUrl:       certificates.CertURL,
		CertStableUrl: certificates.CertStableURL,
	}

	var jsonData []byte
	jsonData, err = json.Marshal(basket)

	type BodyJson struct {
		Status  string
		Contact []string
	}
	type RegistrationJson struct {
		Body BodyJson
		URI  string
	}
	type AccountJson struct {
		EmailAddress string
		Registration RegistrationJson
	}

	accountjson := &AccountJson{
		EmailAddress: myUser.GetEmail(),
		Registration: RegistrationJson{
			URI: myUser.GetRegistration().URI,
			Body: BodyJson{
				Status:  myUser.GetRegistration().Body.Status,
				Contact: myUser.GetRegistration().Body.Contact,
			},
		},
	}

	var account []byte
	account, err = json.Marshal(accountjson)

	return string(jsonData), encPriv, string(account), nil
	// ... all done.
}

// +kubebuilder:rbac:groups=certengine.certengine.kubebuilder.domain,resources=certengines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certengine.certengine.kubebuilder.domain,resources=certengines/status,verbs=get;update;patch

func (r *CertEngineReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certengine", req.NamespacedName)

	var certengine certenginev1.CertEngine
	if err := r.Get(ctx, req.NamespacedName, &certengine); err != nil {
		log.Error(err, "unable to fetch certengine")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// name of our custom finalizer
	myFinalizerName := "storage.finalizers.domain.com"

	// examine DeletionTimestamp to determine if object is under deletion
	if certengine.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !containsString(certengine.ObjectMeta.Finalizers, myFinalizerName) {
			certengine.ObjectMeta.Finalizers = append(certengine.ObjectMeta.Finalizers, myFinalizerName)
			if err := r.Update(context.Background(), &certengine); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if containsString(certengine.ObjectMeta.Finalizers, myFinalizerName) {
			// our finalizer is present, so lets handle any external dependency
			if err := r.deleteExternalSecret(&secretSpec); err != nil {
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				return ctrl.Result{}, err
			}
			if err := r.deleteExternalConfigMap(&configSpec); err != nil {
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				return ctrl.Result{}, err
			}
			if err := r.deleteExternalCronJob(cronjob); err != nil {
				// if fail to delete the external dependency here, return with error
				// so that it can be retried
				return ctrl.Result{}, err
			}

			// remove our finalizer from the list and update it.
			certengine.ObjectMeta.Finalizers = removeString(certengine.ObjectMeta.Finalizers, myFinalizerName)
			if err := r.Update(context.Background(), &certengine); err != nil {
				return ctrl.Result{}, err
			}
		}

		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	domain = certengine.Spec.DomainName
	acmednsstoragepath = certengine.Spec.ACMEStoragePath
	acmednsaddress = certengine.Spec.ACMEDNSAddress
	acmeaccountemail = certengine.Spec.ACMEAccountEmail

	domainjson, domainkey, accountjson, err := LegoClient(certengine.Spec.ACMETest)
	if err != nil {
		log.Error(err, "unable to make certificate")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// //change status
	// certengine.Status.Status = "compeleted"
	// err = r.Status().Update(context.Background(), &certengine)
	// if err != nil {
	// 	log.Error(err, "unable to change status")
	// 	return reconcile.Result{}, err
	// }

	//create secret
	msg := make(map[string]string)
	msg["certficate"] = Privatekey + Publickey
	//fmt.Println(Publickey)
	secretSpec.Namespace = certengine.Namespace
	secretSpec.Name = fmt.Sprintf("secret-%s", certengine.Spec.DomainName)
	secretSpec.ResourceVersion = ""
	secretSpec.UID = ""
	secretSpec.StringData = msg
	if err := r.Create(ctx, &secretSpec); err != nil {
		//log.Error(err, "unable to create secret")
		r.Update(ctx, &secretSpec)
	}

	//create configMap
	storagebuffer, _ := ioutil.ReadFile(acmednsstoragepath)

	configData := make(map[string]string)
	configData["storage.json"] = string(storagebuffer)
	mountpathDomainCrt := fmt.Sprintf("/.lego/certificates/%s.crt", certengine.Spec.DomainName)
	configData["domain.crt"] = string(Publickey)
	mountpahtDomainIssuerCrt := fmt.Sprintf("/.lego/certificates/%s.issuer.crt", certengine.Spec.DomainName)
	configData["domain.issuer.crt"] = string(Publickey)
	moutnpathDoaminIssuerKey := fmt.Sprintf("/.lego/certificates/%s.key", certengine.Spec.DomainName)
	configData["domain.issuer.key"] = string(Privatekey)
	mountpathDomainJson := fmt.Sprintf("/.lego/certificates/%s.json", certengine.Spec.DomainName)
	configData["domain.json"] = domainjson
	mountpathDomainKey := fmt.Sprintf("/.lego/accounts/acme-v02.api.letsencrypt.org/%s/keys/%s.key", certengine.Spec.ACMEAccountEmail, certengine.Spec.ACMEAccountEmail)
	configData["doamin.key"] = domainkey
	mountpathAccountJson := fmt.Sprintf("/.lego/accounts/acme-v02.api.letsencrypt.org/%s/account.json", certengine.Spec.ACMEAccountEmail)
	configData["account.json"] = accountjson
	configSpec.Namespace = certengine.Namespace
	configSpec.Name = fmt.Sprintf("configmap-%s", certengine.Spec.DomainName)
	configSpec.ResourceVersion = ""
	configSpec.UID = ""
	configSpec.Data = configData
	if err := r.Create(ctx, &configSpec); err != nil {
		//log.Error(err, "unable to create configmap")
		r.Update(ctx, &configSpec)

	}

	//create cornjob template
	constructJobForCronJob := func(cronJob *certenginev1.CertEngine) (*kbatch.CronJob, error) {
		// We want job names for a given nominal start time to have a deterministic name to avoid the same job being created twice
		name := fmt.Sprintf("job-%s", domain)
		email := fmt.Sprintf("--email=%s", certengine.Spec.ACMEAccountEmail)
		domain := fmt.Sprintf("--domains=%s", certengine.Spec.DomainName)
		arguments := []string{
			email,
			domain,
			"--dns=acme-dns",
			"renew",
		}
		fmt.Println(arguments)
		podenv := []coreV1.EnvVar{
			coreV1.EnvVar{
				Name:  "ACME_DNS_API_BASE",
				Value: certengine.Spec.ACMEDNSAddress,
			},
			coreV1.EnvVar{
				Name:  "ACME_DNS_STORAGE_PATH",
				Value: "/tmp/storage.json",
			},
		}

		podvolume := []coreV1.VolumeMount{
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: certengine.Spec.ACMEStoragePath,
				ReadOnly:  false,
				SubPath:   "storage.json",
			},
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: mountpathAccountJson,
				ReadOnly:  false,
				SubPath:   "account.json",
			},
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: mountpathDomainKey,
				ReadOnly:  false,
				SubPath:   "doamin.key",
			},
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: mountpathDomainCrt,
				ReadOnly:  false,
				SubPath:   "domain.crt",
			},
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: mountpahtDomainIssuerCrt,
				ReadOnly:  false,
				SubPath:   "domain.issuer.crt",
			},
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: moutnpathDoaminIssuerKey,
				ReadOnly:  false,
				SubPath:   "domain.issuer.key",
			},
			coreV1.VolumeMount{
				Name:      "acme-volume",
				MountPath: mountpathDomainJson,
				ReadOnly:  false,
				SubPath:   "domain.json",
			},
		}
		fmt.Println(certengine.Spec.RenewSchedule)
		var defaultmode int32 = 0775
		job := &kbatch.CronJob{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
				Name:        name,
				Namespace:   secretSpec.Namespace,
			},
			Spec: kbatch.CronJobSpec{
				Schedule: certengine.Spec.RenewSchedule,
				JobTemplate: kbatch.JobTemplateSpec{
					Spec: v1.JobSpec{
						Template: coreV1.PodTemplateSpec{
							Spec: coreV1.PodSpec{
								RestartPolicy: "OnFailure",
								Volumes: []coreV1.Volume{
									coreV1.Volume{
										Name: "acme-volume",
										VolumeSource: coreV1.VolumeSource{
											ConfigMap: &coreV1.ConfigMapVolumeSource{
												DefaultMode: &defaultmode,
												LocalObjectReference: coreV1.LocalObjectReference{
													Name: configSpec.Name,
												},
											},
										},
									},
								},
								Containers: []coreV1.Container{
									coreV1.Container{
										Name:            "lego",
										Image:           "goacme/lego:v4.1.3",
										ImagePullPolicy: "IfNotPresent",
										Args:            arguments,
										Env:             podenv,
										// Command:      []string{"sh", "-c", "--"},
										// Args:         []string{"while true; do sleep 30; done;"},
										VolumeMounts: podvolume,
									},
								},
							},
						},
					},
				},
			},
		}

		return job, nil
	}
	// +kubebuilder:docs-gen:collapse=constructJobForCronJob

	// actually make the job...

	cronjob, err = constructJobForCronJob(&certengine)

	if err != nil {
		//log.Error(err, "unable to construct job from template")
		// don't bother requeuing until we get a change to the spec
		//return ctrl.Result{}, nil
	}
	if err := r.Create(ctx, cronjob); err != nil {
		log.Error(err, "unable to create Job for CronJob", "job", err)
		r.Update(ctx, cronjob)
	}

	return ctrl.Result{}, nil

}

func (r *CertEngineReconciler) deleteExternalSecret(secret *coreV1.Secret) error {

	if err := r.Delete(context.Background(), secret); err != nil {
		return err
	}
	return nil
}
func (r *CertEngineReconciler) deleteExternalConfigMap(configmap *coreV1.ConfigMap) error {

	if err := r.Delete(context.Background(), configmap); err != nil {
		return err
	}
	return nil
}
func (r *CertEngineReconciler) deleteExternalCronJob(cronjob *kbatch.CronJob) error {

	if err := r.Delete(context.Background(), cronjob); err != nil {
		return err
	}
	return nil
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

func (r *CertEngineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certenginev1.CertEngine{}).
		Complete(r)
}
