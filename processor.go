// Copyright 2016 Google Inc. All Rights Reserved.
// Copyright 2016 Palm Stone Games, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/jpillora/backoff"
	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"github.com/xenolf/lego/providers/dns/digitalocean"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
	"github.com/xenolf/lego/providers/dns/dnspod"
	"github.com/xenolf/lego/providers/dns/dyn"
	"github.com/xenolf/lego/providers/dns/gandi"
	"github.com/xenolf/lego/providers/dns/googlecloud"
	"github.com/xenolf/lego/providers/dns/linode"
	"github.com/xenolf/lego/providers/dns/namecheap"
	"github.com/xenolf/lego/providers/dns/ovh"
	"github.com/xenolf/lego/providers/dns/pdns"
	"github.com/xenolf/lego/providers/dns/rfc2136"
	"github.com/xenolf/lego/providers/dns/route53"
	"github.com/xenolf/lego/providers/dns/vultr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/labels"
	"k8s.io/client-go/pkg/selection"
	"k8s.io/client-go/rest"
)

// certBackoff
type certBackoff struct {
	// Permitted is time we can retry the request
	Permitted time.Time
	// Rate is the backoff implementation
	Rate *backoff.Backoff
}

// CertProcessor holds the shared configuration, state, and locks
type CertProcessor struct {
	HTTPLock sync.Mutex
	Lock     sync.Mutex
	TLSLock  sync.Mutex
	rateLock sync.RWMutex

	acmeURL           string
	certNamespace     string
	certSecretPrefix  string
	class             string
	db                *bolt.DB
	defaultBackoff    time.Duration
	defaultEmail      string
	defaultMaxBackoff time.Duration
	defaultProvider   string
	k8s               K8sClient
	namespaces        []string
	rateLimits        map[string]*certBackoff
	renewBeforeDays   int
	tagPrefix         string
}

// NewCertProcessor creates and populates a CertProcessor
func NewCertProcessor(
	k8s *kubernetes.Clientset,
	certClient *rest.RESTClient,
	acmeURL string,
	certSecretPrefix string,
	certNamespace string,
	tagPrefix string,
	namespaces []string,
	class string,
	defaultBackoff time.Duration,
	defaultMaxBackoff time.Duration,
	defaultProvider string,
	defaultEmail string,
	db *bolt.DB,
	renewBeforeDays int) *CertProcessor {

	return &CertProcessor{
		k8s:               K8sClient{c: k8s, certClient: certClient},
		acmeURL:           acmeURL,
		certSecretPrefix:  certSecretPrefix,
		certNamespace:     certNamespace,
		tagPrefix:         tagPrefix,
		namespaces:        namespaces,
		class:             class,
		defaultBackoff:    defaultBackoff,
		defaultMaxBackoff: defaultMaxBackoff,
		defaultProvider:   defaultProvider,
		defaultEmail:      defaultEmail,
		db:                db,
		rateLimits:        make(map[string]*certBackoff, 0),
		renewBeforeDays:   renewBeforeDays,
	}
}

func (p *CertProcessor) syncCertificates() error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	certificates, err := p.getCertificates()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, cert := range certificates {
		wg.Add(1)
		go func(cert Certificate) {
			defer wg.Done()
			if _, err := p.processCertificate(cert); err != nil {
				log.Printf("Error while processing certificate during sync: %v", err)
				return
			}
		}(cert)
	}
	wg.Wait()

	return nil
}

func (p *CertProcessor) syncIngresses() error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	ingresses, err := p.getIngresses()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, ingress := range ingresses {
		wg.Add(1)
		go func(ingress v1beta1.Ingress) {
			p.processIngress(ingress)
			wg.Done()
		}(ingress)
	}
	wg.Wait()
	return nil
}

func (p *CertProcessor) watchKubernetesEvents(namespace string, selector labels.Selector, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	if namespace == v1.NamespaceAll {
		log.Printf("Watching certificates and ingresses in all namespaces")
	} else {
		log.Printf("Watchining certificates and ingresses in namespace %s", namespace)
	}
	certEvents := p.k8s.monitorCertificateEvents(namespace, selector, doneChan)
	ingressEvents := p.k8s.monitorIngressEvents(namespace, selector, doneChan)
	for {
		select {
		case event := <-certEvents:
			err := p.processCertificateEvent(event)
			if err != nil {
				log.Printf("Error while processing certificate event: %v", err)
			}
		case event := <-ingressEvents:
			p.processIngressEvent(event)
		case <-doneChan:
			wg.Done()
			log.Println("Stopped certificate event watcher.")
			return
		}
	}
}

func (p *CertProcessor) maintenance(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	for {
		select {
		case <-time.After(syncInterval):
			if err := p.syncCertificates(); err != nil {
				log.Printf("Error while synchronizing certificates during refresh: %s", err)
			}
			if err := p.syncIngresses(); err != nil {
				log.Printf("Error while synchronizing ingresses during refresh: %s", err)
			}
			if err := p.gcSecrets(); err != nil {
				log.Printf("Error cleaning up secrets: %s", err)
			}
		case <-doneChan:
			wg.Done()
			log.Println("Stopped refresh loop.")
			return
		}
	}
}

func (p *CertProcessor) processCertificateEvent(c CertificateEvent) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	switch c.Type {
	case "ADDED", "MODIFIED":
		_, err := p.processCertificate(c.Object)
		return err
	}
	return nil
}

func (p *CertProcessor) secretName(cert Certificate) string {
	if cert.Spec.SecretName != "" {
		return cert.Spec.SecretName
	}
	return p.certSecretPrefix + cert.Spec.Domain
}

// newACMEClient creates a new acme cliennt from the provider
func (p *CertProcessor) newACMEClient(acmeUser acme.User, provider string) (*acme.Client, *sync.Mutex, error) {
	acmeClient, err := acme.NewClient(p.acmeURL, acmeUser, acme.RSA2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while generating acme client")
	}

	initDNSProvider := func(p acme.ChallengeProvider, err error) (*acme.Client, *sync.Mutex, error) {
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Error while initializing challenge provider %v", provider)
		}

		if err := acmeClient.SetChallengeProvider(acme.DNS01, p); err != nil {
			return nil, nil, errors.Wrapf(err, "Error while setting challenge provider %v for dns-01", provider)
		}

		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
		return acmeClient, nil, nil
	}

	switch provider {
	case "http":
		acmeClient.SetHTTPAddress(":8080")
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
		return acmeClient, &p.HTTPLock, nil
	case "tls":
		acmeClient.SetTLSAddress(":8081")
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.DNS01})
		return acmeClient, &p.TLSLock, nil
	case "cloudflare":
		return initDNSProvider(cloudflare.NewDNSProvider())
	case "digitalocean":
		return initDNSProvider(digitalocean.NewDNSProvider())
	case "dnsimple":
		return initDNSProvider(dnsimple.NewDNSProvider())
	case "dnsmadeeasy":
		return initDNSProvider(dnsmadeeasy.NewDNSProvider())
	case "dnspod":
		return initDNSProvider(dnspod.NewDNSProvider())
	case "dyn":
		return initDNSProvider(dyn.NewDNSProvider())
	case "gandi":
		return initDNSProvider(gandi.NewDNSProvider())
	case "googlecloud":
		return initDNSProvider(googlecloud.NewDNSProvider())
	case "linode":
		return initDNSProvider(linode.NewDNSProvider())
	case "namecheap":
		return initDNSProvider(namecheap.NewDNSProvider())
	case "ovh":
		return initDNSProvider(ovh.NewDNSProvider())
	case "pdns":
		return initDNSProvider(pdns.NewDNSProvider())
	case "rfc2136":
		return initDNSProvider(rfc2136.NewDNSProvider())
	case "route53":
		return initDNSProvider(route53.NewDNSProvider())
	case "vultr":
		return initDNSProvider(vultr.NewDNSProvider())
	default:
		return nil, nil, errors.Errorf("Unknown provider %v", provider)
	}
}

// normalizeHostnames returns a copy of the hostnames array where all hostnames are lower
// cased and the array sorted.
// This allows the input to have changed order or different casing between runs,
// but a new certificate will only be created if a certificate is added or removed.
func normalizeHostnames(hostnames []string) []string {
	arr := make([]string, len(hostnames))
	copy(arr, hostnames)
	for i, hostname := range arr {
		arr[i] = strings.ToLower(hostname)
	}
	sort.Strings(arr)

	return arr
}

func (p *CertProcessor) getStoredAltNames(cert Certificate) ([]string, error) {
	var altNamesRaw []byte
	err := p.db.View(func(tx *bolt.Tx) error {
		altNamesRaw = tx.Bucket([]byte("domain-altnames")).Get([]byte(cert.Spec.Domain))
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Error while fetching altnames from database for domain %v", cert.Spec.Domain)
	}
	if altNamesRaw == nil {
		return nil, nil
	}

	var altNames []string
	err = json.Unmarshal(altNamesRaw, &altNames)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while unmarshalling altnames from database for domain %v", cert.Spec.Domain)
	}
	return altNames, nil
}

func equalAltNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// processCertificate handles the custom error handling on the request
func (p *CertProcessor) processCertificate(cert Certificate) (processed bool, err error) {
	hostname := cert.Spec.Domain

	// @check if this certificate is on a backoff condition
	limit, found := p.isCertificateRated(hostname)
	if found && time.Now().Before(limit.Permitted) {
		return false, fmt.Errorf("Request for: '%s' is presently in backoff for: %s", hostname, limit.Permitted.Sub(time.Now()).String())
	}

	// @step: attempt to process the certificate
	fetched, err := p.acquireCertificate(cert)
	if err != nil {
		if p.defaultBackoff <= 0 {
			return false, err
		}
		switch found {
		case true:
			limit.Permitted = limit.Permitted.Add(limit.Rate.Duration())
		default:
			req := &certBackoff{Rate: &backoff.Backoff{Factor: 2, Max: p.defaultMaxBackoff, Min: p.defaultBackoff}}
			req.Permitted = time.Now().Add(req.Rate.Duration())
			p.addCertificateRate(hostname, req)
		}

		return false, err
	}

	p.removeCertificateRate(hostname)

	return fetched, err
}

// acquireCertificate creates or renews the corresponding secret; it will create new ACME users if necessary
// and complete ACME challenges, caches ACME user and certificate information in boltdb for reuse
func (p *CertProcessor) acquireCertificate(cert Certificate) (bool, error) {
	var (
		acmeUserInfo    ACMEUserData
		acmeCertDetails ACMECertDetails
		acmeCert        ACMECertData
		acmeClient      *acme.Client
		acmeClientMutex *sync.Mutex
	)
	namespace := certificateNamespace(cert)

	// Fetch current certificate data from k8s
	s, err := p.k8s.getSecret(namespace, p.secretName(cert))
	if err != nil {
		return false, errors.Wrapf(err, "Error while fetching certificate acme data for domain %v", cert.Spec.Domain)
	}

	altNames := normalizeHostnames(cert.Spec.AltNames)
	storedAltNames, err := p.getStoredAltNames(cert)
	if err != nil {
		return false, errors.Wrap(err, "Error while getting stored alternative names")
	}

	sameAltNames := equalAltNames(altNames, storedAltNames)

	// If a cert exists, and altNames are correct check its expiry and expected altNames
	if s != nil && getDomainFromLabel(s, p.tagPrefix) == cert.Spec.Domain && sameAltNames {
		acmeCert, err = NewACMECertDataFromSecret(s, p.tagPrefix)
		if err != nil {
			return false, errors.Wrapf(err, "Error while decoding acme certificate from secret for existing domain %v", cert.Spec.Domain)
		}

		// Decode cert
		pemBlock, _ := pem.Decode(acmeCert.Cert)
		if pemBlock == nil {
			return false, errors.Wrapf(err, "Got nil back when decoding x509 encoded certificate for existing domain %v", cert.Spec.Domain)
		}

		parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return false, errors.Wrapf(err, "Error while parsing x509 encoded certificate for existing domain %v", cert.Spec.Domain)
		}

		// If certificate expires after now + p.renewBeforeDays, don't renew
		if parsedCert.NotAfter.After(time.Now().Add(time.Hour * time.Duration(24*p.renewBeforeDays))) {
			return false, nil
		}

		log.Printf("[%v] Expiry for cert is in less than %v days (%v), attempting renewal", cert.Spec.Domain, p.renewBeforeDays, parsedCert.NotAfter.String())
	}

	email := valueOrDefault(cert.Spec.Email, p.defaultEmail)

	// Fetch acme user data and cert details from bolt
	var userInfoRaw, certDetailsRaw []byte
	err = p.db.View(func(tx *bolt.Tx) error {
		userInfoRaw = tx.Bucket([]byte("user-info")).Get([]byte(email))
		certDetailsRaw = tx.Bucket([]byte("cert-details")).Get([]byte(cert.Spec.Domain))
		return nil
	})

	if err != nil {
		return false, errors.Wrapf(err, "Error while running bolt view transaction for domain %v", cert.Spec.Domain)
	}

	provider := valueOrDefault(cert.Spec.Provider, p.defaultProvider)

	// Handle user information
	if userInfoRaw != nil { // Use existing user
		if err := json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
			return false, errors.Wrapf(err, "Error while unmarshalling user info for %v", email)
		}

		log.Printf("Creating ACME client for %v provider for %v", provider, cert.Spec.Domain)
		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, provider)
		if err != nil {
			return false, errors.Wrapf(err, "Error while creating ACME client for %v provider for %v", provider, cert.Spec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Unlock()
		}
	} else { // Generate a new ACME user
		userKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return false, errors.Wrapf(err, "Error while generating rsa key for new user for domain %v", cert.Spec.Domain)
		}

		acmeUserInfo.Email = email
		acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(userKey),
		})

		log.Printf("Creating ACME client for %v provider for account %v", provider, email)
		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, provider)
		if err != nil {
			return false, errors.Wrapf(err, "Error while creating ACME client for account %v", email)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Unlock()
		}

		// Register
		acmeUserInfo.Registration, err = acmeClient.Register()
		if err != nil {
			return false, errors.Wrapf(err, "Error while registering user for new account %v", email)
		}

		// Agree to TOS
		if err := acmeClient.AgreeToTOS(); err != nil {
			return false, errors.Wrapf(err, "Error while agreeing to acme TOS for new account %v", email)
		}

		userInfoRaw, err = json.Marshal(&acmeUserInfo)
		if err != nil {
			return false, errors.Wrapf(err, "Error while marshalling user info for account %v", email)
		}
		// Save cert details and user info to bolt
		err = p.db.Update(func(tx *bolt.Tx) error {
			tx.Bucket([]byte("user-info")).Put([]byte(email), userInfoRaw)
			return nil
		})
		if err != nil {
			return false, errors.Wrapf(err, "Error while saving user data to bolt for account %v", email)
		}
	}

	domains := append([]string{cert.Spec.Domain}, altNames...)
	// If we have cert details stored with expected altNames, do a renewal, otherwise, obtain from scratch
	if certDetailsRaw == nil || acmeCert.DomainName == "" || !sameAltNames {
		acmeCert.DomainName = cert.Spec.Domain

		// Obtain a cert
		certRes, errs := acmeClient.ObtainCertificate(domains, true, nil, false)
		for _, domain := range domains {
			if errs[domain] != nil {
				return false, errors.Wrapf(errs[domain], "Error while obtaining certificate for new domain %v", domain)
			}
		}

		// fill in data
		acmeCert.Cert = certRes.Certificate
		acmeCert.PrivateKey = certRes.PrivateKey
		acmeCertDetails = NewACMECertDetailsFromResource(certRes)
	} else {
		if err := json.Unmarshal(certDetailsRaw, &acmeCertDetails); err != nil {
			return false, errors.Wrapf(err, "Error while unmarshalling cert details for existing domain %v", cert.Spec.Domain)
		}

		// Fill in cert resource
		certRes := acmeCertDetails.ToCertResource()
		certRes.Certificate = acmeCert.Cert
		certRes.PrivateKey = acmeCert.PrivateKey

		certRes, err = acmeClient.RenewCertificate(certRes, true, false)
		if err != nil {
			return false, errors.Wrapf(err, "Error while renewing certificate for existing domain %v", cert.Spec.Domain)
		}

		// Fill in details
		acmeCert.Cert = certRes.Certificate
		acmeCert.PrivateKey = certRes.PrivateKey
		acmeCertDetails = NewACMECertDetailsFromResource(certRes)
	}

	// Serialize acmeCertDetails and acmeUserInfo
	certDetailsRaw, err = json.Marshal(&acmeCertDetails)
	if err != nil {
		return false, errors.Wrapf(err, "Error while marshalling cert details for domain %v", cert.Spec.Domain)
	}

	userInfoRaw, err = json.Marshal(&acmeUserInfo)
	if err != nil {
		return false, errors.Wrapf(err, "Error while marshalling user info for domain %v", cert.Spec.Domain)
	}

	altNamesRaw, err := json.Marshal(altNames)
	if err != nil {
		return false, errors.Wrapf(err, "Error while marshalling altNames for domain %v", cert.Spec.Domain)
	}

	// Save cert details and user info to bolt
	err = p.db.Update(func(tx *bolt.Tx) error {
		key := []byte(cert.Spec.Domain)
		tx.Bucket([]byte("cert-details")).Put(key, certDetailsRaw)
		tx.Bucket([]byte("domain-altnames")).Put(key, altNamesRaw)
		return nil
	})
	if err != nil {
		return false, errors.Wrapf(err, "Error while saving data to bolt for domain %v", cert.Spec.Domain)
	}

	// Convert cert data to k8s secret
	isUpdate := s != nil
	s = acmeCert.ToSecret(p.tagPrefix, p.class)
	s.Name = p.secretName(cert)

	if isUpdate {
		log.Printf("Updating secret %v in namespace %v for domain %v", s.Name, namespace, cert.Spec.Domain)
	} else {
		log.Printf("Creating secret %v in namespace %v for domain %v", s.Name, namespace, cert.Spec.Domain)
	}

	// Save the k8s secret
	if err := p.k8s.saveSecret(namespace, s, isUpdate); err != nil {
		return false, errors.Wrapf(err, "Error while saving secret for domain %v", cert.Spec.Domain)
	}

	msg := "Created certificate"
	if isUpdate {
		msg = "Updated certificate"
	}
	p.k8s.createEvent(v1.Event{
		ObjectMeta: v1.ObjectMeta{
			Namespace: namespace,
		},
		InvolvedObject: v1.ObjectReference{
			Kind:      "Secret",
			Namespace: namespace,
			Name:      s.Name,
		},
		Reason:  "ACMEUpdated",
		Message: msg,
		Source: v1.EventSource{
			Component: "kube-cert-manager",
		},
		Type: "Normal",
	})

	return true, nil
}

func (p *CertProcessor) gcSecrets() error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	// Fetch secrets before certificates. That way, if a race occurs,
	// we will only fail to delete a secret, not accidentally delete
	// one that's still referenced.
	secrets, err := p.getSecrets()
	if err != nil {
		return err
	}
	certs, err := p.getCertificates()
	if err != nil {
		return err
	}
	ingresses, err := p.getIngresses()
	if err != nil {
		return err
	}
	for _, ingress := range ingresses {
		certs = append(certs, ingressCertificates(p, ingress)...)
	}
	usedSecrets := map[string]bool{}
	for _, cert := range certs {
		usedSecrets[cert.Metadata.Namespace+" "+p.secretName(cert)] = true
	}
	for _, secret := range secrets {
		// Only check for the deprecated "enabled" annotation if not using the "class" feature
		if p.class == "" && secret.Annotations[addTagPrefix(p.tagPrefix, "enabled")] != "true" {
			continue
		}
		if usedSecrets[secret.Namespace+" "+secret.Name] {
			continue
		}
		log.Printf("Deleting unused secret %s in namespace %s", secret.Name, secret.Namespace)
		if err := p.k8s.deleteSecret(secret.Namespace, secret.Name); err != nil {
			return err
		}
	}
	return nil
}

func (p *CertProcessor) processIngressEvent(c IngressEvent) {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	switch c.Type {
	case "ADDED", "MODIFIED":
		p.processIngress(c.Object)
	}
}

func ingressCertificates(p *CertProcessor, ingress v1beta1.Ingress) []Certificate {
	// The enabled annotation is deprecated when a class label is used
	if p.class == "" && ingress.Annotations[addTagPrefix(p.tagPrefix, "enabled")] != "true" {
		return nil
	}
	var certs []Certificate
	provider := valueOrDefault(ingress.Annotations[addTagPrefix(p.tagPrefix, "provider")], p.defaultProvider)
	email := valueOrDefault(ingress.Annotations[addTagPrefix(p.tagPrefix, "email")], p.defaultEmail)
	if provider == "" || email == "" {
		return nil
	}
	for _, tls := range ingress.Spec.TLS {
		if len(tls.Hosts) < 1 {
			continue
		}
		cert := Certificate{
			TypeMeta: unversioned.TypeMeta{
				APIVersion: "v1",
				Kind:       "Certificate",
			},
			Metadata: api.ObjectMeta{
				Namespace: ingress.Namespace,
			},
			Spec: CertificateSpec{
				Domain:     tls.Hosts[0],
				Provider:   provider,
				Email:      email,
				SecretName: tls.SecretName,
				AltNames:   tls.Hosts[1:],
			},
		}
		certs = append(certs, cert)
	}
	return certs
}

func (p *CertProcessor) processIngress(ingress v1beta1.Ingress) {
	if p.class == "" && ingress.Annotations[addTagPrefix(p.tagPrefix, "enabled")] != "true" {
		return
	}
	source := v1.EventSource{
		Component: "kube-cert-manager",
	}
	var certs []Certificate
	provider := valueOrDefault(ingress.Annotations[addTagPrefix(p.tagPrefix, "provider")], p.defaultProvider)
	email := valueOrDefault(ingress.Annotations[addTagPrefix(p.tagPrefix, "email")], p.defaultEmail)
	for _, tls := range ingress.Spec.TLS {
		if len(tls.Hosts) == 0 {
			continue
		}
		altNames := tls.Hosts[1:]
		cert := Certificate{
			TypeMeta: unversioned.TypeMeta{
				APIVersion: "v1",
				Kind:       "Certificate",
			},
			Metadata: api.ObjectMeta{
				Namespace: ingress.Namespace,
			},
			Spec: CertificateSpec{
				Domain:     tls.Hosts[0],
				Provider:   provider,
				Email:      email,
				SecretName: tls.SecretName,
				AltNames:   altNames,
			},
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 && (provider == "" || email == "") {
		p.k8s.createEvent(v1.Event{
			ObjectMeta: v1.ObjectMeta{
				Namespace: ingress.Namespace,
			},
			InvolvedObject: ingressReference(ingress, ""),
			Reason:         "ACMEMissingAnnotation",
			Message:        "Couldn't create certificates: missing email or provider annotation",
			Source:         source,
			Type:           "Warning",
		})
		return
	}
	for _, cert := range certs {
		processed, err := p.processCertificate(cert)
		if err != nil {
			p.k8s.createEvent(v1.Event{
				ObjectMeta: v1.ObjectMeta{
					Namespace: ingress.Namespace,
				},
				InvolvedObject: ingressReference(ingress, ""),
				Reason:         "ACMEError",
				Message:        fmt.Sprintf("Couldn't create certificate for secret %s: %s", cert.Spec.SecretName, err),
				Source:         source,
				Type:           "Warning",
			})
			continue
		}
		if processed {
			p.k8s.createEvent(v1.Event{
				ObjectMeta: v1.ObjectMeta{
					Namespace: ingress.Namespace,
				},
				InvolvedObject: ingressReference(ingress, ""),
				Reason:         "ACMEProcessed",
				Message:        fmt.Sprintf("Processed ACME certificate for secret: %s", cert.Spec.SecretName),
				Source:         source,
				Type:           "Normal",
			})
		}
	}
}

func certificateNamespace(c Certificate) string {
	if c.Metadata.Namespace != "" {
		return c.Metadata.Namespace
	}

	return "default"
}

func (p *CertProcessor) getLabelSelector() labels.Selector {
	if p.class != "" {
		r, err := labels.NewRequirement(
			addTagPrefix(p.tagPrefix, "class"),
			selection.Equals,
			[]string{p.class},
		)
		if err != nil {
			log.Fatalf("unable to create class-equals requirement: %v", err)
		}
		return labels.NewSelector().Add(*r)
	}
	return nil
}

// isCertificateRated checks if the certificate hostname has a certificate rate
func (p *CertProcessor) isCertificateRated(hostname string) (*certBackoff, bool) {
	p.rateLock.RLock()
	defer p.rateLock.RUnlock()

	rate, found := p.rateLimits[hostname]

	return rate, found
}

// addCertificateRate adds a certificate rate to the hostname
func (p *CertProcessor) addCertificateRate(hostname string, rate *certBackoff) {
	p.rateLock.Lock()
	defer p.rateLock.Unlock()

	p.rateLimits[hostname] = rate
}

// removeCertificateRate removes the rate froma hostname
func (p *CertProcessor) removeCertificateRate(hostname string) {
	p.rateLock.Lock()
	defer p.rateLock.Unlock()

	delete(p.rateLimits, hostname)
}

func addTagPrefix(prefix, tag string) string {
	if prefix == "" {
		return tag
	} else if strings.HasSuffix(prefix, ".") {
		// Support the deprecated "stable.k8s.psg.io/kcm." prefix
		return prefix + tag
	}
	return prefix + "/" + tag
}

func valueOrDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
