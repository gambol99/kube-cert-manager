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
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"github.com/xenolf/lego/providers/dns/digitalocean"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
	"github.com/xenolf/lego/providers/dns/dyn"
	"github.com/xenolf/lego/providers/dns/gandi"
	"github.com/xenolf/lego/providers/dns/googlecloud"
	"github.com/xenolf/lego/providers/dns/namecheap"
	"github.com/xenolf/lego/providers/dns/ovh"
	"github.com/xenolf/lego/providers/dns/pdns"
	"github.com/xenolf/lego/providers/dns/rfc2136"
	"github.com/xenolf/lego/providers/dns/route53"
	"github.com/xenolf/lego/providers/dns/vultr"
)

type CertProcessor struct {
	certSecretPrefix string
	acmeURL          string
	namespaces       []string
	db               *bolt.DB
	Lock             sync.Mutex
	HTTPLock         sync.Mutex
	TLSLock          sync.Mutex
}

func NewCertProcessor(acmeURL string, certSecretPrefix string, namespaces []string, db *bolt.DB) *CertProcessor {
	return &CertProcessor{
		acmeURL:          acmeURL,
		certSecretPrefix: certSecretPrefix,
		namespaces:       namespaces,
		db:               db,
	}
}

func (p *CertProcessor) newACMEClient(acmeUser acme.User, provider string) (*acme.Client, *sync.Mutex, error) {
	acmeClient, err := acme.NewClient(p.acmeURL, acmeUser, acme.RSA2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while generating acme client")
	}

	initDNSProvider := func(p acme.ChallengeProvider, err error) (*acme.Client, *sync.Mutex, error) {
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Error while initializing provider %v", provider)
		}

		if err := acmeClient.SetChallengeProvider(acme.DNS01, p); err != nil {
			return nil, nil, errors.Wrap(err, "Error while setting cloudflare challenge provider")
		}

		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
		return acmeClient, nil, nil
	}

	switch provider {
	case "http":
		acmeClient.SetHTTPAddress("8080")
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
		return acmeClient, &p.HTTPLock, nil
	case "tls":
		acmeClient.SetTLSAddress("8081")
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
	case "dyn":
		return initDNSProvider(dyn.NewDNSProvider())
	case "gandi":
		return initDNSProvider(gandi.NewDNSProvider())
	case "googlecloud":
		return initDNSProvider(googlecloud.NewDNSProvider())
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

func (p *CertProcessor) syncCertificates(verbose bool) error {
	// FIXME(dh): sync implicit certificates created by Ingress
	p.Lock.Lock()
	defer p.Lock.Unlock()

	var certificates []Certificate
	if len(p.namespaces) == 0 {
		var err error
		certificates, err = getCertificates(certEndpointAll)
		if err != nil {
			return errors.Wrap(err, "Error while fetching certificate list")
		}
	} else {
		for _, namespace := range p.namespaces {
			certs, err := getCertificates(namespacedEndpoint(certEndpoint, namespace))
			if err != nil {
				return errors.Wrap(err, "Error while fetching certificate list")
			}
			certificates = append(certificates, certs...)
		}
	}

	var wg sync.WaitGroup
	for _, cert := range certificates {
		wg.Add(1)
		go func(cert Certificate) {
			defer wg.Done()
			_, err := p.processCertificate(cert)
			if err != nil {
				log.Printf("Error while processing certificate during sync: %v", err)
			}
		}(cert)
	}
	wg.Wait()
	return nil
}

func (p *CertProcessor) watchKubernetesEvents(certEndpoint, ingressEndpoint string, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	certEvents, certErrs := monitorCertificateEvents(certEndpoint)
	ingressEvents, ingressErrs := monitorIngressEvents(ingressEndpoint)
	watchErrs := make(chan error)
	go func() {
		for {
			select {
			case err := <-certErrs:
				watchErrs <- err
			case err := <-ingressErrs:
				watchErrs <- err
			case <-doneChan:
				return
			}
		}
	}()
	for {
		select {
		case event := <-certEvents:
			err := p.processCertificateEvent(event)
			if err != nil {
				log.Printf("Error while processing certificate event: %v", err)
			}
		case event := <-ingressEvents:
			p.processIngressEvent(event)
		case err := <-watchErrs:
			log.Printf("Error while watching kubernetes events: %v", err)
		case <-doneChan:
			wg.Done()
			log.Println("Stopped certificate event watcher.")
			return
		}
	}
}

func (p *CertProcessor) refreshCertificates(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	for {
		select {
		case <-time.After(syncInterval):
			err := p.syncCertificates(false)
			if err != nil {
				log.Printf("Error while synchronizing certificates during refresh: %v", err)
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
	case "ADDED":
		_, err := p.processCertificate(c.Object)
		return err
	case "DELETED":
		return p.deleteCertificate(c.Object)
	}
	return nil
}

func (p *CertProcessor) secretName(cert Certificate) string {
	if cert.Spec.SecretName != "" {
		return cert.Spec.SecretName
	}
	return p.certSecretPrefix + cert.Spec.Domain
}

func (p *CertProcessor) processCertificate(cert Certificate) (processed bool, err error) {
	var (
		acmeUserInfo    ACMEUserData
		acmeCertDetails ACMECertDetails
		acmeCert        ACMECertData
		acmeClient      *acme.Client
		acmeClientMutex *sync.Mutex
	)
	namespace := certificateNamespace(cert)

	// Fetch current certificate data from k8s
	s, err := getSecret(namespace, p.secretName(cert))
	if err != nil {
		return false, errors.Wrapf(err, "Error while fetching certificate acme data for domain %v", cert.Spec.Domain)
	}

	// If a cert exists, check its expiry
	if s != nil {
		acmeCert, err = NewACMECertDataFromSecret(s)
		if err != nil {
			return false, errors.Wrapf(err, "Error while decoding acme certificate from secret for existing domain %v", cert.Spec.Domain)
		}

		// Decode cert
		pemBlock, _ := pem.Decode(acmeCert.Cert)
		parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return false, errors.Wrapf(err, "Error while decoding x509 encoded certificate for existing domain %v", cert.Spec.Domain)
		}

		// If certificate expires in more than a week, don't renew
		if parsedCert.NotAfter.After(time.Now().Add(time.Hour * 24 * 7)) {
			return false, nil
		}

		log.Printf("[%v] Expiry for cert is in less than a week (%v), attempting renewal", cert.Spec.Domain, parsedCert.NotAfter.String())
	}

	// Fetch acme user data and cert details from bolt
	var userInfoRaw, certDetailsRaw []byte
	err = p.db.View(func(tx *bolt.Tx) error {
		userInfoRaw = tx.Bucket([]byte("user-info")).Get([]byte(cert.Spec.Domain))
		certDetailsRaw = tx.Bucket([]byte("cert-details")).Get([]byte(cert.Spec.Domain))
		return nil
	})

	if err != nil {
		return false, errors.Wrapf(err, "Error while running bolt view transaction for domain %v", cert.Spec.Domain)
	}

	// Handle user information
	if userInfoRaw != nil { // Use existing user
		if err := json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
			return false, errors.Wrapf(err, "Error while unmarshalling user info for %v", cert.Spec.Domain)
		}

		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, cert.Spec.Provider)
		if err != nil {
			return false, errors.Wrapf(err, "Error while creating ACME client for %v", cert.Spec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Lock()
		}
	} else { // Generate a new ACME user
		userKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return false, errors.Wrapf(err, "Error while generating rsa key for new user for domain %v", cert.Spec.Domain)
		}

		acmeUserInfo.Email = cert.Spec.Email
		acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(userKey),
		})

		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, cert.Spec.Provider)
		if err != nil {
			return false, errors.Wrapf(err, "Error while creating ACME client for %v", cert.Spec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Lock()
		}

		// Register
		acmeUserInfo.Registration, err = acmeClient.Register()
		if err != nil {
			return false, errors.Wrapf(err, "Error while registering user for new domain %v", cert.Spec.Domain)
		}

		// Agree to TOS
		if err := acmeClient.AgreeToTOS(); err != nil {
			return false, errors.Wrapf(err, "Error while agreeing to acme TOS for new domain %v", cert.Spec.Domain)
		}
	}

	// If we have cert details stored, do a renewal, otherwise, obtain from scratch
	if certDetailsRaw == nil || acmeCert.DomainName == "" {
		acmeCert.DomainName = cert.Spec.Domain

		// Obtain a cert
		certRes, errs := acmeClient.ObtainCertificate([]string{cert.Spec.Domain}, true, nil)
		if errs[cert.Spec.Domain] != nil {
			return false, errors.Wrapf(errs[cert.Spec.Domain], "Error while obtaining certificate for new domain %v", cert.Spec.Domain)
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

		certRes, err = acmeClient.RenewCertificate(certRes, true)
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

	// Save cert details and user info to bolt
	err = p.db.Update(func(tx *bolt.Tx) error {
		key := []byte(cert.Spec.Domain)
		tx.Bucket([]byte("user-info")).Put(key, userInfoRaw)
		tx.Bucket([]byte("cert-details")).Put(key, certDetailsRaw)
		return nil
	})
	if err != nil {
		return false, errors.Wrapf(err, "Error while saving data to bolt for domain %v", cert.Spec.Domain)
	}

	// Convert cert data to k8s secret
	isUpdate := s != nil
	s = acmeCert.ToSecret()
	s.Metadata["name"] = p.secretName(cert)

	// Save the k8s secret
	if err := saveSecret(namespace, s, isUpdate); err != nil {
		return false, errors.Wrapf(err, "Error while saving secret for domain %v", cert.Spec.Domain)
	}

	return true, nil
}

func (p *CertProcessor) deleteCertificate(cert Certificate) error {
	namespace := certificateNamespace(cert)
	secretName := p.secretName(cert)
	log.Printf("[%v] Deleting secret %v", cert.Spec.Domain, secretName)
	if err := deleteSecret(namespace, secretName); err != nil {
		return errors.Wrapf(err, "Error while deleting secret for domain %v", cert.Spec.Domain)
	}

	log.Printf("[%v] Deleting user info and certificate details", cert.Spec.Domain)
	err := p.db.Update(func(tx *bolt.Tx) error {
		key := []byte(cert.Spec.Domain)
		tx.Bucket([]byte("user-info")).Delete(key)
		tx.Bucket([]byte("cert-details")).Delete(key)
		return nil
	})

	if err != nil {
		return errors.Wrapf(err, "Error while saving data to bolt for domain %v", cert.Spec.Domain)
	}

	return nil
}

func (p *CertProcessor) processIngressEvent(c IngressEvent) {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	switch c.Type {
	case "ADDED", "MODIFIED":
		if c.Object.Metadata.Annotations["stable.k8s.psg.io/kcm.enabled"] != "true" {
			return
		}
		source := EventSource{
			Component: "kube-cert-manager",
		}
		var certs []Certificate
		provider := c.Object.Metadata.Annotations["stable.k8s.psg.io/kcm.provider"]
		email := c.Object.Metadata.Annotations["stable.k8s.psg.io/kcm.email"]
		for i, tls := range c.Object.Spec.TLS {
			if len(tls.Hosts) == 0 {
				continue
			}
			if len(tls.Hosts) > 1 {
				createEvent(Event{
					Metadata: EventMetadata{
						Namespace: c.Object.Metadata.Namespace,
					},
					InvolvedObject: ingressReference(c.Object, fmt.Sprintf("spec.tls[%d]", i)),
					Reason:         "ACMEMultipleHosts",
					Message:        fmt.Sprintf("Couldn't create LE certificate for secret %s: don't support multiple hosts per secret", tls.SecretName),
					Source:         source,
					Type:           "Warning",
				})
				continue
			}
			cert := Certificate{
				ApiVersion: "v1",
				Kind:       "Certificate",
				Metadata: CertificateMetadata{
					Namespace: c.Object.Metadata.Namespace,
				},
				Spec: CertificateSpec{
					Domain:     tls.Hosts[0],
					Provider:   provider,
					Email:      email,
					SecretName: tls.SecretName,
				},
			}
			certs = append(certs, cert)
		}
		if len(certs) > 0 && (provider == "" || email == "") {
			createEvent(Event{
				Metadata: EventMetadata{
					Namespace: c.Object.Metadata.Namespace,
				},
				InvolvedObject: ingressReference(c.Object, ""),
				Reason:         "ACMEMissingAnnotation",
				Message: fmt.Sprintf("Couldn't create certificates: missing email or provider annotation",
					c.Object.Metadata.Name),
				Source: source,
				Type:   "Warning",
			})
			return
		}
		for _, cert := range certs {
			processed, err := p.processCertificate(cert)
			if err != nil {
				createEvent(Event{
					Metadata: EventMetadata{
						Namespace: c.Object.Metadata.Namespace,
					},
					InvolvedObject: ingressReference(c.Object, ""),
					Reason:         "ACMEError",
					Message:        fmt.Sprintf("Couldn't create certificate for secret %s: %s", cert.Spec.SecretName, err),
					Source:         source,
					Type:           "Warning",
				})
				continue
			}
			if processed {
				createEvent(Event{
					Metadata: EventMetadata{
						Namespace: c.Object.Metadata.Namespace,
					},
					InvolvedObject: ingressReference(c.Object, ""),
					Reason:         "ACMEProcessed",
					Message:        fmt.Sprintf("Processed ACME certificate for secret: %s", cert.Spec.SecretName),
					Source:         source,
					Type:           "Normal",
				})
			}
		}
	case "DELETED":
		// TODO(dh): clean up unused certs. We can't blindly delete
		// the certs for all listed domains, as the same domains and
		// secrets may be referenced in other Ingresses, or in
		// Certificate objects.
	}
}

func certificateNamespace(c Certificate) string {
	if c.Metadata.Namespace != "" {
		return c.Metadata.Namespace
	}
	return "default"
}
