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
	"github.com/pkg/errors"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (p *CertProcessor) getSecrets() ([]v1.Secret, error) {
	var secrets []v1.Secret
	var err error

	switch len(p.namespaces) {
	case 0:
		secrets, err = p.k8s.getSecrets(v1.NamespaceAll, p.getLabelSelector())
	default:
		for _, namespace := range p.namespaces {
			s, err := p.k8s.getSecrets(namespace, p.getLabelSelector())
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching secret list")
			}
			secrets = append(secrets, s...)
		}
	}

	return secrets, err
}

func (p *CertProcessor) getCertificates() ([]Certificate, error) {
	var certificates []Certificate
	var err error

	switch len(p.namespaces) {
	case 0:
		certificates, err = p.k8s.getCertificates(v1.NamespaceAll, p.getLabelSelector())
	default:
		for _, namespace := range p.namespaces {
			certs, err := p.k8s.getCertificates(namespace, p.getLabelSelector())
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching certificate list")
			}
			certificates = append(certificates, certs...)
		}
	}

	return certificates, err
}

func (p *CertProcessor) getIngresses() ([]v1beta1.Ingress, error) {
	var ingresses []v1beta1.Ingress
	var err error

	switch len(p.namespaces) {
	case 0:
		ingresses, err = p.k8s.getIngresses(v1.NamespaceAll, p.getLabelSelector())
	default:
		for _, namespace := range p.namespaces {
			igs, err := p.k8s.getIngresses(namespace, p.getLabelSelector())
			if err != nil {
				return nil, errors.Wrap(err, "Error while fetching ingress list")
			}
			ingresses = append(ingresses, igs...)
		}
	}

	return ingresses, err
}
