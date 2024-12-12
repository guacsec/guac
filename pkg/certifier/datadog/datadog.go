//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datadog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	ingestor "github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	jsoniter "github.com/json-iterator/go"
	"golang.org/x/time/rate"
)

var (
	json              = jsoniter.ConfigCompatibleWithStandardLibrary
	rateLimit         = 10000
	rateLimitInterval = 30 * time.Second
)

const (
	NPM_MANIFEST_URL  string = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json"
	PYPI_MANIFEST_URL string = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json"
	DataDogCollector  string = "datadog_certifier"
)

var ErrDataDogComponentTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type MaliciousPackages map[string][]string

type assemblerFuncType func([]assembler.IngestPredicates) (*ingestor.AssemblerIngestedIDs, error)

type datadogCertifier struct {
	httpClient    *http.Client
	npmData       MaliciousPackages
	pypiData      MaliciousPackages
	assemblerFunc assemblerFuncType
}

// CertifierOption defines functional options for the certifier
type CertifierOption func(*datadogCertifier)

// WithHTTPClient allows overriding the default HTTP client
func WithHTTPClient(client *http.Client) CertifierOption {
	return func(d *datadogCertifier) {
		d.httpClient = client
	}
}

// NewDataDogCertifier initializes the DataDog Certifier
func NewDataDogCertifier(ctx context.Context, assemblerFunc assemblerFuncType, opts ...CertifierOption) (certifier.Certifier, error) {
	limiter := rate.NewLimiter(rate.Every(rateLimitInterval), rateLimit)
	transport := clients.NewRateLimitedTransport(version.UATransport, limiter)
	defaultClient := &http.Client{Transport: transport}

	d := &datadogCertifier{
		httpClient:    defaultClient,
		assemblerFunc: assemblerFunc,
	}

	// apply options
	for _, opt := range opts {
		opt(d)
	}

	if err := d.fetchManifests(); err != nil {
		return nil, fmt.Errorf("failed to fetch DataDog manifests: %w", err)
	}

	return d, nil
}

func (d *datadogCertifier) fetchManifests() error {
	npmResp, err := d.httpClient.Get(NPM_MANIFEST_URL)
	if err != nil {
		return fmt.Errorf("failed to fetch NPM manifest: %w", err)
	}
	defer npmResp.Body.Close()

	if err := json.NewDecoder(npmResp.Body).Decode(&d.npmData); err != nil {
		return fmt.Errorf("failed to decode NPM manifest: %w", err)
	}

	pypiResp, err := d.httpClient.Get(PYPI_MANIFEST_URL)
	if err != nil {
		return fmt.Errorf("failed to fetch PyPI manifest: %w", err)
	}
	defer pypiResp.Body.Close()

	if err := json.NewDecoder(pypiResp.Body).Decode(&d.pypiData); err != nil {
		return fmt.Errorf("failed to decode PyPI manifest: %w", err)
	}

	return nil
}

func (d *datadogCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrDataDogComponentTypeMismatch
	}

	predicates := &assembler.IngestPredicates{}
	currentTime := time.Now().UTC()

	for _, node := range packageNodes {
		purl := node.Purl

		pkgInput, err := helpers.PurlToPkg(purl)
		if err != nil {
			logger.Debugf("failed to parse purl '%s' into package: %v", purl, err)
			continue
		}

		// determine which dataset to check based on package type
		var maliciousVersions []string
		switch pkgInput.Type {
		case "npm":
			fullName := pkgInput.Name
			if pkgInput.Namespace != nil && *pkgInput.Namespace != "" {
				namespace := strings.TrimPrefix(*pkgInput.Namespace, "@")
				namespace = strings.TrimPrefix(namespace, "%40")
				fullName = "@" + namespace + "/" + pkgInput.Name
			}
			v, found := d.npmData[fullName]
			if !found {
				continue
			}
			maliciousVersions = v
		case "pypi":
			v, found := d.pypiData[pkgInput.Name]
			if !found {
				continue
			}
			maliciousVersions = v
		default:
			logger.Debugf("Skipping package %s, not npm or pypi", purl)
			continue
		}

		// if no versions specified in dataset, skip
		if len(maliciousVersions) == 0 {
			// package known but no malicious versions listed?
			continue
		}

		// certify only if the package has a specified version and that exact version is known malicious
		if pkgInput.Version == nil {
			logger.Debugf("Package %s has no version specified, skipping...", purl)
			continue
		}

		versionToCheck := *pkgInput.Version
		if !containsVersion(maliciousVersions, versionToCheck) {
			// the requested package version is not in the malicious list
			logger.Debugf("Package %s version %s not found in malicious dataset", purl, versionToCheck)
			continue
		}

		// this exact version is known to be malicious
		justification := fmt.Sprintf("Package version found in DataDog's malicious software packages dataset. Malicious version: %s", versionToCheck)
		certifyBad := &assembler.CertifyBadIngest{
			Pkg:          pkgInput,
			PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
			CertifyBad: &generated.CertifyBadInputSpec{
				Justification: justification,
				Origin:        "DataDog Malicious Software Packages Dataset",
				Collector:     DataDogCollector,
				KnownSince:    currentTime,
			},
		}

		predicates.CertifyBad = append(predicates.CertifyBad, *certifyBad)
	}

	if len(predicates.CertifyBad) > 0 {
		if _, err := d.assemblerFunc([]assembler.IngestPredicates{*predicates}); err != nil {
			return fmt.Errorf("unable to assemble graphs: %w", err)
		}
	}

	return nil
}

// containsVersion checks if a given version string is in the malicious versions list
func containsVersion(maliciousVersions []string, versionToCheck string) bool {
	for _, v := range maliciousVersions {
		if v == versionToCheck {
			return true
		}
	}
	return false
}
