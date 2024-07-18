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

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	cd_certifier "github.com/guacsec/guac/pkg/certifier/clearlydefined"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/clearlydefined"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/vuln"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/misc/coordinates"
	"github.com/guacsec/guac/pkg/version"
)

// PurlsVulnScan takes a slice of purls and bulk queries OSV (skipping purls that start with "pkg:guac").
// Once the query returns, an attestation is generated and passed to the vulnerability parser for ingestion
func PurlsVulnScan(ctx context.Context, purls []string) ([]assembler.VulnEqualIngest, []assembler.CertifyVulnIngest, error) {
	type docResult struct {
		doc    *processor.Document
		docErr error
	}

	docChan := make(chan docResult, 1)

	go func(ctx context.Context, purls []string, docChan chan<- docResult) {
		defer close(docChan)

		var query osv_scanner.BatchedQuery
		packMap := map[string]bool{}
		for _, purl := range purls {
			// skip any purls that are generated by GUAC as they will not be found in OSV
			if strings.Contains(purl, "pkg:guac") {
				continue
			}
			if _, ok := packMap[purl]; !ok {
				// build bulk query
				purlQuery := osv_scanner.MakePURLRequest(purl)
				query.Queries = append(query.Queries, purlQuery)
				packMap[purl] = true
			}
		}

		resp, err := osv_scanner.MakeRequestWithClient(query, &http.Client{
			Transport: version.UATransport,
		})
		if err != nil {
			docChan <- docResult{doc: nil,
				docErr: fmt.Errorf("osv.dev batched request failed: %w", err)}
			return
		}
		for i, query := range query.Queries {
			response := resp.Results[i]
			purl := query.Package.PURL

			currentTime := time.Now()
			// generate a vulnerability attestation from the results
			payload, err := json.Marshal(osv.CreateAttestation(&root_package.PackageNode{Purl: purl}, response.Vulns, currentTime))
			if err != nil {
				docChan <- docResult{doc: nil,
					docErr: fmt.Errorf("unable to marshal attestation: %w", err)}
				return
			}
			doc := &processor.Document{
				Blob:   payload,
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector:   osv.OSVCollector,
					Source:      osv.OSVCollector,
					DocumentRef: events.GetDocRef(payload),
				},
			}
			docChan <- docResult{doc: doc,
				docErr: nil}
		}
	}(ctx, purls, docChan)

	// use the existing vulnerability parser to parse and obtain vuln Equal and certifyVuln values
	vulnParser := vuln.NewVulnCertificationParser()
	var vulnEquals []assembler.VulnEqualIngest
	var certifyVulns []assembler.CertifyVulnIngest
	for response := range docChan {
		if response.docErr != nil {
			return nil, nil, fmt.Errorf("docChan channel failure: %w", response.docErr)
		}
		err := vulnParser.Parse(ctx, response.doc)
		if err != nil {
			return nil, nil, fmt.Errorf("vulnerability parser failed with error: %w", err)
		}
		preds := vulnParser.GetPredicates(ctx)
		common.AddMetadata(preds, nil, response.doc.SourceInformation)
		certifyVulns = append(certifyVulns, preds.CertifyVuln...)
		vulnEquals = append(vulnEquals, preds.VulnEqual...)
	}
	return vulnEquals, certifyVulns, nil
}

// PurlsLicenseScan takes a slice of purls and queries clearly defined (skipping purls that start with "pkg:guac").
// Once the query returns, an attestation is generated and passed to the clearly defined parser for ingestion
func PurlsLicenseScan(ctx context.Context, purls []string) ([]assembler.CertifyLegalIngest, []assembler.HasSourceAtIngest, error) {
	logger := logging.FromContext(ctx)

	type docResult struct {
		doc    *processor.Document
		docErr error
	}

	docChan := make(chan docResult, 1)

	go func(ctx context.Context, purls []string, docChan chan<- docResult) {
		defer close(docChan)

		packMap := map[string]bool{}
		for _, purl := range purls {
			// skip any purls that are generated by GUAC as they will not be found in clearly defined
			if strings.Contains(purl, "pkg:guac") {
				continue
			}
			if _, ok := packMap[purl]; !ok {
				coordinate, err := coordinates.ConvertPurlToCoordinate(purl)
				if err != nil {
					logger.Debugf("failed to parse purl into coordinate with error: %v", err)
					continue
				}
				definition, err := cd_certifier.GetPkgDefinition(ctx, coordinate)
				if err != nil {
					docChan <- docResult{doc: nil,
						docErr: fmt.Errorf("failed get package definition from clearly defined with error: %w", err)}
					return
				}
				// if definition for the package is not found, continue to the next package
				if definition == nil {
					continue
				}

				packMap[purl] = true

				doc, err := generateClearlyDefinedAttestationDoc(purl, definition)
				if err != nil {
					docChan <- docResult{doc: nil,
						docErr: fmt.Errorf("failed to generate cd attestation with error: %w", err)}
					return
				}

				docChan <- docResult{doc: doc,
					docErr: nil}

				if definition.Described.SourceLocation != nil {
					srcDefinition, err := cd_certifier.GetSrcDefinition(ctx, definition.Described.SourceLocation.Type, definition.Described.SourceLocation.Provider,
						definition.Described.SourceLocation.Namespace, definition.Described.SourceLocation.Name, definition.Described.SourceLocation.Revision)
					if err != nil {
						docChan <- docResult{doc: nil,
							docErr: fmt.Errorf("failed get source definition from clearly defined with error: %w", err)}
						return
					}

					// if definition for the source is not found, continue to the next package
					if srcDefinition == nil {
						continue
					}

					srcInput := helpers.SourceToSourceInput(definition.Described.SourceLocation.Type, definition.Described.SourceLocation.Namespace,
						definition.Described.SourceLocation.Name, &definition.Described.SourceLocation.Revision)

					doc, err := generateClearlyDefinedAttestationDoc(helpers.SrcClientKey(srcInput).NameId, srcDefinition)
					if err != nil {
						docChan <- docResult{doc: nil,
							docErr: fmt.Errorf("failed to generate cd attestation with error: %w", err)}
						return
					}

					docChan <- docResult{doc: doc,
						docErr: nil}

				}
			}
		}
	}(ctx, purls, docChan)

	// use the existing clearly defined parser to parse and obtain certifyLegal
	cdParser := clearlydefined.NewLegalCertificationParser()
	var certLegalIngest []assembler.CertifyLegalIngest
	var hasSourceAtIngest []assembler.HasSourceAtIngest
	for response := range docChan {
		if response.docErr != nil {
			return nil, nil, fmt.Errorf("docChan channel failure: %w", response.docErr)
		}
		err := cdParser.Parse(ctx, response.doc)
		if err != nil {
			return nil, nil, fmt.Errorf("vulnerability parser failed with error: %w", err)
		}
		preds := cdParser.GetPredicates(ctx)
		common.AddMetadata(preds, nil, response.doc.SourceInformation)
		certLegalIngest = append(certLegalIngest, preds.CertifyLegal...)
		hasSourceAtIngest = append(hasSourceAtIngest, preds.HasSourceAt...)
	}
	return certLegalIngest, hasSourceAtIngest, nil
}

func generateClearlyDefinedAttestationDoc(purl string, definition *attestation.Definition) (*processor.Document, error) {
	currentTime := time.Now()
	// generate a vulnerability attestation from the results
	payload, err := json.Marshal(cd_certifier.CreateAttestation(purl, definition, currentTime))
	if err != nil {
		return nil, fmt.Errorf("unable to marshal attestation: %w", err)
	}
	doc := &processor.Document{
		Blob:   payload,
		Type:   processor.DocumentITE6Vul,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   cd_certifier.CDCollector,
			Source:      cd_certifier.CDCollector,
			DocumentRef: events.GetDocRef(payload),
		},
	}
	return doc, nil
}
