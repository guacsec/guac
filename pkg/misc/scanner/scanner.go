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
	"time"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/vuln"
	"github.com/guacsec/guac/pkg/version"
)

func PurlsToScan(ctx context.Context, purls []string) ([]assembler.VulnEqualIngest, []assembler.CertifyVulnIngest, error) {
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
			if _, ok := packMap[purl]; !ok {
				purlQuery := osv_scanner.MakePURLRequest(purl)
				query.Queries = append(query.Queries, purlQuery)
			}
			packMap[purl] = true
		}

		resp, err := osv_scanner.MakeRequestWithClient(query, &http.Client{
			Transport: version.UATransport,
		})
		if err != nil {
			docChan <- docResult{doc: nil,
				docErr: fmt.Errorf("osv.dev batched request failed: %w", err)}
		}
		for i, query := range query.Queries {
			response := resp.Results[i]
			purl := query.Package.PURL

			currentTime := time.Now()
			payload, err := json.Marshal(osv.CreateAttestation(&root_package.PackageNode{Purl: purl}, response.Vulns, currentTime))
			if err != nil {
				docChan <- docResult{doc: nil,
					docErr: fmt.Errorf("unable to marshal attestation: %w", err)}
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

	vulnParser := vuln.NewVulnCertificationParser()
	var vulnEquals []assembler.VulnEqualIngest
	var certifyVulns []assembler.CertifyVulnIngest
	for response := range docChan {
		if response.docErr != nil {
			return nil, nil, fmt.Errorf("docChan channel failure: %w", response.docErr)
		}
		err := vulnParser.Parse(ctx, response.doc)
		if err != nil {
			return nil, nil, err
		}
		preds := vulnParser.GetPredicates(ctx)

		certifyVulns = append(certifyVulns, preds.CertifyVuln...)
		vulnEquals = append(vulnEquals, preds.VulnEqual...)
	}
	return vulnEquals, certifyVulns, nil
}
