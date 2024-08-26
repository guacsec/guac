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
	"fmt"
	"net/http"

	"github.com/guacsec/guac/pkg/assembler"
	cd_certifier "github.com/guacsec/guac/pkg/certifier/clearlydefined"
	osv_certifier "github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/ingestor/parser/clearlydefined"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/vuln"
	"github.com/guacsec/guac/pkg/version"
)

// PurlsVulnScan takes a slice of purls and bulk queries OSV (skipping purls that start with "pkg:guac").
// Once the query returns, an attestation is generated and passed to the vulnerability parser for ingestion
func PurlsVulnScan(ctx context.Context, purls []string) ([]assembler.VulnEqualIngest, []assembler.CertifyVulnIngest, error) {
	// use the existing vulnerability parser to parse and obtain vuln Equal and certifyVuln values
	vulnParser := vuln.NewVulnCertificationParser()
	var vulnEquals []assembler.VulnEqualIngest
	var certifyVulns []assembler.CertifyVulnIngest

	if osvProcessorDocs, err := osv_certifier.EvaluateOSVResponse(ctx, &http.Client{
		Transport: version.UATransport,
	}, purls); err != nil {
		return nil, nil, fmt.Errorf("failed get response from OSV with error: %w", err)
	} else {
		for _, doc := range osvProcessorDocs {
			err := vulnParser.Parse(ctx, doc)
			if err != nil {
				return nil, nil, fmt.Errorf("vulnerability parser failed with error: %w", err)
			}
			preds := vulnParser.GetPredicates(ctx)
			common.AddMetadata(preds, nil, doc.SourceInformation)
			certifyVulns = append(certifyVulns, preds.CertifyVuln...)
			vulnEquals = append(vulnEquals, preds.VulnEqual...)
		}
	}
	return vulnEquals, certifyVulns, nil
}

// PurlsLicenseScan takes a slice of purls and queries clearly defined (skipping purls that start with "pkg:guac").
// Once the query returns, an attestation is generated and passed to the clearly defined parser for ingestion
func PurlsLicenseScan(ctx context.Context, purls []string) ([]assembler.CertifyLegalIngest, []assembler.HasSourceAtIngest, error) {
	// use the existing clearly defined parser to parse and obtain certifyLegal
	cdParser := clearlydefined.NewLegalCertificationParser()
	var certLegalIngest []assembler.CertifyLegalIngest
	var hasSourceAtIngest []assembler.HasSourceAtIngest

	if cdProcessorDocs, err := cd_certifier.EvaluateClearlyDefinedDefinition(ctx, purls); err != nil {
		return nil, nil, fmt.Errorf("failed get definition from clearly defined with error: %w", err)
	} else {
		for _, doc := range cdProcessorDocs {
			err := cdParser.Parse(ctx, doc)
			if err != nil {
				return nil, nil, fmt.Errorf("vulnerability parser failed with error: %w", err)
			}
			preds := cdParser.GetPredicates(ctx)
			common.AddMetadata(preds, nil, doc.SourceInformation)
			certLegalIngest = append(certLegalIngest, preds.CertifyLegal...)
			hasSourceAtIngest = append(hasSourceAtIngest, preds.HasSourceAt...)
		}
	}
	return certLegalIngest, hasSourceAtIngest, nil
}
