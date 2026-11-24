//
// Copyright 2026 The GUAC Authors.
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

package intoto_sbom

import (
	"context"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	// differs from the digest in the SBOM purls, so the link can only come from the subject
	subjectDigest = "db57c6d5709fa3f1cec415ae1c75348c10315baf18762bd90f71ed79f5c1de33"

	spdxSBOM = `{
	"spdxVersion": "SPDX-2.3",
	"SPDXID": "SPDXRef-DOCUMENT",
	"name": "app",
	"documentNamespace": "https://example.com/app",
	"creationInfo": { "created": "2023-01-01T01:01:01.00Z" },
	"packages": [{
		"SPDXID": "SPDXRef-Package-app",
		"name": "app",
		"externalRefs": [{
			"referenceCategory": "PACKAGE_MANAGER",
			"referenceLocator": "pkg:oci/app@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"referenceType": "purl"
		}]
	}],
	"relationships": [{
		"spdxElementId": "SPDXRef-DOCUMENT",
		"relationshipType": "DESCRIBES",
		"relatedSpdxElement": "SPDXRef-Package-app"
	}]
}`

	cdxSBOM = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.5",
	"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
	"version": 1,
	"metadata": {
		"timestamp": "2023-01-01T01:01:01Z",
		"component": {
			"type": "container",
			"bom-ref": "pkg:oci/app@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"name": "app",
			"purl": "pkg:oci/app@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10"
		}
	},
	"components": [{
		"type": "library",
		"bom-ref": "pkg:golang/example.com/lib@v1.0.0",
		"name": "example.com/lib",
		"version": "v1.0.0",
		"purl": "pkg:golang/example.com/lib@v1.0.0"
	}]
}`
)

func statementBlob(predicateType, predicate string) []byte {
	return []byte(`{
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "` + predicateType + `",
	"subject": [{"name": "registry.example.com/app", "digest": {"sha256": "` + strings.ToUpper(subjectDigest) + `"}}],
	"predicate": ` + predicate + `
}`)
}

func TestIntotoSBOMParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	subjectArt := generated.ArtifactInputSpec{Algorithm: "sha256", Digest: subjectDigest}
	encodedSPDX := `"` + strings.NewReplacer(`"`, `\"`, "\n", `\n`, "\t", `\t`).Replace(spdxSBOM) + `"`

	tests := []struct {
		name        string
		blob        []byte
		wantErr     bool
		wantSubject bool
		wantPurls   bool
	}{
		{
			name:        "SPDX predicate",
			blob:        statementBlob("https://spdx.dev/Document", spdxSBOM),
			wantSubject: true,
			wantPurls:   true,
		},
		{
			name:        "SPDX predicate encoded as a string",
			blob:        statementBlob("https://spdx.dev/Document/v2.3", encodedSPDX),
			wantSubject: true,
			wantPurls:   true,
		},
		{
			name:        "CycloneDX predicate",
			blob:        statementBlob("https://cyclonedx.org/bom/v1.5", cdxSBOM),
			wantSubject: true,
			wantPurls:   true,
		},
		{
			name:    "not an SBOM predicate",
			blob:    statementBlob("https://slsa.dev/provenance/v0.2", `{}`),
			wantErr: true,
		},
		{
			name:    "missing predicate",
			blob:    statementBlob("https://spdx.dev/Document", `null`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewIntotoSBOMParser()
			err := p.Parse(ctx, &processor.Document{
				Blob:   tt.blob,
				Type:   processor.DocumentITE6SBOM,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			preds := p.GetPredicates(ctx)
			if got := hasSBOMFor(preds.HasSBOM, &subjectArt); got != tt.wantSubject {
				t.Errorf("HasSBOM for the subject artifact = %v, want %v", got, tt.wantSubject)
			}
			if got := occurrenceFor(preds.IsOccurrence, &subjectArt); got != tt.wantSubject {
				t.Errorf("IsOccurrence of the subject artifact = %v, want %v", got, tt.wantSubject)
			}

			ids, err := p.GetIdentifiers(ctx)
			if err != nil {
				t.Fatalf("GetIdentifiers() error = %v", err)
			}
			if got := len(ids.PurlStrings) > 0; got != tt.wantPurls {
				t.Errorf("GetIdentifiers() purls = %v, want some: %v", ids.PurlStrings, tt.wantPurls)
			}
		})
	}
}

func TestIntotoSBOMParserWithoutSubjects(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	blob := []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://spdx.dev/Document", "predicate": ` + spdxSBOM + `}`)

	p := NewIntotoSBOMParser()
	if err := p.Parse(ctx, &processor.Document{Blob: blob, Type: processor.DocumentITE6SBOM, Format: processor.FormatJSON}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	preds := p.GetPredicates(ctx)
	for _, h := range preds.HasSBOM {
		if h.Artifact != nil {
			t.Errorf("unexpected HasSBOM on artifact %+v", h.Artifact)
		}
	}
	for _, o := range preds.IsOccurrence {
		if o.IsOccurrence.Justification == subjectJustification {
			t.Errorf("unexpected subject IsOccurrence %+v", o)
		}
	}
}

func occurrenceFor(occurrences []assembler.IsOccurrenceIngest, art *generated.ArtifactInputSpec) bool {
	for _, o := range occurrences {
		if o.Pkg != nil && o.Artifact != nil && sameArtifact(o.Artifact, art) &&
			o.IsOccurrence.Justification == subjectJustification {
			return true
		}
	}
	return false
}
