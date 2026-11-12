//
// Copyright 2022 The GUAC Authors.
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

package clearlydefined

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	attestation_license "github.com/guacsec/guac/pkg/certifier/attestation/license"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestParser(t *testing.T) {
	lvUnknown := "UNKNOWN"
	ctx := logging.WithLogger(context.Background())
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	tests := []struct {
		name    string
		doc     *processor.Document
		wantCLs []assembler.CertifyLegalIngest
		wantHSA []assembler.HasSourceAtIngest
		wantErr bool
	}{{
		name: "valid log4j licenses",
		doc: &processor.Document{
			Blob:   testdata.ITE6CDLog4j,
			Format: processor.FormatJSON,
			Type:   processor.DocumentITE6ClearlyDefined,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantCLs: []assembler.CertifyLegalIngest{
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Declared:   []generated.LicenseInputSpec{{Name: "Apache-2.0", ListVersion: &lvUnknown}},
				Discovered: []generated.LicenseInputSpec{{Name: "Apache-2.0", ListVersion: &lvUnknown}},
				CertifyLegal: &generated.CertifyLegalInputSpec{
					DiscoveredLicense: "Apache-2.0",
					DeclaredLicense:   "Apache-2.0",
					Justification:     "Retrieved from ClearlyDefined",
					TimeScanned:       tm,
				},
			},
		},
		wantHSA: []assembler.HasSourceAtIngest{
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				PkgMatchFlag: generated.MatchFlags{Pkg: "SPECIFIC_VERSION"},
				Src: &generated.SourceInputSpec{
					Type:      "sourcearchive",
					Namespace: "org.apache.logging.log4j",
					Name:      "log4j-core",
					Tag:       ptrfrom.String("2.8.1"),
				},
				HasSourceAt: &generated.HasSourceAtInputSpec{
					KnownSince:    tm,
					Justification: "Retrieved from ClearlyDefined",
				},
			},
		},
		wantErr: false,
	}, {
		name: "valid source log4j licenses",
		doc: &processor.Document{
			Blob:   testdata.ITE6CDSourceLog4j,
			Format: processor.FormatJSON,
			Type:   processor.DocumentITE6ClearlyDefined,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantCLs: []assembler.CertifyLegalIngest{
			{
				Src: &generated.SourceInputSpec{
					Type:      "sourcearchive",
					Namespace: "org.apache.logging.log4j",
					Name:      "log4j-core",
					Tag:       ptrfrom.String("2.8.1"),
				},
				Declared: []generated.LicenseInputSpec{},
				Discovered: []generated.LicenseInputSpec{
					{Name: "Apache-2.0", ListVersion: &lvUnknown},
					{Name: "NOASSERTION", ListVersion: &lvUnknown},
				},
				CertifyLegal: &generated.CertifyLegalInputSpec{
					DiscoveredLicense: "Apache-2.0 AND NOASSERTION",
					Attribution:       "Copyright 2005-2006 Tim Fennell,Copyright 1999-2012 Apache Software Foundation,Copyright 1999-2005 The Apache Software Foundation",
					Justification:     "Retrieved from ClearlyDefined",
					TimeScanned:       tm,
				},
			},
		},
		wantHSA: []assembler.HasSourceAtIngest{},
		wantErr: false,
	}}

	var ignoreHSATimestamp = cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".KnownSince", p[len(p)-1].String()) == 0
	}, cmp.Ignore())

	var ignoreCLTimestamp = cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".TimeScanned", p[len(p)-1].String()) == 0
	}, cmp.Ignore())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewLegalCertificationParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			ip := s.GetPredicates(ctx)
			if diff := cmp.Diff(tt.wantCLs, ip.CertifyLegal, ignoreCLTimestamp); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantHSA, ip.HasSourceAt, ignoreHSATimestamp); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParserHasSourceAtMatchesCertifierIdentity(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	revision := "9e3b772b8cabbd8cadc7522ebe3dde3279e79d9e"
	loc := &attestation_license.SourceLocation{
		Type:      "git",
		Provider:  "github",
		Namespace: "facebook",
		Name:      "react",
		Revision:  revision,
		URL:       "https://github.com/facebook/react/tree/" + revision,
	}
	wantSrc := attestation_license.SourceInputFromCD(loc)

	// Minimal ClearlyDefined attestation whose described.sourceLocation is a
	// git GitHub source. The package subject is enough for HasSourceAt.
	blob := []byte(`{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{"uri": "pkg:npm/react@18.2.0"}],
  "predicateType": "https://in-toto.io/attestation/clearlydefined/v0.1",
  "predicate": {
    "definition": {
      "described": {
        "releaseDate": "2022-06-14",
        "sourceLocation": {
          "type": "git",
          "provider": "github",
          "namespace": "facebook",
          "name": "react",
          "revision": "9e3b772b8cabbd8cadc7522ebe3dde3279e79d9e",
          "url": "https://github.com/facebook/react/tree/9e3b772b8cabbd8cadc7522ebe3dde3279e79d9e"
        }
      },
      "licensed": {
        "declared": "MIT",
        "facets": {
          "core": {
            "attribution": {"parties": []},
            "discovered": {"expressions": ["MIT"], "unknown": 0}
          }
        }
      },
      "coordinates": {
        "type": "npm",
        "provider": "npmjs",
        "namespace": "-",
        "name": "react",
        "revision": "18.2.0"
      },
      "meta": {"schemaVersion": "1.6.1", "updated": "2022-11-21T17:45:50.520Z"}
    },
    "metadata": {"scannedOn": "2022-11-21T17:45:50.520Z"}
  }
}`)

	s := NewLegalCertificationParser()
	err := s.Parse(ctx, &processor.Document{
		Blob:   blob,
		Format: processor.FormatJSON,
		Type:   processor.DocumentITE6ClearlyDefined,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	})
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	preds := s.GetPredicates(ctx)
	if len(preds.HasSourceAt) != 1 {
		t.Fatalf("expected 1 HasSourceAt, got %d", len(preds.HasSourceAt))
	}
	got := preds.HasSourceAt[0].Src
	if diff := cmp.Diff(wantSrc, got); diff != "" {
		t.Errorf("HasSourceAt.Src does not match certifier SourceInputFromCD identity (-want +got):\n%s", diff)
	}
}
