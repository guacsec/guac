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
			Type:   processor.DocumentITE6Vul,
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
				Discovered: []generated.LicenseInputSpec{},
				CertifyLegal: &generated.CertifyLegalInputSpec{
					DeclaredLicense: "Apache-2.0",
					Justification:   "Retrieved from ClearlyDefined",
					TimeScanned:     tm,
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Declared:   []generated.LicenseInputSpec{},
				Discovered: []generated.LicenseInputSpec{{Name: "Apache-2.0", ListVersion: &lvUnknown}},
				CertifyLegal: &generated.CertifyLegalInputSpec{
					DiscoveredLicense: "Apache-2.0",
					Attribution:       "Copyright 2005-2006 Tim Fennell,Copyright 1999-2012 Apache Software Foundation,Copyright 1999-2005 The Apache Software Foundation",
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
			Type:   processor.DocumentITE6Vul,
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
		wantHSA: nil,
		wantErr: false,
	}}

	var ignoreTimestamp = cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".KnownSince", p[len(p)-1].String()) == 0
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
			if diff := cmp.Diff(tt.wantCLs, ip.CertifyLegal); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantHSA, ip.HasSourceAt, ignoreTimestamp); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
