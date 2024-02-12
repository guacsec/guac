//
// Copyright 2023 The GUAC Authors.
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

package backend_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var vmd1 = &model.ScanMetadata{
	Collector:      "test collector",
	Origin:         "test origin",
	ScannerVersion: "v1.0.0",
	ScannerURI:     "test scanner uri",
	DbVersion:      "2023.01.01",
	DbURI:          "test db uri",
	TimeScanned:    testdata.T1,
}

func TestIngestCertifyVulnerability(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		InPkg        []*model.IDorPkgInput
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpVuln      []*model.CertifyVuln
		Query        *model.CertifyVulnSpec
		QueryID      bool
		QueryPkgID   bool
		QueryVulnID  bool
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.C1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					ID:      "1",
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify NoVuln",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.NoVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("noVuln"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.O1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("osv"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &testdata.G1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &testdata.G1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on Vulnerability ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			QueryVulnID: true,
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			QueryID: true,
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query DbURI",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri 1",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				DbURI: ptrfrom.String("test db uri 1"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri 1",
						TimeScanned:    testdata.T1,
					},
				},
			},
		},
		{
			Name:   "Query DB Version",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				DbVersion: ptrfrom.String("2023.08.01"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
		},
		{
			Name:   "Query TimeScanned",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				TimeScanned: ptrfrom.Time(testTime),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
			},
		},
		{
			Name:   "Query ScannerURI",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				ScannerURI: ptrfrom.String("test scanner uri 1"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
			},
		},
		{
			Name:   "Query ScannerVersion",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.8.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				ScannerVersion: ptrfrom.String("v1.8.0"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.8.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
			},
		},
		{
			Name:   "Query on Package",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P3}},
			Calls: []call{
				{
					Pkg:  testdata.P3,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Package: &model.PkgSpec{
					Name:    ptrfrom.String(testdata.P3.Name),
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P3out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on Package ID",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P3}},
			Calls: []call{
				{
					Pkg:  testdata.P3,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			QueryPkgID: true,
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P3out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVuln: nil,
		},
		{
			Name:   "Query No Vuln",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.NoVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("noVuln"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query No Vuln - with novuln boolen",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.NoVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
				{
					Pkg:  testdata.P1,
					Vuln: testdata.C1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					NoVuln: ptrfrom.Bool(true),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query only cve (exclude novuln) - with novuln boolen",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.NoVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
				{
					Pkg:  testdata.P1,
					Vuln: testdata.C1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:   ptrfrom.String("cve"),
					NoVuln: ptrfrom.Bool(false),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query all vulns - with novuln boolean omitted",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.C1, testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.NoVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
				{
					Pkg:  testdata.P1,
					Vuln: testdata.C1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
				{
					Pkg:  testdata.P1,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri 1",
						TimeScanned:    testdata.T1,
					},
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testdata.T1,
					},
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: &model.ScanMetadata{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.8.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    testTime,
					},
				},
				{
					Package: testdata.P3out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, g := range test.InVuln {
				if vulnIDs, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: g}); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				} else {
					if test.QueryVulnID {
						test.Query = &model.CertifyVulnSpec{
							Vulnerability: &model.VulnerabilitySpec{
								ID: ptrfrom.String(vulnIDs.VulnerabilityNodeID),
							},
						}
					}
				}
			}
			if pkgIDs, err := b.IngestPackages(ctx, test.InPkg); err != nil {
				t.Fatalf("Could not ingest packages: %v", err)
			} else {
				if test.QueryPkgID {
					test.Query = &model.CertifyVulnSpec{
						Package: &model.PkgSpec{
							ID: ptrfrom.String(pkgIDs[0].PackageVersionID),
						},
					}
				}
			}
			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				cvID, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: o.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: o.Vuln}, *o.CertifyVuln)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyVulnSpec{
						ID: ptrfrom.String(cvID),
					}
				}
				ids[i] = cvID
			}
			if test.Query != nil {
				if test.Query.ID != nil {
					idIndex, err := strconv.Atoi(*test.Query.ID)
					if err == nil && idIndex > -1 && idIndex < len(ids) {
						test.Query.ID = ptrfrom.String(ids[idIndex])
					}
				}
			}
			got, err := b.CertifyVuln(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVuln, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestCertifyVulns(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Pkgs         []*model.IDorPkgInput
		Vulns        []*model.IDorVulnerabilityInput
		CertifyVulns []*model.ScanMetadataInput
	}
	tests := []struct {
		InPkg        []*model.PkgInputSpec
		Name         string
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		ExpVuln      []*model.CertifyVuln
		Query        *model.CertifyVulnSpec
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.C1}, {VulnerabilityInput: testdata.C2}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Collector: ptrfrom.String("test collector"),
			},
			ExpVuln: []*model.CertifyVuln{
				{
					ID:      "1",
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					Metadata: vmd1,
				},
				{
					ID:      "10",
					Package: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C2out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify NoVuln",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.NoVulnInput},
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.NoVulnInput}, {VulnerabilityInput: testdata.NoVulnInput}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("noVuln"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify OSV",
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			InPkg:  []*model.PkgInputSpec{testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("osv"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Certify GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.PkgInputSpec{testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.G1}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("ghsa"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on GHSA",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.G1}, {VulnerabilityInput: testdata.G2}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &testdata.G1.VulnerabilityID,
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query on Package",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
			InPkg:  []*model.PkgInputSpec{testdata.P3, testdata.P4},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P3}, {PackageInput: testdata.P4}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.G1}, {VulnerabilityInput: testdata.G2}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Package: &model.PkgSpec{
					Name:    ptrfrom.String(testdata.P3.Name),
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P3out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
			},
		},
		{
			Name:   "Query none",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1, testdata.G2},
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.G1}, {VulnerabilityInput: testdata.G2}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVuln: nil,
		},
		{
			Name:   "Query No Vuln",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.NoVulnInput},
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Pkgs:  []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.NoVulnInput}, {VulnerabilityInput: testdata.NoVulnInput}},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    testdata.T1,
						},
					},
				},
			},
			Query: &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type: ptrfrom.String("noVuln"),
				},
			},
			ExpVuln: []*model.CertifyVuln{
				{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
				{
					Package: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "novuln",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.NoVulnOut},
					},
					Metadata: vmd1,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, v := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: v}); err != nil {
					t.Fatalf("Could not ingest vulnerabilities: %a", err)
				}
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest packages: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestCertifyVulns(ctx, o.Pkgs, o.Vulns, o.CertifyVulns)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}

			}
			got, err := b.CertifyVuln(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVuln, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
