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

package osv

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	text4ShellVulAttestation = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://in-toto.io/attestation/vuln/v0.1",
		"subject": [
		  {
			"name": "pkg:maven/org.apache.commons/commons-text@1.9",
			"digest": null
		  }
		],
		"predicate": {
		  "invocation": {
			"uri": "guac",
			"producer_id": "guecsec/guac"
		  },
		  "scanner": {
			"uri": "osv.dev",
			"version": "0.0.14",
			"db": {},
			"result": [
			  {
				"vulnerability_id": "GHSA-599f-7c49-w659"
			  }
			]
		  },
		  "metadata": {
			"scannedOn": "2022-11-21T16:29:03.332745-05:00"
		  }
		}
	}`

	rootVulAttestation = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://in-toto.io/attestation/vuln/v0.1",
		"subject": [
		  {
			"name": "pkg:oci/vul-image-latest?repository_url=grc.io",
			"digest": null
		  }
		],
		"predicate": {
		  "invocation": {
			"uri": "guac",
			"producer_id": "guecsec/guac"
		  },
		  "scanner": {
			"uri": "osv.dev",
			"version": "0.0.14",
			"db": {},
			"result": [
			  {
				"vulnerability_id": "GHSA-599f-7c49-w659"
			  },
			  {
				"vulnerability_id": "GHSA-599f-7c49-w659"
			  }
			]
		  },
		  "metadata": {
			"scannedOn": "2022-11-21T16:32:14.42045-05:00"
		  }
		}
	}`
	log4JVulAttestation = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://in-toto.io/attestation/vuln/v0.1",
		"subject": [
		  {
			"name": "pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1",
			"digest": null
		  }
		],
		"predicate": {
		  "invocation": {
			"uri": "guac",
			"producer_id": "guecsec/guac"
		  },
		  "scanner": {
			"uri": "osv.dev",
			"version": "0.0.14",
			"db": {},
			"result": [
			  {
				"vulnerability_id": "GHSA-599f-7c49-w659"
			  }
			]
		  },
		  "metadata": {
			"scannedOn": "2022-11-21T16:54:04.549583-05:00"
		  }
		}
	}`
)

func TestOSVCertifier_CertifyVulns(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	rootPackage := assembler.PackageNode{}
	rootPackage.Purl = "pkg:oci/vul-image-latest?repository_url=grc.io"
	log4JPackage := assembler.PackageNode{}
	log4JPackage.Purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1"
	text4ShelPackage := assembler.PackageNode{}
	text4ShelPackage.Purl = "pkg:maven/org.apache.commons/commons-text@1.9"

	lastlevel := &certifier.Component{
		CurPackage:  text4ShelPackage,
		DepPackages: []*certifier.Component{},
	}

	secondLevel := &certifier.Component{
		CurPackage:  log4JPackage,
		DepPackages: []*certifier.Component{lastlevel},
	}

	rootComponent := &certifier.Component{
		CurPackage:  rootPackage,
		DepPackages: []*certifier.Component{secondLevel},
	}
	tests := []struct {
		name          string
		rootComponent *certifier.Component
		want          []*processor.Document
		wantErr       bool
	}{{
		name:          "query and generate attestation for OSV",
		rootComponent: rootComponent,
		want: []*processor.Document{
			{
				Blob:   []byte(text4ShellVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(log4JVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(rootVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OSVCertifier{}
			collectedDocs := []*processor.Document{}
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- o.CertifyVulns(ctx, tt.rootComponent, docChan)
			}()
			numCollectors := 1
			collectorsDone := 0
			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err := <-errChan:
					if (err != nil) != tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					collectorsDone += 1
				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				d := <-docChan
				collectedDocs = append(collectedDocs, d)
			}
			if !reflect.DeepEqual(collectedDocs, tt.want) {
				t.Errorf("g.RetrieveArtifacts() = %v, want %v", collectedDocs, tt.want)
			}
		})
	}
}
