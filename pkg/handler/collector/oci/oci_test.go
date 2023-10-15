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

package oci

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/pkg/errors"
)

func Test_ociCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		ociValues []string
		poll      bool
		interval  time.Duration
	}

	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		errMessage error
		want       []*processor.Document
	}{{
		name: "multi-platform sbom",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/go-multi-test:7ddfb3e035b42cd70649cc33393fe32c",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIGoSPDXMulti1),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/go-multi-test:sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10.sbom",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIGoSPDXMulti2),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/go-multi-test:sha256-1bc7e53e25de5c00ecaeca1473ab56bfaf4e39cea747edcf7db467389a287931.sbom",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIGoSPDXMulti3),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/go-multi-test:sha256-534035553d1270a98dab3512fde0987e7709ec6b878c8fd60fdaf0d8e1611979.sbom",
				},
			},
		},
		wantErr: false,
	}, {
		name: "get attestation and sbom",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/guac-test-image:e26f2e514682726fa808a849c863e5feca71e0c3",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIDsseAttExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.att",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCISPDXExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.sbom",
				},
			},
		},
		wantErr: false,
	}, {
		name: "get OCI referrers",
		fields: fields{
			ociValues: []string{
				"mcr.microsoft.com/oss/kubernetes/kubectl:v1.28.1",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxAMD64ITE6),
				Type:   processor.DocumentITE6SLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:395fbca091afd8cd7406a3b9815c2c4054bd06331f7a2a6b2e48798a5365d4f6",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxAMD64SPDX),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:dc365ff2a58436089f1dfcc2dcbf4699a3b9bbb596f5485b70cc75cbd309f020",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxAMD64SPDX1),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:8e20922c8c2c4172879ff18b85e9de011e7bc5d8a93aab8244b8834e6e471e29",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARMV7ITE6),
				Type:   processor.DocumentITE6SLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:988bec89fa63b1eed4c804e4d8acb7073a97ede89c86768193bca408faad3ed6",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARMV7SPDX),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:264ad11a504bc570eadd7e75c3eeb6432638ecb65ab5203a5b464218dba5b63e",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARM64ITE6),
				Type:   processor.DocumentITE6SLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:884e5fd916210a1f2fe371fe7e35812e7770787e292134aba104ed1b10d721e9",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARM64SPDX),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:3c48cc52d341cc6a57fcf25225b1d669fbdd32d8942fe669495e6f88de948597",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARM64SPDX1),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:ff231891d6af8af7c5e90b3647a262bd4a8013c74b99dae4a171ccc5480e60c2",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlWindowsAMD64ITE6),
				Type:   processor.DocumentITE6SLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:61715e8b3d8577fc8fcc54335d4f726803f806475239899498a96170d062b6ea",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlWindowsAMD64ITE6),
				Type:   processor.DocumentITE6SLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:1b7421f29020b2ff35190e26da222e379c14b457fe23a83be7c2ed44a57c490c",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlWindowsAMD64ITE6),
				Type:   processor.DocumentITE6SLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:30019e253ab74eb3e38abae7b8997e8e60c420169044ca9bfaf9665f54ad18bc",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARM64SPDX),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:8035089a59a6f8577255f494c1ced250e1206667d8462869fc0deeca98d79427",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxARMV7SPDX),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:78efdf2e0abe78a6964b8b5cbcdbfe4496f4564b227992806edd1cac57b68db2",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIKubectlLinuxAMD64SPDX),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "mcr.microsoft.com/oss/kubernetes/kubectl@sha256:64f5e3b86c83acef2fb79e359a942bd2290e30773269f532856421db4e75cc30",
				},
			},
		}}, {
		name: "tag not specified not polling",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/guac-test-image",
			},
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIDsseAttExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.att",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCISPDXExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ghcr.io/guacsec/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.sbom",
				},
			},
		},
		wantErr: false,
	}, {
		name: "tag empty string",
		fields: fields{
			ociValues: []string{
				"ghcr.io/guacsec/guac-test-image:",
			},
			poll:     false,
			interval: 0,
		},
		errMessage: errors.New("image tag not specified to fetch"),
		wantErr:    true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewOCICollector(ctx, toDataSource(tt.fields.ociValues), tt.fields.poll, tt.fields.interval)

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			if err := collector.RegisterDocumentCollector(g, OCICollector); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			var collectedDocs []*processor.Document
			em := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}
			eh := func(err error) bool {
				if err != nil {
					if !tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
					} else if !strings.Contains(err.Error(), tt.errMessage.Error()) {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.errMessage)
					}
				}
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error handler error: %v", err)
			}

			for i := range tt.want {
				collectedDoc := findDocumentBySource(collectedDocs, tt.want[i].SourceInformation.Source)
				if collectedDoc == nil {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", nil, tt.want[i])
				}
				result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDoc), dochelper.DocNode(tt.want[i]))
				if !result {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
				}
			}

			if len(collectedDocs) != len(tt.want) {
				t.Fatalf("g.RetrieveArtifacts() = %v, want %v", len(collectedDocs), len(tt.want))
			}

			if g.Type() != OCICollector {
				t.Errorf("g.Type() = %s, want %s", g.Type(), OCICollector)
			}

		})
	}
}

// findDocumentBySource returns the document with the given source
func findDocumentBySource(docs []*processor.Document, source string) *processor.Document {
	for _, d := range docs {
		if d.SourceInformation.Source == source {
			return d
		}
	}
	return nil
}

func toDataSource(ociValues []string) datasource.CollectSource {
	values := []datasource.Source{}
	for _, v := range ociValues {
		values = append(values, datasource.Source{Value: v})
	}

	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: values,
	})
	if err != nil {
		panic(err)
	}
	return ds
}
