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

package spdx

import (
	_ "embed"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed testdata/spdx_alpine.json
	spdxExampleAlpine []byte

	baselayoutPack = assembler.PackageNode{
		Name:   "alpine-baselayout",
		Digest: "",
		Purl:   "pkg:alpine/alpine-baselayout@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2",
		CPEs: []string{
			"cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r22:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.2.0-r22:*:*:*:*:*:*:*",
		},
	}

	keysPack = assembler.PackageNode{
		Name:   "alpine-keys",
		Digest: "",
		Purl:   "pkg:alpine/alpine-keys@2.4-r1?arch=x86_64&upstream=alpine-keys&distro=alpine-3.16.2",
		CPEs: []string{
			"cpe:2.3:a:alpine-keys:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-keys:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
		},
	}

	baselayoutdataPack = assembler.PackageNode{
		Name:   "alpine-baselayout-data",
		Digest: "",
		Purl:   "pkg:alpine/alpine-baselayout-data@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2",
		CPEs: []string{
			"cpe:2.3:a:alpine-baselayout-data:alpine-baselayout-data:3.2.0-r22:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-baselayout-data:alpine_baselayout_data:3.2.0-r22:*:*:*:*:*:*:*",
		},
	}

	worldFile = assembler.ArtifactNode{
		Name:   "/etc/apk/world",
		Digest: "SHA256:713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201",
	}
	rootFile = assembler.ArtifactNode{
		Name:   "/etc/crontabs/root",
		Digest: "SHA256:575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
	}
	triggersFile = assembler.ArtifactNode{
		Name:   "/lib/apk/db/triggers",
		Digest: "SHA256:5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4",
	}
	rsaPubFile = assembler.ArtifactNode{
		Name:   "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
		Digest: "SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
	}

	spdxNodes = []assembler.GuacNode{baselayoutPack, baselayoutdataPack, rsaPubFile, keysPack, worldFile, rootFile, triggersFile}
	spdxEdges = []assembler.GuacEdge{
		assembler.DependsOnEdge{
			PackageNode:        baselayoutPack,
			ArtifactDependency: rootFile,
		},
		assembler.DependsOnEdge{
			PackageNode:        keysPack,
			ArtifactDependency: rsaPubFile,
		},
	}
)

func Test_spdxParser(t *testing.T) {
	tests := []struct {
		name    string
		doc     *processor.Document
		wantErr bool
	}{{
		name: "valid big SPDX document",
		doc: &processor.Document{
			Blob:              spdxExampleAlpine,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSpdxParser()
			if err := s.Parse(tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("spdxParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := s.CreateNodes(); !reflect.DeepEqual(nodes, spdxNodes) {
				t.Errorf("spdxParser.CreateNodes() = %v, want %v", nodes, spdxNodes)
			}
			if edges := s.CreateEdges(nil); !reflect.DeepEqual(edges, spdxEdges) {
				t.Errorf("spdxParser.CreateEdges() = %v, want %v", edges, spdxEdges)
			}
			if docType := s.GetDocType(); !reflect.DeepEqual(docType, processor.DocumentSPDX) {
				t.Errorf("spdxParser.GetDocType() = %v, want %v", docType, processor.DocumentSPDX)
			}
		})
	}
}
