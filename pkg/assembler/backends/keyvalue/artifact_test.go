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

package keyvalue

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_artifactStruct_ID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{{
		name: "getID",
		id:   "643",
		want: "643",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &artStruct{
				ThisID: tt.id,
			}
			if got := b.ID(); got != tt.want {
				t.Errorf("builderStruct.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_artifactStruct_Neighbors(t *testing.T) {
	type fields struct {
		id          string
		algorithm   string
		digest      string
		hashEquals  []string
		occurrences []string
		hasSLSAs    []string
		vexLinks    []string
		badLinks    []string
		goodLinks   []string
	}
	tests := []struct {
		name         string
		fields       fields
		allowedEdges edgeMap
		want         []string
	}{{
		name: "hashEquals",
		fields: fields{
			hashEquals: []string{"343", "546"},
		},
		allowedEdges: edgeMap{model.EdgeArtifactHashEqual: true},
		want:         []string{"343", "546"},
	}, {
		name: "occurrences",
		fields: fields{
			occurrences: []string{"2324", "1234"},
		},
		allowedEdges: edgeMap{model.EdgeArtifactIsOccurrence: true},
		want:         []string{"2324", "1234"},
	}, {
		name: "hasSLSAs",
		fields: fields{
			hasSLSAs: []string{"445", "1232244"},
		},
		allowedEdges: edgeMap{model.EdgeArtifactHasSlsa: true},
		want:         []string{"445", "1232244"},
	}, {
		name: "vexLinks",
		fields: fields{
			vexLinks: []string{"987", "9876"},
		},
		allowedEdges: edgeMap{model.EdgeArtifactCertifyVexStatement: true},
		want:         []string{"987", "9876"},
	}, {
		name: "badLinks",
		fields: fields{
			badLinks: []string{"5322", "544"},
		},
		allowedEdges: edgeMap{model.EdgeArtifactCertifyBad: true},
		want:         []string{"5322", "544"},
	}, {
		name: "goodLinks",
		fields: fields{
			goodLinks: []string{"25468", "1458"},
		},
		allowedEdges: edgeMap{model.EdgeArtifactCertifyGood: true},
		want:         []string{"25468", "1458"},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &artStruct{
				ThisID:      tt.fields.id,
				Algorithm:   tt.fields.algorithm,
				Digest:      tt.fields.digest,
				HashEquals:  tt.fields.hashEquals,
				Occurrences: tt.fields.occurrences,
				HasSLSAs:    tt.fields.hasSLSAs,
				VexLinks:    tt.fields.vexLinks,
				BadLinks:    tt.fields.badLinks,
				GoodLinks:   tt.fields.goodLinks,
			}
			if got := a.Neighbors(tt.allowedEdges); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("builderStruct.Neighbors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_artifactStruct_BuildModelNode(t *testing.T) {
	type fields struct {
		id        string
		algorithm string
		digest    string
	}
	tests := []struct {
		name    string
		fields  fields
		want    model.Node
		wantErr bool
	}{{
		name: "sha256",
		fields: fields{
			id:        "43",
			algorithm: strings.ToLower("sha256"),
			digest:    strings.ToLower("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
		},
		want: &model.Artifact{
			ID:        "43",
			Algorithm: strings.ToLower("sha256"),
			Digest:    strings.ToLower("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
		},
		wantErr: false,
	}, {
		name: "sha1",
		fields: fields{
			id:        "53",
			algorithm: strings.ToLower("sha1"),
			digest:    strings.ToLower("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
		},
		want: &model.Artifact{
			ID:        "53",
			Algorithm: strings.ToLower("sha1"),
			Digest:    strings.ToLower("7a8f47318e4676dacb0142afa0b83029cd7befd9"),
		},
		wantErr: false,
	}, {
		name: "sha512",
		fields: fields{
			id:        "63",
			algorithm: strings.ToLower("sha512"),
			digest:    strings.ToLower("374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7"),
		},
		want: &model.Artifact{
			ID:        "63",
			Algorithm: strings.ToLower("sha512"),
			Digest:    strings.ToLower("374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7"),
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(context.Background(), nil)
			a := &artStruct{
				ThisID:    tt.fields.id,
				Algorithm: tt.fields.algorithm,
				Digest:    tt.fields.digest,
			}
			b := c.(*demoClient)
			got, err := a.BuildModelNode(context.Background(), b)
			if (err != nil) != tt.wantErr {
				t.Errorf("artStruct.BuildModelNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_IngestArtifacts(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		artifactInputs []*model.ArtifactInputSpec
		wantErr        bool
	}{{
		name: "sha256",
		artifactInputs: []*model.ArtifactInputSpec{{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		}, {
			Algorithm: "sha1",
			Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
		}, {
			Algorithm: "sha512",
			Digest:    "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7",
		}},
		wantErr: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(ctx, nil)
			_, err := c.IngestArtifactIDs(ctx, tt.artifactInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_demoClient_IngestArtifact(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		artifactInput *model.ArtifactInputSpec
		wantErr       bool
	}{{
		name: "sha256",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		wantErr: false,
	}, {
		name: "sha1",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha1",
			Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
		},
		wantErr: false,
	}, {
		name: "sha512",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha512",
			Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
		},
		wantErr: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(ctx, nil)

			_, err := c.IngestArtifactID(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_demoClient_Artifacts(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		artifactInput *model.ArtifactInputSpec
		artifactSpec  *model.ArtifactSpec
		idInFilter    bool
		want          []*model.Artifact
		wantErr       bool
	}{{
		name: "sha256",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		artifactSpec: &model.ArtifactSpec{
			Algorithm: ptrfrom.String("sha256"),
			Digest:    ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
		},
		want: []*model.Artifact{{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		}},
		wantErr: false,
	}, {
		name: "sha1",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha1",
			Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
		},
		artifactSpec: &model.ArtifactSpec{
			Algorithm: ptrfrom.String("sha1"),
			Digest:    ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
		},
		want: []*model.Artifact{{
			Algorithm: "sha1",
			Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
		}},
		wantErr: false,
	}, {
		name: "sha512",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha512",
			Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
		},
		artifactSpec: &model.ArtifactSpec{
			Algorithm: ptrfrom.String("sha512"),
			Digest:    ptrfrom.String("374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7"),
		},
		idInFilter: true,
		want: []*model.Artifact{{
			Algorithm: "sha512",
			Digest:    "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7",
		}},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(ctx, nil)
			ingestedArt, err := c.IngestArtifactID(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.artifactSpec.ID = &ingestedArt
			}
			got, err := c.Artifacts(ctx, tt.artifactSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Artifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_buildArtifactResponse(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		artifactInput *model.ArtifactInputSpec
		artifactSpec  *model.ArtifactSpec
		idInFilter    bool
		want          *model.Artifact
		wantErr       bool
	}{{
		name: "sha256",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		artifactSpec: &model.ArtifactSpec{
			Algorithm: ptrfrom.String("sha256"),
			Digest:    ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
		},
		want: &model.Artifact{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		wantErr: false,
	}, {
		name: "sha1",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha1",
			Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
		},
		artifactSpec: &model.ArtifactSpec{
			Algorithm: ptrfrom.String("sha1"),
			Digest:    ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
		},
		want: &model.Artifact{
			Algorithm: "sha1",
			Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
		},
		wantErr: false,
	}, {
		name: "sha512",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha512",
			Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
		},
		artifactSpec: &model.ArtifactSpec{
			Algorithm: ptrfrom.String("sha512"),
			Digest:    ptrfrom.String("374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7"),
		},
		idInFilter: true,
		want: &model.Artifact{
			Algorithm: "sha512",
			Digest:    "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7",
		},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(ctx, nil)
			art, err := c.IngestArtifactID(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.artifactSpec.ID = &art
			}
			b := c.(*demoClient)
			got, err := b.buildArtifactResponse(context.Background(), art, tt.artifactSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Artifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_demoClient_getArtifactIDFromInput(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		artifactInput *model.ArtifactInputSpec
		wantErr       bool
	}{{
		name: "sha256",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		wantErr: false,
	}, {
		name: "sha1",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha1",
			Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
		},
		wantErr: false,
	}, {
		name: "sha512",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha512",
			Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
		},
		wantErr: false,
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := getBackend(ctx, nil)
			art, err := c.IngestArtifactID(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			b := c.(*demoClient)
			got, err := b.artifactByInput(context.Background(), tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Artifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(art, got.ThisID, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
