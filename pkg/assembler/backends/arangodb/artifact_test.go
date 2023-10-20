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

//go:build integration

package arangodb

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func getArangoConfig() *ArangoConfig {
	return &ArangoConfig{
		User:     "root",
		Pass:     "test123",
		DBAddr:   "http://localhost:8529",
		TestData: false,
	}
}

func lessArtifact(a, b *model.Artifact) int {
	return strings.Compare(a.Digest, b.Digest)
}

func Test_IngestArtifacts(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	c, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	tests := []struct {
		name           string
		artifactInputs []*model.ArtifactInputSpec
		want           []*model.Artifact
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
		want: []*model.Artifact{{
			Algorithm: "sha512",
			Digest:    "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7",
		}, {
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		}, {
			Algorithm: "sha1",
			Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
		}},
		wantErr: false,
	}}

	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.IngestArtifacts(ctx, tt.artifactInputs)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessArtifact)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_IngestArtifact(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	c, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	tests := []struct {
		name          string
		artifactInput *model.ArtifactInputSpec
		want          *model.Artifact
		wantErr       bool
	}{{
		name: "sha256",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
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
			got, err := c.IngestArtifact(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_Artifacts(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	c, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
			ingestedArt, err := c.IngestArtifact(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.artifactSpec.ID = &ingestedArt.ID
			}
			got, err := c.Artifacts(ctx, tt.artifactSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Artifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.SortFunc(got, lessArtifact)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildArtifactResponseByID(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
			ingestedArt, err := b.IngestArtifact(ctx, tt.artifactInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.artifactSpec.ID = &ingestedArt.ID
			}
			got, err := b.(*arangoClient).buildArtifactResponseByID(ctx, ingestedArt.ID, tt.artifactSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("arangoClient.buildPackageResponseFromID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
