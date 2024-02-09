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
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO move src cmp to src_test.go

func cmpSrcName(a, b *model.SourceName) int {
	if d := strings.Compare(a.Name, b.Name); d != 0 {
		return d
	}
	if a.Tag != nil && b.Tag == nil {
		return 1
	}
	if b.Tag != nil && a.Tag == nil {
		return -1
	}
	if a.Tag != nil && b.Tag != nil {
		return strings.Compare(*a.Tag, *b.Tag)
	}
	if a.Commit != nil && b.Commit == nil {
		return 1
	}
	if b.Commit != nil && a.Commit == nil {
		return -1
	}
	if a.Commit != nil && b.Commit != nil {
		return strings.Compare(*a.Commit, *b.Commit)
	}
	// names were equal, and neither has tag nor commit
	return 0
}

func cmpSrcNS(a, b *model.SourceNamespace) int {
	if d := strings.Compare(a.Namespace, b.Namespace); d != 0 {
		return d
	}
	slices.SortFunc(a.Names, cmpSrcName)
	slices.SortFunc(b.Names, cmpSrcName)
	return slices.CompareFunc(a.Names, b.Names, cmpSrcName)
}

func cmpSrc(a, b *model.Source) int {
	if d := strings.Compare(a.Type, b.Type); d != 0 {
		return d
	}
	slices.SortFunc(a.Namespaces, cmpSrcNS)
	slices.SortFunc(b.Namespaces, cmpSrcNS)
	return slices.CompareFunc(a.Namespaces, b.Namespaces, cmpSrcNS)
}

// TODO move pkg cmp to pkg_test.go

func cmpPkgQual(a, b *model.PackageQualifier) int {
	if d := strings.Compare(a.Key, b.Key); d != 0 {
		return d
	}
	return strings.Compare(a.Value, b.Value)
}

func cmpPkgVer(a, b *model.PackageVersion) int {
	if d := strings.Compare(a.Version, b.Version); d != 0 {
		return d
	}
	if d := strings.Compare(a.Subpath, b.Subpath); d != 0 {
		return d
	}
	slices.SortFunc(a.Qualifiers, cmpPkgQual)
	slices.SortFunc(b.Qualifiers, cmpPkgQual)
	return slices.CompareFunc(a.Qualifiers, b.Qualifiers, cmpPkgQual)
}

func cmpPkgName(a, b *model.PackageName) int {
	if d := strings.Compare(a.Name, b.Name); d != 0 {
		return d
	}
	slices.SortFunc(a.Versions, cmpPkgVer)
	slices.SortFunc(b.Versions, cmpPkgVer)
	return slices.CompareFunc(a.Versions, b.Versions, cmpPkgVer)
}

func cmpPkgNS(a, b *model.PackageNamespace) int {
	if d := strings.Compare(a.Namespace, b.Namespace); d != 0 {
		return d
	}
	slices.SortFunc(a.Names, cmpPkgName)
	slices.SortFunc(b.Names, cmpPkgName)
	return slices.CompareFunc(a.Names, b.Names, cmpPkgName)
}

func cmpPkg(a, b *model.Package) int {
	if d := strings.Compare(a.Type, b.Type); d != 0 {
		return d
	}
	slices.SortFunc(a.Namespaces, cmpPkgNS)
	slices.SortFunc(b.Namespaces, cmpPkgNS)
	return slices.CompareFunc(a.Namespaces, b.Namespaces, cmpPkgNS)
}

// TODO move artifact cmp to artifact_test.go

func cmpArt(a, b *model.Artifact) int {
	if d := strings.Compare(a.Algorithm, b.Algorithm); d != 0 {
		return d
	}
	return strings.Compare(a.Digest, b.Digest)
}

func cmpCB(a, b *model.CertifyBad) int {
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d
	}
	if d := a.KnownSince.Compare(b.KnownSince); d != 0 {
		return d
	}
	ap, oka := a.Subject.(*model.Package)
	bp, okb := b.Subject.(*model.Package)
	if oka && !okb {
		return 1
	}
	if okb && !oka {
		return -1
	}
	if oka && okb {
		return cmpPkg(ap, bp)
	}
	as, oka := a.Subject.(*model.Source)
	bs, okb := b.Subject.(*model.Source)
	if oka && !okb {
		return 1
	}
	if okb && !oka {
		return -1
	}
	if oka && okb {
		return cmpSrc(as, bs)
	}
	aa := a.Subject.(*model.Artifact)
	ba := b.Subject.(*model.Artifact)
	return cmpArt(aa, ba)
}

func TestCertifyBad(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CB    *model.CertifyBadInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		InSrc         []*model.SourceInputSpec
		InArt         []*model.ArtifactInputSpec
		Calls         []call
		Query         *model.CertifyBadSpec
		QueryID       bool
		QueryPkgID    bool
		QuerySourceID bool
		QueryArtID    bool
		ExpCB         []*model.CertifyBad
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on KnownSince",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification one",
						KnownSince:    curTime,
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification two",
						KnownSince:    timeAfterOneSecond,
					},
				},
			},
			Query: &model.CertifyBadSpec{
				KnownSince: ptrfrom.Time(timeAfterOneSecond),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification two",
					KnownSince:    timeAfterOneSecond,
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P4}},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
						Version:   ptrfrom.String("3.0.3"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P4outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package version ID",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P4}},
			InSrc: []*model.SourceInputSpec{},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryPkgID: true,
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}, &model.IDorSourceInput{SourceInput: testdata.S2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.IDorPkgInput{},
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			QuerySourceID: true,
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact ID",
			InSrc: []*model.SourceInputSpec{},
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryArtID: true,
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpCB: nil,
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}, &model.IDorSourceInput{SourceInput: testdata.S2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Type: ptrfrom.String("git"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query Packages",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}, &model.IDorPkgInput{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:    ptrfrom.String("pypi"),
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query ID",
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if pkgIDs, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				} else {
					if test.QueryPkgID {
						test.Query = &model.CertifyBadSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(pkgIDs.PackageVersionID),
								},
							},
						}
					}
				}
			}
			for _, s := range test.InSrc {
				if srcIDs, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				} else {
					if test.QuerySourceID {
						test.Query = &model.CertifyBadSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Source: &model.SourceSpec{
									ID: ptrfrom.String(srcIDs.SourceNameID),
								},
							},
						}
					}
				}
			}
			for _, a := range test.InArt {
				if artID, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					if test.QueryArtID {
						test.Query = &model.CertifyBadSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(artID),
								},
							},
						}
					}
				}
			}
			for _, o := range test.Calls {
				cbID, err := b.IngestCertifyBad(ctx, o.Sub, o.Match, *o.CB)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyBadSpec{
						ID: ptrfrom.String(cbID),
					}
				}
			}
			got, err := b.CertifyBad(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, cmpCB)
			slices.SortFunc(test.ExpCB, cmpCB)
			if diff := cmp.Diff(test.ExpCB, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestCertifyBads(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match *model.MatchFlags
		CB    []*model.CertifyBadInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.CertifyBadSpec
		ExpCB        []*model.CertifyBad
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}, &model.IDorPkgInput{PackageInput: testdata.P2}},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}, &model.IDorPkgInput{PackageInput: testdata.P2}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.P2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}, &model.IDorSourceInput{SourceInput: testdata.S2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S2, testdata.S2},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpCB: []*model.CertifyBad{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestCertifyBads(ctx, o.Sub, o.Match, o.CB)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.CertifyBad(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			slices.SortFunc(got, cmpCB)
			slices.SortFunc(test.ExpCB, cmpCB)
			if diff := cmp.Diff(test.ExpCB, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
