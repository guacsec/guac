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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type testDependency struct {
	pkg       *model.PkgInputSpec
	depPkg    *model.PkgInputSpec
	matchType model.MatchFlags
	isDep     *model.IsDependencyInputSpec
}

type testOccurrence struct {
	Subj  *model.PackageOrSourceInput
	Art   *model.ArtifactInputSpec
	isOcc *model.IsOccurrenceInputSpec
}

// Test resources

var includedPackage1QualifierKey = "p1_key"
var includedPackage1QualifierValue = "p1_value"

var includedPackage1 = &model.PkgInputSpec{
	Type:      "p1_type",
	Namespace: ptrfrom.String("p1_namespace"),
	Name:      "p1_name",
	Version:   ptrfrom.String("v1.0.0-p1version"),
	Qualifiers: []*model.PackageQualifierInputSpec{{
		Key:   includedPackage1QualifierKey,
		Value: includedPackage1QualifierValue,
	}},
	Subpath: ptrfrom.String("p1_subpath"),
}

var includedPackage2QualifierKey = "p2_key"
var includedPackage2QualifierValue = "p2_value"

var includedPackage2 = &model.PkgInputSpec{
	Type:      "p2_type",
	Namespace: ptrfrom.String("p2_namespace"),
	Name:      "p2_name",
	Version:   ptrfrom.String("v1.0.0-p2version"),
	Qualifiers: []*model.PackageQualifierInputSpec{{
		Key:   includedPackage2QualifierKey,
		Value: includedPackage2QualifierValue,
	}},
	Subpath: ptrfrom.String("p2_subpath"),
}

var includedPackage3 = &model.PkgInputSpec{
	Type:       "p3_type",
	Namespace:  ptrfrom.String("p3_namespace"),
	Name:       "p3_name",
	Version:    ptrfrom.String("v1.0.0-p3version"),
	Qualifiers: []*model.PackageQualifierInputSpec{},
	Subpath:    ptrfrom.String("p3_subpath"),
}

var includedPackages = []*model.PkgInputSpec{includedPackage1, includedPackage2, includedPackage3}

var includedArtifact1 = &model.ArtifactInputSpec{
	Algorithm: "a1_algorithm",
	Digest:    "a1_digest",
}

var includedArtifact2 = &model.ArtifactInputSpec{
	Algorithm: "a2_algorithm",
	Digest:    "a2_digest",
}

var includedArtifacts = []*model.ArtifactInputSpec{includedArtifact1, includedArtifact2}

var includedPackageArtifacts = &model.PackageOrArtifactInputs{
	Packages:  includedPackages,
	Artifacts: includedArtifacts,
}

var includedDependency1 = &model.IsDependencyInputSpec{
	VersionRange:   "dep1_range",
	DependencyType: model.DependencyTypeDirect,
	Justification:  "dep1_justification",
	Origin:         "dep1_origin",
	Collector:      "dep1_collector",
}

var includedDependency2 = &model.IsDependencyInputSpec{
	VersionRange:   "dep2_range",
	DependencyType: model.DependencyTypeIndirect,
	Justification:  "dep2_justification",
	Origin:         "dep2_origin",
	Collector:      "dep2_collector",
}

var includedTestDependency1 = &testDependency{
	pkg:       includedPackage1,
	depPkg:    includedPackage2,
	matchType: mSpecific,
	isDep:     includedDependency1,
}

var includedTestDependency2 = &testDependency{
	pkg:       includedPackage1,
	depPkg:    includedPackage3,
	matchType: mSpecific,
	isDep:     includedDependency2,
}

var includedTestDependencies = []testDependency{*includedTestDependency1, *includedTestDependency2}

var includedSource = &model.SourceInputSpec{
	Type:      "src_type",
	Namespace: "src_namespace",
	Name:      "src_name",
	Tag:       ptrfrom.String("src_tag"),
	Commit:    ptrfrom.String("src_commit"),
}

var includedSources = []*model.SourceInputSpec{includedSource}

var includedOccurrence = &model.IsOccurrenceInputSpec{
	Justification: "occ_justification",
	Origin:        "occ_origin",
	Collector:     "occ_collector",
}

var includedTestOccurrences = []testOccurrence{{
	Subj:  &model.PackageOrSourceInput{Package: includedPackage1},
	Art:   includedArtifact1,
	isOcc: includedOccurrence,
}, {
	Subj:  &model.PackageOrSourceInput{Source: includedSource},
	Art:   includedArtifact1,
	isOcc: includedOccurrence,
}}

// var includedHasSBOM = &model.HasSBOMInputSpec{
// 	URI:              "sbom_URI",
// 	Algorithm:        "sbom_algorithm",
// 	Digest:           "sbom_digest",
// 	DownloadLocation: "sbom_download_location",
// 	Origin:           "sbom_origin",
// 	Collector:        "sbom_collector",
// }

var includedTestExpectedPackage1 = &model.Package{
	Type: "p1_type",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "p1_namespace",
		Names: []*model.PackageName{{
			Name: "p1_name",
			Versions: []*model.PackageVersion{{
				Version: "v1.0.0-p1version",
				Qualifiers: []*model.PackageQualifier{{
					Key:   includedPackage1QualifierKey,
					Value: includedPackage1QualifierValue,
				}},
				Subpath: "p1_subpath",
			}},
		}},
	}},
}

var includedTestExpectedPackage2 = &model.Package{
	Type: "p2_type",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "p2_namespace",
		Names: []*model.PackageName{{
			Name: "p2_name",
			Versions: []*model.PackageVersion{{
				Version: "v1.0.0-p2version",
				Qualifiers: []*model.PackageQualifier{{
					Key:   includedPackage2QualifierKey,
					Value: includedPackage2QualifierValue,
				}},
				Subpath: "p2_subpath",
			}},
		}},
	}},
}

var includedTestExpectedPackage3 = &model.Package{
	Type: "p3_type",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "p3_namespace",
		Names: []*model.PackageName{{
			Name: "p3_name",
			Versions: []*model.PackageVersion{{
				Version:    "v1.0.0-p3version",
				Qualifiers: []*model.PackageQualifier{},
				Subpath:    "p3_subpath",
			}},
		}},
	}},
}

var includedTestExpectedArtifact1 = &model.Artifact{
	Algorithm: "a1_algorithm",
	Digest:    "a1_digest",
}

var includedTestExpectedArtifact2 = &model.Artifact{
	Algorithm: "a2_algorithm",
	Digest:    "a2_digest",
}

var includedTestExpectedSource = &model.Source{
	Type: "src_type",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "src_namespace",
		Names: []*model.SourceName{{
			Name:   "src_name",
			Tag:    ptrfrom.String("src_tag"),
			Commit: ptrfrom.String("src_commit"),
		}},
	}},
}

// var includedTestExpectedSBOM = &model.HasSbom{
// 	Subject:          includedTestExpectedPackage1,
// 	URI:              "sbom_URI",
// 	Algorithm:        "sbom_algorithm",
// 	Digest:           "sbom_digest",
// 	DownloadLocation: "sbom_download_location",
// 	Origin:           "sbom_origin",
// 	Collector:        "sbom_collector",
// 	IncludedSoftware: []model.PackageOrArtifact{
// 		includedTestExpectedPackage1,
// 		includedTestExpectedPackage2,
// 		includedTestExpectedPackage3,
// 		includedTestExpectedArtifact1,
// 		includedTestExpectedArtifact2,
// 	},
// 	IncludedDependencies: []*model.IsDependency{{
// 		Package:           includedTestExpectedPackage1,
// 		DependencyPackage: includedTestExpectedPackage2,
// 		VersionRange:      "dep1_range",
// 		DependencyType:    model.DependencyTypeDirect,
// 		Justification:     "dep1_justification",
// 		Origin:            "dep1_origin",
// 		Collector:         "dep1_collector",
// 	}, {
// 		Package:           includedTestExpectedPackage1,
// 		DependencyPackage: includedTestExpectedPackage3,
// 		VersionRange:      "dep2_range",
// 		DependencyType:    model.DependencyTypeIndirect,
// 		Justification:     "dep2_justification",
// 		Origin:            "dep2_origin",
// 		Collector:         "dep2_collector",
// 	}},
// 	IncludedOccurrences: []*model.IsOccurrence{{
// 		Subject:       includedTestExpectedPackage1,
// 		Artifact:      includedTestExpectedArtifact1,
// 		Justification: "occ_justification",
// 		Origin:        "occ_origin",
// 		Collector:     "occ_collector",
// 	}, {
// 		Subject:       includedTestExpectedSource,
// 		Artifact:      includedTestExpectedArtifact1,
// 		Justification: "occ_justification",
// 		Origin:        "occ_origin",
// 		Collector:     "occ_collector",
// 	}},
// }

// End of Test resources

// func TestHasSBOM(t *testing.T) {
// 	ctx := context.Background()
// 	arangoArgs := getArangoConfig()
// 	err := DeleteDatabase(ctx, arangoArgs)
// 	if err != nil {
// 		t.Fatalf("error deleting arango database: %v", err)
// 	}
// 	b, err := getBackend(ctx, arangoArgs)
// 	if err != nil {
// 		t.Fatalf("error creating arango backend: %v", err)
// 	}
// 	curTime := time.Now()
// 	timeAfterOneSecond := curTime.Add(time.Second)
// 	type call struct {
// 		Sub model.PackageOrArtifactInput
// 		HS  *model.HasSBOMInputSpec
// 		Inc *model.HasSBOMIncludesInputSpec
// 	}
// 	tests := []struct {
// 		Name                     string
// 		InPkg                    []*model.PkgInputSpec
// 		InArt                    []*model.ArtifactInputSpec
// 		PkgArt                   *model.PackageOrArtifactInputs
// 		InSrc                    []*model.SourceInputSpec
// 		IsDeps                   []testDependency
// 		IsOccs                   []testOccurrence
// 		Calls                    []call
// 		Query                    *model.HasSBOMSpec
// 		QueryID                  bool
// 		QueryPkgID               bool
// 		QueryArtID               bool
// 		QueryIncludePkgID        bool
// 		QueryIncludeArtID        bool
// 		QueryIncludeDepID        bool
// 		QueryIncludeOccurID      bool
// 		QueryIncludeDepMainPkgID bool
// 		QueryIncludeDepPkgID     bool
// 		QueryIncludeOccurPkgID   bool
// 		QueryIncludeOccurArtID   bool
// 		QueryIncludeOccurSrcID   bool
// 		ExpHS                    []*model.HasSbom
// 		ExpIngestErr             bool
// 		ExpQueryErr              bool
// 	}{
// 		{
// 			Name:   "Includes - include without filters",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI: ptrfrom.String("test uri"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest same twice",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI: ptrfrom.String("test uri"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on URI",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri one",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI: ptrfrom.String("test uri one"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					URI:              "test uri one",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on URI and KnownSince",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI:        "test uri one",
// 						KnownSince: curTime,
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI:        "test uri two",
// 						KnownSince: timeAfterOneSecond,
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI:        ptrfrom.String("test uri one"),
// 				KnownSince: ptrfrom.Time(curTime),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:    testdata.P1out,
// 					URI:        "test uri one",
// 					KnownSince: curTime,
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Package",
// 			InPkg: []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages:  []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 				Artifacts: []*model.ArtifactInputSpec{testdata.A1},
// 			},
// 			IsDeps: []testDependency{{
// 				pkg:       testdata.P2,
// 				depPkg:    testdata.P4,
// 				matchType: mSpecific,
// 				isDep: &model.IsDependencyInputSpec{
// 					Justification: "test justification",
// 				},
// 			}},
// 			IsOccs: []testOccurrence{{
// 				Subj:  &model.PackageOrSourceInput{Package: testdata.P4},
// 				Art:   testdata.A1,
// 				isOcc: &model.IsOccurrenceInputSpec{Justification: "test justification"},
// 			}},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P4,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Package: &model.PkgSpec{
// 						Version: ptrfrom.String("2.11.1"),
// 					},
// 				},
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P2out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.P4out, testdata.A1out},
// 					IncludedDependencies: []*model.IsDependency{{
// 						Package:           testdata.P2out,
// 						DependencyPackage: testdata.P4out,
// 						Justification:     "test justification",
// 					}},
// 					IncludedOccurrences: []*model.IsOccurrence{{
// 						Subject:       testdata.P4out,
// 						Artifact:      testdata.A1out,
// 						Justification: "test justification",
// 					}},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Package ID",
// 			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			QueryPkgID: true,
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject: testdata.P2out,
// 					URI:     "test uri",
// 				},
// 				{
// 					Subject:          testdata.P2out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.P4out, testdata.A1out},
// 					IncludedDependencies: []*model.IsDependency{{
// 						Package:           testdata.P2out,
// 						DependencyPackage: testdata.P4out,
// 						Justification:     "test justification",
// 					}},
// 					IncludedOccurrences: []*model.IsOccurrence{{
// 						Subject:       testdata.P4out,
// 						Artifact:      testdata.A1out,
// 						Justification: "test justification",
// 					}},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Artifact",
// 			InPkg: []*model.PkgInputSpec{testdata.P2},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages:  []*model.PkgInputSpec{testdata.P2},
// 				Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Artifact: &model.ArtifactSpec{
// 						Algorithm: ptrfrom.String("sha1"),
// 					},
// 				},
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.A2out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.A1out, testdata.A2out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Artifact ID",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			QueryArtID: true,
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject: testdata.A2out,
// 					URI:     "test uri",
// 				},
// 				{
// 					Subject:          testdata.A2out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.A1out, testdata.A2out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Algorithm",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						Algorithm: "QWERasdf",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						Algorithm: "QWERasdf two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				Algorithm: ptrfrom.String("QWERASDF"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					Algorithm:        "qwerasdf",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Digest",
// 			InPkg: []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages:  []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 				Artifacts: []*model.ArtifactInputSpec{testdata.A1},
// 			},
// 			IsDeps: []testDependency{{
// 				pkg:       testdata.P2,
// 				depPkg:    testdata.P4,
// 				matchType: mSpecific,
// 				isDep: &model.IsDependencyInputSpec{
// 					Justification: "test justification",
// 				},
// 			}},
// 			IsOccs: []testOccurrence{{
// 				Subj:  &model.PackageOrSourceInput{Package: testdata.P4},
// 				Art:   testdata.A1,
// 				isOcc: &model.IsOccurrenceInputSpec{Justification: "test justification"},
// 			}},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						Digest: "QWERasdf",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						Digest: "QWERasdf two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				Digest: ptrfrom.String("QWERASDF"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P2out,
// 					Digest:           "qwerasdf",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.P4out, testdata.A1out},
// 					IncludedDependencies: []*model.IsDependency{{
// 						Package:           testdata.P2out,
// 						DependencyPackage: testdata.P4out,
// 						Justification:     "test justification",
// 					}},
// 					IncludedOccurrences: []*model.IsOccurrence{{
// 						Subject:       testdata.P4out,
// 						Artifact:      testdata.A1out,
// 						Justification: "test justification",
// 					}},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on DownloadLocation",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location one",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				DownloadLocation: ptrfrom.String("location two"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					DownloadLocation: "location two",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query none",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location one",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				DownloadLocation: ptrfrom.String("location three"),
// 			},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:  "Query multiple",
// 			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location one",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location two",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P2,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				DownloadLocation: ptrfrom.String("location two"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					DownloadLocation: "location two",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 				{
// 					Subject:          testdata.P1out,
// 					DownloadLocation: "location two",
// 				},
// 				{
// 					Subject:          testdata.P2out,
// 					DownloadLocation: "location two",
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on ID",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location one",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location two",
// 					},
// 				},
// 			},
// 			QueryID: true,
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					DownloadLocation: "location two",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query bad ID",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location one",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						DownloadLocation: "location two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				ID: ptrfrom.String("-7"),
// 			},
// 			ExpQueryErr: true,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Package ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludePkgID: true,
// 			ExpHS:             []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Package ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{ID: ptrfrom.String("10000")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Package Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Namespace: includedPackage2.Namespace}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Package Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Namespace: ptrfrom.String("invalid_namespace")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Package Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Name: &includedPackage2.Name}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Package Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Name: ptrfrom.String("invalid_name")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Package Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Version: includedPackage2.Version}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Package Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Version: ptrfrom.String("v1.0.0-invalid-version")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Package Qualifier",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage2QualifierKey, Value: ptrfrom.String(includedPackage2QualifierValue)}}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Package Qualifier Key",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: "invalid_qualifier_key", Value: ptrfrom.String(includedPackage2QualifierValue)}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Subject Package Qualifier Value",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage2QualifierKey, Value: ptrfrom.String("invalid_qualifier_value")}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Package Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Subpath: includedPackage2.Subpath}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Package Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{Subpath: ptrfrom.String("invalid_subpath")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Artifact ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeArtID: true,
// 			Query:             &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{ID: ptrfrom.String("13")}}}},
// 			ExpHS:             []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Artifact ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{ID: ptrfrom.String("10000")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Artifact Algorithm",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{Algorithm: &includedArtifact1.Algorithm}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Artifact Algorithm",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{Algorithm: ptrfrom.String("invalid_algorithm")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedSoftware - Valid Included Artifact Digest",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{Digest: &includedArtifact1.Digest}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedSoftware - Invalid Included Artifact Digest",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{Digest: ptrfrom.String("invalid_digest")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeDepID: true,
// 			Query:             &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{ID: ptrfrom.String("19")}}},
// 			ExpHS:             []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{ID: ptrfrom.String("10000")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeDepMainPkgID: true,
// 			ExpHS:                    []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{ID: ptrfrom.String("10000")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Namespace: includedPackage1.Namespace}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Namespace: ptrfrom.String("invalid_namespace")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Name: &includedPackage1.Name}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Name: ptrfrom.String("invalid_name")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Version: includedPackage1.Version}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Version: ptrfrom.String("v1.0.0-invalid-version")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Qualifier",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage1QualifierKey, Value: ptrfrom.String(includedPackage1QualifierValue)}}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package Qualifier Key",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: "invalid_qualifier_key", Value: ptrfrom.String(includedPackage1QualifierValue)}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Subject Package Qualifier Value",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage1QualifierKey, Value: ptrfrom.String("invalid_qualifier_value")}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Subpath: includedPackage1.Subpath}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Subpath: ptrfrom.String("invalid_subpath")}}}},
// 			ExpHS: nil,
// 		},

// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyPackage ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeDepPkgID: true,
// 			ExpHS:                []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyPackage ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{ID: ptrfrom.String("10000")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyPackage Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Namespace: includedPackage2.Namespace}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyPackage Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Namespace: ptrfrom.String("invalid_namespace")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyPackage Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Name: &includedPackage2.Name}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyPackage Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Name: ptrfrom.String("invalid_name")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyPackage Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Version: includedPackage2.Version}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyPackage Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Version: ptrfrom.String("v1.0.0-invalid-version")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyPackage Qualifier",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage2QualifierKey, Value: ptrfrom.String(includedPackage2QualifierValue)}}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyPackage Qualifier Key",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: "invalid_qualifier_key", Value: ptrfrom.String(includedPackage2QualifierValue)}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Subject DependencyPackage Qualifier Value",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage2QualifierKey, Value: ptrfrom.String("invalid_qualifier_value")}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyPackage Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Subpath: includedPackage2.Subpath}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyPackage Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{Subpath: ptrfrom.String("invalid_subpath")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package ID and DependencyPackage ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeDepMainPkgID: true,
// 			QueryIncludeDepPkgID:     true,
// 			ExpHS:                    []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package ID and Invalid DependencyPackage ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{ID: ptrfrom.String("4")}, DependencyPackage: &model.PkgSpec{ID: ptrfrom.String("10000")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package ID and Valid DependencyPackage ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{ID: ptrfrom.String("10000")}, DependencyPackage: &model.PkgSpec{ID: ptrfrom.String("8")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Name and DependencyPackage Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Name: &includedPackage1.Name}, DependencyPackage: &model.PkgSpec{Name: &includedPackage2.Name}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Package Name and Invalid DependencyPackage Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Name: &includedPackage1.Name}, DependencyPackage: &model.PkgSpec{Name: ptrfrom.String("invalid_name")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Package Name and Valid DependencyPackage Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{Name: ptrfrom.String("invalid_name")}, DependencyPackage: &model.PkgSpec{Name: &includedPackage2.Name}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included VersionRange",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{VersionRange: &includedDependency1.VersionRange}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included VersionRange",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{VersionRange: ptrfrom.String("invalid_range")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included DependencyType",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyType: &includedDependency1.DependencyType}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included DependencyType",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyType: (*model.DependencyType)(ptrfrom.String(string(model.DependencyTypeUnknown)))}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Justification",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Justification: &includedDependency1.Justification}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Justification",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Justification: ptrfrom.String("invalid_justification")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Origin",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Origin: &includedDependency1.Origin}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Origin",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Origin: ptrfrom.String("invalid_origin")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedDependencies - Valid Included Collector",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Collector: &includedDependency1.Collector}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedDependencies - Invalid Included Collector",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Collector: ptrfrom.String("invalid_collector")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeOccurID: true,
// 			Query:               &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{ID: ptrfrom.String("21")}}},
// 			ExpHS:               []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{ID: ptrfrom.String("10000")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Package ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeOccurPkgID: true,
// 			ExpHS:                  []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Package ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{ID: ptrfrom.String("10000")}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Package Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Namespace: includedPackage1.Namespace}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Package Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Namespace: ptrfrom.String("invalid_namespace")}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Package Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Name: ptrfrom.String("p1_name")}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Package Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Name: ptrfrom.String("invalid_name")}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Package Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Version: includedPackage1.Version}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Package Version",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Version: ptrfrom.String("v1.0.0-invalid-version")}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Package Qualifier",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage1QualifierKey, Value: ptrfrom.String(includedPackage1QualifierValue)}}}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Package Qualifier Key",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: "invalid_qualifier_key", Value: ptrfrom.String(includedPackage1QualifierValue)}}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Subject Package Qualifier Value",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Qualifiers: []*model.PackageQualifierSpec{{Key: includedPackage1QualifierKey, Value: ptrfrom.String("invalid_qualifier_value")}}}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Package Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Subpath: includedPackage1.Subpath}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Package Subpath",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{Subpath: ptrfrom.String("invalid_subpath")}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Source ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeOccurSrcID: true,
// 			ExpHS:                  []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Source ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{ID: ptrfrom.String("10000")}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Source",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			// TODO (knrc) - source currently needs to be an exact match, does this need to change?
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{
// 				Type:      &includedSource.Type,
// 				Namespace: &includedSource.Namespace,
// 				Name:      &includedSource.Name,
// 				Tag:       includedSource.Tag,
// 				Commit:    includedSource.Commit,
// 			}}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Source Type",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{
// 				Type:      ptrfrom.String("invalid_type"),
// 				Namespace: &includedSource.Namespace,
// 				Name:      &includedSource.Name,
// 				Tag:       includedSource.Tag,
// 				Commit:    includedSource.Commit,
// 			}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Source Namespace",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{
// 				Type:      &includedSource.Type,
// 				Namespace: ptrfrom.String("invalid_namespace"),
// 				Name:      &includedSource.Name,
// 				Tag:       includedSource.Tag,
// 				Commit:    includedSource.Commit,
// 			}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Source Name",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{
// 				Type:      &includedSource.Type,
// 				Namespace: &includedSource.Namespace,
// 				Name:      ptrfrom.String("invalid_name"),
// 				Tag:       includedSource.Tag,
// 				Commit:    includedSource.Commit,
// 			}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Source Tag",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{
// 				Type:      &includedSource.Type,
// 				Namespace: &includedSource.Namespace,
// 				Name:      &includedSource.Name,
// 				Tag:       ptrfrom.String("invalid_tag"),
// 				Commit:    includedSource.Commit,
// 			}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Source Commit",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{
// 				Type:      &includedSource.Type,
// 				Namespace: &includedSource.Namespace,
// 				Name:      &includedSource.Name,
// 				Tag:       includedSource.Tag,
// 				Commit:    ptrfrom.String("invalid_commit"),
// 			}}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Artifact ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			QueryIncludeOccurArtID: true,
// 			ExpHS:                  []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Artifact ID",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Artifact: &model.ArtifactSpec{ID: ptrfrom.String("10000")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Artifact Algorithm",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Artifact: &model.ArtifactSpec{Algorithm: &includedArtifact1.Algorithm}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Artifact Algorithm",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Artifact: &model.ArtifactSpec{Algorithm: ptrfrom.String("invalid_algorithm")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Artifact Digest",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Artifact: &model.ArtifactSpec{Digest: &includedArtifact1.Digest}}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Artifact Digest",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Artifact: &model.ArtifactSpec{Digest: ptrfrom.String("invalid_digest")}}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Justification",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Justification: &includedOccurrence.Justification}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Justification",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Justification: ptrfrom.String("invalid_justification")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Origin",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Origin: &includedOccurrence.Origin}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Origin",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Origin: ptrfrom.String("invalid_origin")}}},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Valid Included Collector",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Collector: &includedOccurrence.Collector}}},
// 			ExpHS: []*model.HasSbom{includedTestExpectedSBOM},
// 		},
// 		{
// 			Name:   "IncludedOccurrences - Invalid Included Collector",
// 			InPkg:  includedPackages,
// 			InArt:  includedArtifacts,
// 			InSrc:  includedSources,
// 			PkgArt: includedPackageArtifacts,
// 			IsDeps: includedTestDependencies,
// 			IsOccs: includedTestOccurrences,
// 			Calls: []call{{
// 				Sub: model.PackageOrArtifactInput{
// 					Package: includedPackage1,
// 				},
// 				HS: includedHasSBOM,
// 			}},
// 			Query: &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Collector: ptrfrom.String("invalid_collector")}}},
// 			ExpHS: nil,
// 		},
// 	}
// 	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
// 		return strings.Compare(".ID", p[len(p)-1].String()) == 0
// 	}, cmp.Ignore())
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			for _, p := range test.InPkg {
// 				if pkgIDs, err := b.IngestPackage(ctx, *p); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				} else {
// 					if test.QueryPkgID {
// 						test.Query = &model.HasSBOMSpec{
// 							Subject: &model.PackageOrArtifactSpec{
// 								Package: &model.PkgSpec{
// 									ID: ptrfrom.String(pkgIDs.PackageVersionID),
// 								},
// 							},
// 						}
// 					}
// 				}
// 			}
// 			for _, a := range test.InArt {
// 				if artID, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				} else {
// 					if test.QueryArtID {
// 						test.Query = &model.HasSBOMSpec{
// 							Subject: &model.PackageOrArtifactSpec{
// 								Artifact: &model.ArtifactSpec{
// 									ID: ptrfrom.String(artID),
// 								},
// 							},
// 						}
// 					}
// 				}
// 			}
// 			includes := model.HasSBOMIncludesInputSpec{}
// 			for _, s := range test.InSrc {
// 				if srcIDs, err := b.IngestSource(ctx, *s); err != nil {
// 					t.Fatalf("Could not ingest source: %v", err)
// 				} else {
// 					if test.QueryIncludeOccurSrcID {
// 						test.Query = &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Source: &model.SourceSpec{ID: ptrfrom.String(srcIDs.SourceNameID)}}}}}
// 					}
// 				}
// 			}
// 			if test.PkgArt != nil {
// 				if pkgs, err := b.IngestPackages(ctx, test.PkgArt.Packages); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				} else {
// 					if pkgs != nil {
// 						for _, pkg := range pkgs {
// 							includes.Software = append(includes.Software, pkg.PackageVersionID)
// 						}
// 						if test.QueryIncludePkgID {
// 							test.Query = &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Package: &model.PkgSpec{ID: ptrfrom.String(pkgs[0].PackageVersionID)}}}}
// 						}
// 						if test.QueryIncludeOccurPkgID {
// 							test.Query = &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Subject: &model.PackageOrSourceSpec{Package: &model.PkgSpec{ID: ptrfrom.String(pkgs[0].PackageVersionID)}}}}}
// 						}
// 						if test.QueryIncludeDepMainPkgID {
// 							test.Query = &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{ID: ptrfrom.String(pkgs[0].PackageVersionID)}}}}
// 						}
// 						if test.QueryIncludeDepPkgID {
// 							test.Query = &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{DependencyPackage: &model.PkgSpec{ID: ptrfrom.String(pkgs[len(pkgs)-1].PackageVersionID)}}}}
// 						}
// 						if test.QueryIncludeDepMainPkgID && test.QueryIncludeDepPkgID {
// 							test.Query = &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{Package: &model.PkgSpec{ID: ptrfrom.String(pkgs[0].PackageVersionID)}, DependencyPackage: &model.PkgSpec{ID: ptrfrom.String(pkgs[len(pkgs)-1].PackageVersionID)}}}}
// 						}
// 					}
// 				}
// 				if arts, err := b.IngestArtifacts(ctx, test.PkgArt.Artifacts); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				} else {
// 					if arts != nil {
// 						includes.Software = append(includes.Software, arts...)
// 						if test.QueryIncludeArtID {
// 							test.Query = &model.HasSBOMSpec{IncludedSoftware: []*model.PackageOrArtifactSpec{{Artifact: &model.ArtifactSpec{ID: ptrfrom.String(arts[0])}}}}
// 						}
// 						if test.QueryIncludeOccurArtID {
// 							test.Query = &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{Artifact: &model.ArtifactSpec{ID: ptrfrom.String(arts[0])}}}}
// 						}
// 					}
// 				}
// 			}

// 			for _, dep := range test.IsDeps {
// 				if isDep, err := b.IngestDependency(ctx, *dep.pkg, *dep.depPkg, dep.matchType, *dep.isDep); err != nil {
// 					t.Fatalf("Could not ingest dependency: %v", err)
// 				} else {
// 					includes.Dependencies = append(includes.Dependencies, isDep)
// 					if test.QueryIncludeDepID {
// 						test.Query = &model.HasSBOMSpec{IncludedDependencies: []*model.IsDependencySpec{{ID: ptrfrom.String(isDep)}}}
// 					}
// 				}
// 			}

// 			for _, occ := range test.IsOccs {
// 				if isOcc, err := b.IngestOccurrence(ctx, *occ.Subj, *occ.Art, *occ.isOcc); err != nil {
// 					t.Fatalf("Could not ingest occurrence: %v", err)
// 				} else {
// 					includes.Occurrences = append(includes.Occurrences, isOcc)
// 					if test.QueryIncludeOccurID {
// 						test.Query = &model.HasSBOMSpec{IncludedOccurrences: []*model.IsOccurrenceSpec{{ID: ptrfrom.String(isOcc)}}}
// 					}
// 				}
// 			}

// 			for _, o := range test.Calls {
// 				hsID, err := b.IngestHasSbom(ctx, o.Sub, *o.HS, includes)
// 				if (err != nil) != test.ExpIngestErr {
// 					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
// 				}
// 				if err != nil {
// 					return
// 				}
// 				if test.QueryID {
// 					test.Query = &model.HasSBOMSpec{
// 						ID: ptrfrom.String(hsID),
// 					}
// 				}
// 			}
// 			got, err := b.HasSBOM(ctx, test.Query)
// 			if (err != nil) != test.ExpQueryErr {
// 				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
// 			}
// 			if err != nil {
// 				return
// 			}
// 			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
// 				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

// func TestIngestHasSBOMs(t *testing.T) {
// 	ctx := context.Background()
// 	arangoArgs := getArangoConfig()
// 	err := DeleteDatabase(ctx, arangoArgs)
// 	if err != nil {
// 		t.Fatalf("error deleting arango database: %v", err)
// 	}
// 	b, err := getBackend(ctx, arangoArgs)
// 	if err != nil {
// 		t.Fatalf("error creating arango backend: %v", err)
// 	}
// 	type call struct {
// 		Sub model.PackageOrArtifactInputs
// 		HS  []*model.HasSBOMInputSpec
// 		Inc []*model.HasSBOMIncludesInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InArt        []*model.ArtifactInputSpec
// 		PkgArt       *model.PackageOrArtifactInputs
// 		IsDeps       []testDependency
// 		IsOccs       []testOccurrence
// 		Calls        []call
// 		Query        *model.HasSBOMSpec
// 		ExpHS        []*model.HasSbom
// 		ExpIngestErr bool
// 		ExpQueryErr  bool
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Packages: []*model.PkgInputSpec{testdata.P1},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI: ptrfrom.String("test uri"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest same twice",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri",
// 						},
// 						{
// 							URI: "test uri",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI: ptrfrom.String("test uri"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on URI",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages: []*model.PkgInputSpec{testdata.P1},
// 			},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri one",
// 						},
// 						{
// 							URI: "test uri two",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				URI: ptrfrom.String("test uri one"),
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P1out,
// 					URI:              "test uri one",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Package",
// 			InPkg: []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages:  []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 				Artifacts: []*model.ArtifactInputSpec{testdata.A1},
// 			},
// 			IsDeps: []testDependency{{
// 				pkg:       testdata.P2,
// 				depPkg:    testdata.P4,
// 				matchType: mSpecific,
// 				isDep: &model.IsDependencyInputSpec{
// 					Justification: "test justification",
// 				},
// 			}},
// 			IsOccs: []testOccurrence{{
// 				Subj:  &model.PackageOrSourceInput{Package: testdata.P4},
// 				Art:   testdata.A1,
// 				isOcc: &model.IsOccurrenceInputSpec{Justification: "test justification"},
// 			}},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Packages: []*model.PkgInputSpec{testdata.P2, testdata.P4},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri",
// 						},
// 						{
// 							URI: "test uri",
// 						},
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Package: &model.PkgSpec{
// 						Version: ptrfrom.String("2.11.1"),
// 					},
// 				},
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.P2out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.P4out, testdata.A1out},
// 					IncludedDependencies: []*model.IsDependency{{
// 						Package:           testdata.P2out,
// 						DependencyPackage: testdata.P4out,
// 						Justification:     "test justification",
// 					}},
// 					IncludedOccurrences: []*model.IsOccurrence{{
// 						Subject:       testdata.P4out,
// 						Artifact:      testdata.A1out,
// 						Justification: "test justification",
// 					}},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Artifact",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			PkgArt: &model.PackageOrArtifactInputs{
// 				Packages:  []*model.PkgInputSpec{testdata.P1},
// 				Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			},
// 			IsOccs: []testOccurrence{{
// 				Subj:  &model.PackageOrSourceInput{Package: testdata.P1},
// 				Art:   testdata.A2,
// 				isOcc: &model.IsOccurrenceInputSpec{Justification: "test justification"},
// 			}},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Packages: []*model.PkgInputSpec{testdata.P1},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri",
// 						},
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInputs{
// 						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 					},
// 					HS: []*model.HasSBOMInputSpec{
// 						{
// 							URI: "test uri",
// 						},
// 						{
// 							URI: "test uri",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSBOMSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Artifact: &model.ArtifactSpec{
// 						Algorithm: ptrfrom.String("sha1"),
// 					},
// 				},
// 			},
// 			ExpHS: []*model.HasSbom{
// 				{
// 					Subject:          testdata.A2out,
// 					URI:              "test uri",
// 					IncludedSoftware: []model.PackageOrArtifact{testdata.P1out, testdata.A1out, testdata.A2out},
// 					IncludedOccurrences: []*model.IsOccurrence{{
// 						Subject:       testdata.P1out,
// 						Artifact:      testdata.A2out,
// 						Justification: "test justification",
// 					}},
// 				},
// 			},
// 		},
// 	}
// 	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
// 		return strings.Compare(".ID", p[len(p)-1].String()) == 0
// 	}, cmp.Ignore())
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			for _, p := range test.InPkg {
// 				if _, err := b.IngestPackage(ctx, *p); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				}
// 			}
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				}
// 			}
// 			includes := model.HasSBOMIncludesInputSpec{}
// 			if test.PkgArt != nil {
// 				if pkgs, err := b.IngestPackages(ctx, test.PkgArt.Packages); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				} else {
// 					for _, pkg := range pkgs {
// 						includes.Software = append(includes.Software, pkg.PackageVersionID)
// 					}
// 				}
// 				if arts, err := b.IngestArtifacts(ctx, test.PkgArt.Artifacts); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				} else {
// 					includes.Software = append(includes.Software, arts...)
// 				}
// 			}

// 			for _, dep := range test.IsDeps {
// 				if isDep, err := b.IngestDependency(ctx, *dep.pkg, *dep.depPkg, dep.matchType, *dep.isDep); err != nil {
// 					t.Fatalf("Could not ingest dependency: %v", err)
// 				} else {
// 					includes.Dependencies = append(includes.Dependencies, isDep)
// 				}
// 			}

// 			for _, occ := range test.IsOccs {
// 				if isOcc, err := b.IngestOccurrence(ctx, *occ.Subj, *occ.Art, *occ.isOcc); err != nil {
// 					t.Fatalf("Could not ingest occurrence: %v", err)
// 				} else {
// 					includes.Occurrences = append(includes.Occurrences, isOcc)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				var sbomIncludes []*model.HasSBOMIncludesInputSpec
// 				for count := 0; count < len(o.HS); count++ {
// 					sbomIncludes = append(sbomIncludes, &includes)
// 				}
// 				_, err := b.IngestHasSBOMs(ctx, o.Sub, o.HS, sbomIncludes)
// 				if (err != nil) != test.ExpIngestErr {
// 					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
// 				}
// 				if err != nil {
// 					return
// 				}
// 			}
// 			got, err := b.HasSBOM(ctx, test.Query)
// 			if (err != nil) != test.ExpQueryErr {
// 				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
// 			}
// 			if err != nil {
// 				return
// 			}
// 			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
// 				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

func Test_buildHasSbomByID(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := DeleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasSBOMSpec
		ExpHS        *model.HasSbom
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.P2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on Package ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{

				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.P2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on Artifact",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.A2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on Artifact ID",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.A2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject:          testdata.P1out,
				DownloadLocation: "location two",
			},
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				ID: ptrfrom.String("-7"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				// TODO (knrc) handle includes
				hsID, err := b.IngestHasSbom(ctx, o.Sub, *o.HS, model.HasSBOMIncludesInputSpec{})
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildHasSbomByID(ctx, hsID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
