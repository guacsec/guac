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

package guacanalytics

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/Khan/genqlient/graphql"
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	tm, _                   = time.Parse(time.RFC3339, "2023-07-17T17:45:50.52Z")
	simpleIsDependencyGraph = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String("ubuntu"),
					Name:      "dpkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "conan",
					Namespace: ptrfrom.String("openssl.org"),
					Name:      "openssl",
					Version:   ptrfrom.String("3.0.3"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "top",
					Namespace: ptrfrom.String("topns"),
					Name:      "toppkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String("ubuntu"),
					Name:      "dpkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "conan",
					Namespace: ptrfrom.String("openssl.org"),
					Name:      "openssl",
					Version:   ptrfrom.String("3.0.3"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "bottom",
					Namespace: ptrfrom.String("bottomns"),
					Name:      "bottompkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeIndirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}

	simpleHasSLSAGraph = assembler.IngestPredicates{

		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType1",
					Namespace: ptrfrom.String("pkgNamespace1"),
					Name:      "pkgName1",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg1 and artifact1",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType2",
					Namespace: ptrfrom.String("pkgNamespace2"),
					Name:      "pkgName2",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm2",
					Digest:    "testArtifactDigest2",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg2 and artifact2",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType4",
					Namespace: ptrfrom.String("pkgNamespace4"),
					Name:      "pkgName4",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg4 and artifact1",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType4",
					Namespace: ptrfrom.String("pkgNamespace4"),
					Name:      "pkgName4",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm3",
					Digest:    "testArtifactDigest3",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg4 and artifact3",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType5",
					Namespace: ptrfrom.String("pkgNamespace5"),
					Name:      "pkgName5",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm4",
					Digest:    "testArtifactDigest4",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg5 and artifact3",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm2",
					Digest:    "testArtifactDigest2",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm3",
					Digest:    "testArtifactDigest3",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithm4",
					Digest:    "testArtifactDigest4",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
	}

	isDependencyAndHasSLSARelationship = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType1",
					Namespace: ptrfrom.String("pkgNamespace1"),
					Name:      "pkgName1",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgType3",
					Namespace: ptrfrom.String("pkgNamespace3"),
					Name:      "pkgName3",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}

	hasSLSASimpletonGraph = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType1",
					Namespace: ptrfrom.String("pkgNamespace1"),
					Name:      "pkgName1",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg1 and artifact1",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType2",
					Namespace: ptrfrom.String("pkgNamespace2"),
					Name:      "pkgName2",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm2",
					Digest:    "testArtifactDigest2",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg2 and artifact2",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm2",
					Digest:    "testArtifactDigest2",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
	}

	isDependencyNotInRangeGraph = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "conan3",
					Namespace: ptrfrom.String("openssl.org3"),
					Name:      "openssl3",
					Version:   ptrfrom.String("3.0.3"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "extraType",
					Namespace: ptrfrom.String("extraNamespace"),
					Name:      "extraName",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   "=3.0.3",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}

	sourceNameHasSLSAGraph = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Src: &model.SourceInputSpec{
					Type:      "srcType2",
					Namespace: "srcNamespace2",
					Name:      "srcName2",
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm5",
					Digest:    "testArtifactDigest5",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect src2 and artifact5",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType6",
					Namespace: ptrfrom.String("pkgNamespace6"),
					Name:      "pkgName6",
					Version:   ptrfrom.String("3.0.3"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm6",
					Digest:    "testArtifactDigest6",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg6 and artifact6",
				},
			},
			{
				Src: &model.SourceInputSpec{
					Type:      "srcType2",
					Namespace: "srcNamespace2",
					Name:      "srcName2",
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm7",
					Digest:    "testArtifactDigest7",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect src2 and artifact7",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm5",
					Digest:    "testArtifactDigest5",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithm6",
					Digest:    "testArtifactDigest6",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
	}

	shouldNotBeExplored = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeA",
					Namespace: ptrfrom.String("pkgNamespaceA"),
					Name:      "pkgNameA",
					Version:   ptrfrom.String("3.0.3"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgTypeB",
					Namespace: ptrfrom.String("pkgNamespaceB"),
					Name:      "pkgNameB",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
		CertifyGood: []assembler.CertifyGoodIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeB",
					Namespace: ptrfrom.String("pkgNamespaceB"),
					Name:      "pkgNameB",
					Version:   ptrfrom.String("1.19.0"),
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeAllVersions,
				},
				CertifyGood: &model.CertifyGoodInputSpec{
					Justification: "good package",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeA",
					Namespace: ptrfrom.String("pkgNamespaceA"),
					Name:      "pkgNameA",
					Version:   ptrfrom.String("3.0.3"),
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeAllVersions,
				},
				CertifyGood: &model.CertifyGoodInputSpec{
					Justification: "good package",
				},
			},
		},
	}

	hasSourceAtPackageVersionGraph = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeC",
					Namespace: ptrfrom.String("pkgNamespaceC"),
					Name:      "pkgNameC",
					Version:   ptrfrom.String("3.0.3"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithmC",
					Digest:    "testArtifactDigestC",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkgC and artifactC",
				},
			},
			{
				Src: &model.SourceInputSpec{
					Type:      "srcTypeD",
					Namespace: "srcNamespaceD",
					Name:      "srcNameD",
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithmD",
					Digest:    "testArtifactDigestD",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect srcD and artifactD",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithmD",
					Digest:    "testArtifactDigestD",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithmC",
					Digest:    "testArtifactDigestC",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
		HasSourceAt: []assembler.HasSourceAtIngest{
			{
				Src: &model.SourceInputSpec{
					Type:      "srcTypeD",
					Namespace: "srcNamespaceD",
					Name:      "srcNameD",
				},
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeE",
					Namespace: ptrfrom.String("pkgNamespaceE"),
					Name:      "pkgNameE",
					Version:   ptrfrom.String("1.19.0"),
				},
				HasSourceAt: &model.HasSourceAtInputSpec{
					Justification: "test justification",
					KnownSince:    tm,
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeSpecificVersion,
				},
			},
		},
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeF",
					Namespace: ptrfrom.String("pkgNamespaceF"),
					Name:      "pkgNameF",
					Version:   ptrfrom.String("2.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgTypeE",
					Namespace: ptrfrom.String("pkgNamespaceE"),
					Name:      "pkgNameE",
					Version:   ptrfrom.String("3.0.3"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   "=>2.0.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}

	hasSourceAtPackageNameGraph = assembler.IngestPredicates{
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeG",
					Namespace: ptrfrom.String("pkgNamespaceG"),
					Name:      "pkgNameG",
					Version:   ptrfrom.String("3.0.3"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithmG",
					Digest:    "testArtifactDigestG",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkgG and artifactG",
				},
			},
			{
				Src: &model.SourceInputSpec{
					Type:      "srcTypeH",
					Namespace: "srcNamespaceH",
					Name:      "srcNameH",
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithmH",
					Digest:    "testArtifactDigestH",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect srcH and artifactH",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithmH",
					Digest:    "testArtifactDigestH",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithmG",
					Digest:    "testArtifactDigestG",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
		HasSourceAt: []assembler.HasSourceAtIngest{
			{
				Src: &model.SourceInputSpec{
					Type:      "srcTypeH",
					Namespace: "srcNamespaceH",
					Name:      "srcNameH",
				},
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeI",
					Namespace: ptrfrom.String("pkgNamespaceI"),
					Name:      "pkgNameI",
				},
				HasSourceAt: &model.HasSourceAtInputSpec{
					Justification: "test justification",
					KnownSince:    tm,
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeAllVersions,
				},
			},
		},
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeJ",
					Namespace: ptrfrom.String("pkgNamespaceJ"),
					Name:      "pkgNameJ",
					Version:   ptrfrom.String("2.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgTypeI",
					Namespace: ptrfrom.String("pkgNamespaceI"),
					Name:      "pkgNameI",
					Version:   ptrfrom.String("3.0.3"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=2.0.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}
)

func ingestIsDependency(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.IsDependency {
		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting package: %s\n", err)
		}

		_, err = model.IngestPackage(context.Background(), client, *ingest.DepPkg)

		if err != nil {
			return fmt.Errorf("error in ingesting dependent package: %s\n", err)
		}
		_, err = model.IsDependency(context.Background(), client, *ingest.Pkg, *ingest.DepPkg, *ingest.IsDependency)

		if err != nil {
			return fmt.Errorf("error in ingesting isDependency: %s\n", err)
		}
	}
	return nil
}

func ingestHasSLSA(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.HasSlsa {
		_, err := model.IngestBuilder(context.Background(), client, *ingest.Builder)

		if err != nil {
			return fmt.Errorf("error in ingesting Builder for HasSlsa: %v\n", err)
		}

		_, err = model.IngestMaterials(context.Background(), client, ingest.Materials)

		if err != nil {
			return fmt.Errorf("error in ingesting Material for HasSlsa: %v\n", err)
		}

		_, err = model.SLSAForArtifact(context.Background(), client, *ingest.Artifact, ingest.Materials, *ingest.Builder, *ingest.HasSlsa)

		if err != nil {
			return fmt.Errorf("error in ingesting HasSlsa: %v\n", err)
		}
	}
	return nil
}

func ingestHasSourceAt(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.HasSourceAt {
		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting pkg HasSourceAt: %v\n", err)
		}

		_, err = model.IngestSource(context.Background(), client, *ingest.Src)

		if err != nil {
			return fmt.Errorf("error in ingesting src HasSourceAt: %v\n", err)
		}

		_, err = model.HasSourceAt(context.Background(), client, *ingest.Pkg, ingest.PkgMatchFlag, *ingest.Src, *ingest.HasSourceAt)

		if err != nil {
			return fmt.Errorf("error in ingesting HasSourceAt: %v\n", err)
		}
	}
	return nil
}

func ingestIsOccurrence(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.IsOccurrence {
		var err error

		if ingest.Src != nil {
			_, err = model.IngestSource(context.Background(), client, *ingest.Src)
		} else {
			_, err = model.IngestPackage(context.Background(), client, *ingest.Pkg)

		}

		if err != nil {
			return fmt.Errorf("error in ingesting pkg/src IsOccurrence: %v\n", err)
		}

		_, err = model.IngestArtifact(context.Background(), client, *ingest.Artifact)

		if err != nil {
			return fmt.Errorf("error in ingesting artifact for IsOccurrence: %v\n", err)
		}

		if ingest.Src != nil {
			_, err = model.IsOccurrenceSrc(context.Background(), client, *ingest.Src, *ingest.Artifact, *ingest.IsOccurrence)
		} else {
			_, err = model.IsOccurrencePkg(context.Background(), client, *ingest.Pkg, *ingest.Artifact, *ingest.IsOccurrence)
		}

		if err != nil {
			return fmt.Errorf("error in ingesting isOccurrence: %v\n", err)
		}
	}
	return nil
}

func ingestCertifyGood(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.CertifyGood {
		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting Package for CertifyGood: %v\n", err)
		}

		_, err = model.CertifyGoodPkg(context.Background(), client, *ingest.Pkg, &ingest.PkgMatchFlag, *ingest.CertifyGood)

		if err != nil {
			return fmt.Errorf("error in ingesting CertifyGood: %v\n", err)
		}
	}
	return nil
}

func ingestTestData(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	if len(graph.IsDependency) > 0 {
		err := ingestIsDependency(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.IsOccurrence) > 0 {
		err := ingestIsOccurrence(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.HasSlsa) > 0 {
		err := ingestHasSLSA(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.CertifyGood) > 0 {
		err := ingestCertifyGood(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.HasSourceAt) > 0 {
		err := ingestHasSourceAt(ctx, client, graph)
		if err != nil {
			return err
		}
	}
	return nil
}

func Test_SearchSubgraphFromVuln(t *testing.T) {
	server, err := startTestServer()

	if err != nil {
		t.Errorf("error starting server: %s \n", err)
		os.Exit(1)
	}

	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlClient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	testCases := []struct {
		name              string
		startType         string
		startNamespace    string
		startName         string
		startVersion      *string
		stopType          *string
		stopNamespace     string
		stopName          string
		stopVersion       *string
		maxDepth          int
		expectedLen       int
		expectedPkgs      []string
		expectedArtifacts []string
		expectedSrcs      []string
		graphInputs       []assembler.IngestPredicates
	}{
		{
			name:           "1: two levels of dependencies, no stopID and no limiting maxDepth",
			startType:      "conan",
			startNamespace: "openssl.org",
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			maxDepth:       10,
			expectedLen:    6,
			expectedPkgs:   []string{"top", "deb", "conan"},
			graphInputs:    []assembler.IngestPredicates{simpleIsDependencyGraph},
		},
		{
			name:           "2:  one level of dependencies, no stopID and no limiting maxDepth",
			startType:      "deb",
			startNamespace: "ubuntu",
			startName:      "dpkg",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"top", "deb"},
			graphInputs:    []assembler.IngestPredicates{simpleIsDependencyGraph},
		},
		{
			name:           "3: two levels of dependencies, a stopID at the first level and no limiting maxDepth",
			startType:      "conan",
			startNamespace: "openssl.org",
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			stopType:       ptrfrom.String("deb"),
			stopNamespace:  "ubuntu",
			stopName:       "dpkg",
			stopVersion:    ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"deb", "conan"},
			graphInputs:    []assembler.IngestPredicates{simpleIsDependencyGraph},
		},
		{
			name:           "4: two levels of dependencies, no stopID and a limiting maxDepth at the first level",
			startType:      "conan",
			startNamespace: "openssl.org",
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			maxDepth:       1,
			expectedLen:    4,
			expectedPkgs:   []string{"deb", "conan"},
			graphInputs:    []assembler.IngestPredicates{simpleIsDependencyGraph},
		},
		{
			name:           "5: isDependency indirect dependency",
			startType:      "bottom",
			startNamespace: "bottomns",
			startName:      "bottompkg",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    8,
			expectedPkgs:   []string{"top", "deb", "conan", "bottom"},
			graphInputs:    []assembler.IngestPredicates{simpleIsDependencyGraph},
		},
		{
			name:           "6: isDependency no dependents returns no extra",
			startType:      "top",
			startNamespace: "topns",
			startName:      "toppkg",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    2,
			expectedPkgs:   []string{"top"},
			graphInputs:    []assembler.IngestPredicates{simpleIsDependencyGraph},
		},
		{
			name:           "7: direct isDependency not included in range",
			startType:      "extraType",
			startNamespace: "extraNamespace",
			startName:      "extraName",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    2,
			expectedPkgs:   []string{"extraType"},
			graphInputs:    []assembler.IngestPredicates{isDependencyNotInRangeGraph},
		},
		{
			name:              "8: hasSLSA simpleton case",
			startType:         "pkgType1",
			startNamespace:    "pkgNamespace1",
			startName:         "pkgName1",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       6,
			expectedPkgs:      []string{"pkgType1", "pkgType2"},
			expectedArtifacts: []string{"testArtifactAlgorithm1", "testArtifactAlgorithm2"},
			graphInputs:       []assembler.IngestPredicates{hasSLSASimpletonGraph},
		},
		{
			name:              "9: hasSLSA large case",
			startType:         "pkgType1",
			startNamespace:    "pkgNamespace1",
			startName:         "pkgName1",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       9,
			expectedPkgs:      []string{"pkgType1", "pkgType2", "pkgType4"},
			expectedArtifacts: []string{"testArtifactAlgorithm1", "testArtifactAlgorithm2", "testArtifactAlgorithm3"},
			graphInputs:       []assembler.IngestPredicates{simpleHasSLSAGraph},
		},
		{
			name:              "10: hasSLSA case with no dependent isOccurrences",
			startType:         "pkgType2",
			startNamespace:    "pkgNamespace2",
			startName:         "pkgName2",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       3,
			expectedPkgs:      []string{"pkgType2"},
			expectedArtifacts: []string{"testArtifactAlgorithm2"},
			graphInputs:       []assembler.IngestPredicates{simpleHasSLSAGraph},
		},
		{
			name:              "11: hasSLSA two levels",
			startType:         "pkgType5",
			startNamespace:    "pkgNamespace5",
			startName:         "pkgName5",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       12,
			expectedPkgs:      []string{"pkgType5", "pkgType4", "pkgType2", "pkgType1"},
			expectedArtifacts: []string{"testArtifactAlgorithm4", "testArtifactAlgorithm3", "testArtifactAlgorithm1", "testArtifactAlgorithm2"},
			graphInputs:       []assembler.IngestPredicates{simpleHasSLSAGraph},
		},
		{
			name:              "12: hasSLSA & isDependency combined case",
			startType:         "pkgType3",
			startNamespace:    "pkgNamespace3",
			startName:         "pkgName3",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       11,
			expectedPkgs:      []string{"pkgType3", "pkgType2", "pkgType1", "pkgType4"},
			expectedArtifacts: []string{"testArtifactAlgorithm1", "testArtifactAlgorithm2", "testArtifactAlgorithm3"},
			graphInputs:       []assembler.IngestPredicates{simpleHasSLSAGraph, simpleIsDependencyGraph, isDependencyAndHasSLSARelationship},
		},
		{
			name:           "13: should not explore certifyGood case",
			startType:      "pkgTypeB",
			startNamespace: "pkgNamespaceB",
			startName:      "pkgNameB",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"pkgTypeB", "pkgTypeA"},
			graphInputs:    []assembler.IngestPredicates{shouldNotBeExplored},
		},
		{
			name:              "14: test sourceNames with hasSLSA",
			startType:         "pkgType6",
			startNamespace:    "pkgNamespace6",
			startName:         "pkgName6",
			startVersion:      ptrfrom.String("3.0.3"),
			maxDepth:          10,
			expectedLen:       6,
			expectedPkgs:      []string{"pkgType6"},
			expectedArtifacts: []string{"testArtifactAlgorithm5", "testArtifactAlgorithm6", "testArtifactAlgorithm7"},
			expectedSrcs:      []string{"srcType2"},
			graphInputs:       []assembler.IngestPredicates{sourceNameHasSLSAGraph},
		},
		{
			name:              "15: test hasSourceAt attached to packageVersion",
			startType:         "pkgTypeC",
			startNamespace:    "pkgNamespaceC",
			startName:         "pkgNameC",
			startVersion:      ptrfrom.String("3.0.3"),
			maxDepth:          9,
			expectedLen:       7,
			expectedPkgs:      []string{"pkgTypeC", "pkgTypeE"},
			expectedArtifacts: []string{"testArtifactAlgorithmC", "testArtifactAlgorithmD"},
			expectedSrcs:      []string{"srcTypeD"},
			graphInputs:       []assembler.IngestPredicates{hasSourceAtPackageVersionGraph},
		},
		{
			name:              "16: test hasSourceAt attached to packageName",
			startType:         "pkgTypeG",
			startNamespace:    "pkgNamespaceG",
			startName:         "pkgNameG",
			startVersion:      ptrfrom.String("3.0.3"),
			maxDepth:          9,
			expectedLen:       10,
			expectedPkgs:      []string{"pkgTypeG", "pkgTypeI", "pkgTypeJ"},
			expectedArtifacts: []string{"testArtifactAlgorithmG", "testArtifactAlgorithmH"},
			expectedSrcs:      []string{"srcTypeH"},
			graphInputs:       []assembler.IngestPredicates{hasSourceAtPackageNameGraph},
		},
		{
			name:           "17: test hasSourceAt from packageName",
			startType:      "pkgTypeE",
			startNamespace: "pkgNamespaceE",
			startName:      "pkgNameE",
			maxDepth:       9,
			expectedLen:    6,
			expectedPkgs:   []string{"pkgTypeE", "pkgTypeF"},
			expectedSrcs:   []string{"srcTypeD"},
			graphInputs:    []assembler.IngestPredicates{hasSourceAtPackageVersionGraph},
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Test case %s\n", tt.name), func(t *testing.T) {
			for _, graphInput := range tt.graphInputs {
				err = ingestTestData(ctx, gqlClient, graphInput)

				if err != nil {
					t.Errorf("error ingesting test data: %s", err)
					return
				}
			}

			var getPackageIDsValues []*string
			var startID string
			if tt.startVersion != nil {
				getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, ptrfrom.String(tt.startType), tt.startNamespace, tt.startName, tt.startVersion, true, false)
			} else {
				getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, ptrfrom.String(tt.startType), tt.startNamespace, tt.startName, nil, false, true)
			}

			if err != nil {
				t.Errorf("error finding startNode: %s", err)
				return
			}

			if len(getPackageIDsValues) > 1 {
				t.Errorf("cannot locate matching startID input\n")
				return
			}
			startID = *getPackageIDsValues[0]

			var stopID *string
			if tt.stopType != nil {
				if tt.stopVersion != nil {
					getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, tt.stopType, tt.stopNamespace, tt.stopName, tt.stopVersion, true, false)
				} else {
					getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, tt.stopType, tt.stopNamespace, tt.stopName, nil, false, true)
				}

				if err != nil {
					t.Errorf("error finding stopNode: %s", err)
					return
				}

				if getPackageIDsValues == nil || len(getPackageIDsValues) > 1 {
					t.Errorf("cannot locate matching stopID input\n")
					return
				}

				stopID = getPackageIDsValues[0]
			}

			gotMap, err := SearchDependenciesFromStartNode(ctx, gqlClient, startID, stopID, tt.maxDepth)

			if err != nil {
				t.Errorf("got err from SearchDependenciesFromStartNode: %s", err)
			}

			if diff := cmp.Diff(tt.expectedLen, len(gotMap)); len(diff) > 0 {
				t.Errorf("number of map entries (-want +got):\n%s", diff)
			}

			var expectedPkgIDs []string
			for _, pkg := range tt.expectedPkgs {
				pkgIDs, err := getPackageIDs(ctx, gqlClient, &pkg, "", "", nil, false, false)
				if err != nil {
					t.Errorf("expected package %s not found: %s\n", pkg, err)
				}

				for _, ID := range pkgIDs {
					expectedPkgIDs = append(expectedPkgIDs, *ID)
				}
			}

			var expectedArtifactIDs []string
			for _, artifact := range tt.expectedArtifacts {
				artifactID, err := getArtifactID(ctx, gqlClient, artifact)
				if err != nil {
					t.Errorf("%s \n", err)
				}

				expectedArtifactIDs = append(expectedArtifactIDs, artifactID)
			}

			var expectedSrcIDs []string
			for _, src := range tt.expectedSrcs {
				srcID, err := getSrcID(ctx, gqlClient, src)
				if err != nil {
					t.Errorf("%s \n", err)
				}

				expectedSrcIDs = append(expectedSrcIDs, srcID)
			}

			for gotID, node := range gotMap {
				if stopID == nil && tt.maxDepth == 10 {
					if !node.Expanded {
						t.Errorf("all nodes should be expanded but this node was not: node %s \n", gotID)
					}
				}

				//check that other packages are not present in return map
				inExpectedPkgs := false
				for _, expectedID := range expectedPkgIDs {
					if expectedID == gotID {
						inExpectedPkgs = true
						break
					}
				}

				inExpectedArtifacts := false
				for _, expectedID := range expectedArtifactIDs {
					if expectedID == gotID {
						inExpectedArtifacts = true
						break
					}
				}

				inExpectedSrcs := false
				for _, expectedID := range expectedSrcIDs {
					if expectedID == gotID {
						inExpectedSrcs = true
						break
					}
				}

				// if not present in expected packages or in expected artifacts
				if !(inExpectedPkgs || inExpectedArtifacts || inExpectedSrcs) {
					t.Errorf("this ID appears in the returned map but is not expected: %s \n", gotID)
					return
				}
			}

		})
	}

	// cleaning up server instance
	done := make(chan bool, 1)
	ctx, cf := context.WithCancel(ctx)
	go func() {
		_ = server.Shutdown(ctx)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cf()
		server.Close()
	}
	cf()
}

func startTestServer() (*http.Server, error) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	srv, err := getGraphqlTestServer()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize graphql server: %s", err)
	}
	http.Handle("/query", srv)

	server := &http.Server{Addr: fmt.Sprintf(":%d", 9090)}
	logger.Info("starting server")

	go func() {
		logger.Infof("server finished: %s", server.ListenAndServe())
	}()
	return server, nil
}

func getGraphqlTestServer() (*handler.Server, error) {
	var topResolver resolvers.Resolver
	args := inmem.DemoCredentials{}
	backend, err := inmem.GetBackend(&args)
	if err != nil {
		return nil, fmt.Errorf("error creating inmem backend: %w", err)
	}

	topResolver = resolvers.Resolver{Backend: backend}

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	return srv, nil
}

// This function return matching packageName and/or packageVersion node IDs depending on if you specified to only find name nodes or version nodes
func getPackageIDs(ctx context.Context, gqlClient graphql.Client, nodeType *string, nodeNamespace string, nodeName string, nodeVersion *string, justFindVersion bool, justFindName bool) ([]*string, error) {
	var pkgFilter model.PkgSpec
	if nodeVersion != nil {
		pkgFilter = model.PkgSpec{
			Type:      nodeType,
			Namespace: &nodeNamespace,
			Name:      &nodeName,
			Version:   nodeVersion,
		}
	} else {
		pkgFilter = model.PkgSpec{
			Type: nodeType,
		}
	}

	pkgResponse, err := model.Packages(ctx, gqlClient, &pkgFilter)

	if err != nil {
		return nil, fmt.Errorf("error getting id for test case: %s\n", err)
	}
	var foundIDs []*string

	if len(pkgResponse.Packages[0].Namespaces[0].Names) > 0 && !justFindVersion {
		for _, name := range pkgResponse.Packages[0].Namespaces[0].Names {
			foundIDs = append(foundIDs, &name.Id)
		}
	}

	if len(pkgResponse.Packages[0].Namespaces[0].Names[0].Versions) > 0 && !justFindName {
		for index, _ := range pkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
			foundIDs = append(foundIDs, &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[index].Id)
		}
	}

	if len(foundIDs) < 1 {
		return nil, fmt.Errorf("no matching nodes found\n")
	}

	return foundIDs, nil
}

func getArtifactID(ctx context.Context, gqlClient graphql.Client, algorithm string) (string, error) {
	artifactFilter := model.ArtifactSpec{
		Algorithm: &algorithm,
	}

	artifactResponse, err := model.Artifacts(ctx, gqlClient, &artifactFilter)

	if err != nil {
		return "", fmt.Errorf("error filtering for expected artifact: %s\n", err)
	}

	if len(artifactResponse.Artifacts) != 1 {
		return "", fmt.Errorf("could not find the matching artifact\n")
	}

	return artifactResponse.Artifacts[0].Id, nil
}

func getSrcID(ctx context.Context, gqlClient graphql.Client, srcType string) (string, error) {
	srcFilter := model.SourceSpec{
		Type: &srcType,
	}

	srcResponse, err := model.Sources(ctx, gqlClient, &srcFilter)

	if err != nil {
		return "", fmt.Errorf("error filtering for expected source: %s\n", err)
	}

	if len(srcResponse.Sources) != 1 {
		return "", fmt.Errorf("could not find the matching source\n")
	}

	return srcResponse.Sources[0].Namespaces[0].Names[0].Id, nil
}
