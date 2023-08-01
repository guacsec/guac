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

package arangodb

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/arangodb/go-driver"
	arangodbdriverhttp "github.com/arangodb/go-driver/http"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	namespaces    string        = "namespaces"
	names         string        = namespaces + ".names"
	versions      string        = names + ".versions"
	origin        string        = "origin"
	collector     string        = "collector"
	justification string        = "justification"
	maxRetires    int           = 100
	retryTimer    time.Duration = time.Microsecond
	guacEmpty     string        = "guac-empty-@@"

	// Package collections
	pkgHasTypeStr      string = "pkgHasType"
	pkgRootsStr        string = "pkgRoots"
	pkgTypesStr        string = "pkgTypes"
	pkgHasNamespaceStr string = "pkgHasNamespace"
	pkgNamespacesStr   string = "pkgNamespaces"
	pkgHasNameStr      string = "pkgHasName"
	pkgHasVersionStr   string = "pkgHasVersion"
	pkgNamesStr        string = "pkgNames"
	pkgVersionsStr     string = "pkgVersions"

	// source collections
	srcHasTypeStr      string = "srcHasType"
	srcRootsStr        string = "srcRoots"
	srcTypesStr        string = "srcTypes"
	srcHasNamespaceStr string = "srcHasNamespace"
	srcNamespacesStr   string = "srcNamespaces"
	srcHasNameStr      string = "srcHasName"
	srcNamesStr        string = "srcNames"

	// builder collections

	buildersStr string = "builders"

	// artifact collection

	artifactsStr string = "artifacts"

	// cve collection

	cvesStr string = "cves"

	// ghsa collection

	ghsasStr string = "ghsas"

	// osv collection

	osvsStr string = "osvs"

	// isDependency collections

	isDependencyDepPkgEdgesStr     string = "isDependencyDepPkgEdges"
	isDependencySubjectPkgEdgesStr string = "isDependencySubjectPkgEdges"
	isDependenciesStr              string = "isDependencies"

	//isOccurrences collections

	isOccurrenceArtEdgesStr        string = "isOccurrenceArtEdges"
	isOccurrenceSubjectPkgEdgesStr string = "isOccurrenceSubjectPkgEdges"
	isOccurrenceSubjectSrcEdgesStr string = "isOccurrenceSubjectSrcEdges"
	isOccurrencesStr               string = "isOccurrences"

	// hasSLSA collections

	hasSLSASubjectArtEdgesStr string = "hasSLSASubjectArtEdges"
	hasSLSABuiltByEdgesStr    string = "hasSLSABuiltByEdges"
	hasSLSABuiltFromEdgesStr  string = "hasSLSABuiltFromEdges"
	hasSLSAsStr               string = "hasSLSAs"

	// hashEquals collections

	hashEqualArtEdgesStr        string = "hashEqualArtEdges"
	hashEqualSubjectArtEdgesStr string = "hashEqualSubjectArtEdges"
	hashEqualsStr               string = "hashEquals"

	// hasSBOM collection

	hasSBOMPkgEdgesStr string = "hasSBOMPkgEdges"
	hasSBOMArtEdgesStr string = "hasSBOMArtEdges"
	hasSBOMsStr        string = "hasSBOMs"

	// certifyVuln collection
	// TODO (pxp928): update collections based on edge collections
	certifyVulnEdgesStr string = "certifyVulnEdges"
	certifyVulnsStr     string = "certifyVulns"

	// certifyScorecard collection

	scorecardSrcEdgesStr string = "scorecardSrcEdges"
	scorecardStr         string = "scorecards"

	// certifyBad collection

	certifyBadPkgVersionEdgesStr string = "certifyBadPkgVersionEdges"
	certifyBadPkgNameEdgesStr    string = "certifyBadPkgNameEdges"
	certifyBadSrcEdgesStr        string = "certifyBadSrcEdges"
	certifyBadArtEdgesStr        string = "certifyBadArtEdges"
	certifyBadsStr               string = "certifyBads"

	// certifyGood collection

	certifyGoodPkgVersionEdgesStr string = "certifyGoodPkgVersionEdges"
	certifyGoodPkgNameEdgesStr    string = "certifyGoodPkgNameEdges"
	certifyGoodSrcEdgesStr        string = "certifyGoodSrcEdges"
	certifyGoodArtEdgesStr        string = "certifyGoodArtEdges"
	certifyGoodsStr               string = "certifyGoods"
)

type ArangoConfig struct {
	User     string
	Pass     string
	DBAddr   string
	TestData bool
}

type arangoQueryBuilder struct {
	query strings.Builder
}

type pkgRootData struct {
	Key     string `json:"_key"`
	Id      string `json:"_id"`
	PkgRoot string `json:"root"`
}

type srcRootData struct {
	Key     string `json:"_key"`
	Id      string `json:"_id"`
	SrcRoot string `json:"root"`
}

type arangoClient struct {
	client  driver.Client
	db      driver.Database
	graph   driver.Graph
	pkgRoot *pkgRootData
	srcRoot *srcRootData
}

func arangoDBConnect(address, user, password string) (driver.Client, error) {
	conn, err := arangodbdriverhttp.NewConnection(arangodbdriverhttp.ConnectionConfig{
		Endpoints: []string{address},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect %s database with error: %w", address, err)
	}

	client, err := driver.NewClient(driver.ClientConfig{
		Connection:     conn,
		Authentication: driver.BasicAuthentication(user, password),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect %s database with error: %w", address, err)
	}

	return client, nil
}

func GetBackend(ctx context.Context, args backends.BackendArgs) (backends.Backend, error) {
	config, ok := args.(*ArangoConfig)
	if !ok {
		return nil, fmt.Errorf("failed to assert arango config from backend args")
	}
	arangodbClient, err := arangoDBConnect(config.DBAddr, config.User, config.Pass)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to arango DB %s database with error: %w", config.DBAddr, err)
	}
	var db driver.Database
	// check if database exists
	dbExists, err := arangodbClient.DatabaseExists(ctx, "guac_db")
	if err != nil {
		return nil, fmt.Errorf("failed to check %s database with error: %w", config.DBAddr, err)
	}
	if dbExists {
		db, err = arangodbClient.Database(ctx, "guac_db")
		if err != nil {
			return nil, fmt.Errorf("failed to connect %s database with error: %w", config.DBAddr, err)
		}
	} else {
		// Create database
		db, err = arangodbClient.CreateDatabase(ctx, "guac_db", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s database with error: %w", config.DBAddr, err)
		}
	}

	var graph driver.Graph

	// check if graph exists

	graphExists, err := db.GraphExists(ctx, "guac")
	if err != nil {
		return nil, fmt.Errorf("failed to check if graph exists with error: %w", err)
	}
	if graphExists {
		graph, err = db.Graph(ctx, "guac")
		if err != nil {
			return nil, fmt.Errorf("failed to get graph with error: %w", err)
		}
	} else {

		// setup package collections
		var pkgHasType driver.EdgeDefinition
		pkgHasType.Collection = pkgHasTypeStr
		pkgHasType.From = []string{pkgRootsStr}
		pkgHasType.To = []string{pkgTypesStr}

		var pkgHasNamespace driver.EdgeDefinition
		pkgHasNamespace.Collection = pkgHasNamespaceStr
		pkgHasNamespace.From = []string{pkgTypesStr}
		pkgHasNamespace.To = []string{pkgNamespacesStr}

		var pkgHasName driver.EdgeDefinition
		pkgHasName.Collection = pkgHasNameStr
		pkgHasName.From = []string{pkgNamespacesStr}
		pkgHasName.To = []string{pkgNamesStr}

		var pkgHasVersion driver.EdgeDefinition
		pkgHasVersion.Collection = pkgHasVersionStr
		pkgHasVersion.From = []string{pkgNamesStr}
		pkgHasVersion.To = []string{pkgVersionsStr}

		// setup source collections
		var srcHasType driver.EdgeDefinition
		srcHasType.Collection = srcHasTypeStr
		srcHasType.From = []string{srcRootsStr}
		srcHasType.To = []string{srcTypesStr}

		var srcHasNamespace driver.EdgeDefinition
		srcHasNamespace.Collection = srcHasNamespaceStr
		srcHasNamespace.From = []string{srcTypesStr}
		srcHasNamespace.To = []string{srcNamespacesStr}

		var srcHasName driver.EdgeDefinition
		srcHasName.Collection = srcHasNameStr
		srcHasName.From = []string{srcNamespacesStr}
		srcHasName.To = []string{srcNamesStr}

		// setup isDependency collections
		var isDependencyDepPkgEdges driver.EdgeDefinition
		isDependencyDepPkgEdges.Collection = isDependencyDepPkgEdgesStr
		isDependencyDepPkgEdges.From = []string{isDependenciesStr}
		isDependencyDepPkgEdges.To = []string{pkgNamesStr}

		var isDependencySubjectPkgEdges driver.EdgeDefinition
		isDependencySubjectPkgEdges.Collection = isDependencySubjectPkgEdgesStr
		isDependencySubjectPkgEdges.From = []string{pkgVersionsStr}
		isDependencySubjectPkgEdges.To = []string{isDependenciesStr}

		// setup isOccurrence collections
		var isOccurrenceArtEdges driver.EdgeDefinition
		isOccurrenceArtEdges.Collection = isOccurrenceArtEdgesStr
		isOccurrenceArtEdges.From = []string{isOccurrencesStr}
		isOccurrenceArtEdges.To = []string{artifactsStr}

		var isOccurrenceSubjectPkgEdges driver.EdgeDefinition
		isOccurrenceSubjectPkgEdges.Collection = isOccurrenceSubjectPkgEdgesStr
		isOccurrenceSubjectPkgEdges.From = []string{pkgVersionsStr}
		isOccurrenceSubjectPkgEdges.To = []string{isDependenciesStr}

		var isOccurrenceSubjectSrcEdges driver.EdgeDefinition
		isOccurrenceSubjectSrcEdges.Collection = isOccurrenceSubjectSrcEdgesStr
		isOccurrenceSubjectSrcEdges.From = []string{srcNamesStr}
		isOccurrenceSubjectSrcEdges.To = []string{isDependenciesStr}

		// setup hasSLSA collections
		var hasSLSASubjectArtEdges driver.EdgeDefinition
		hasSLSASubjectArtEdges.Collection = hasSLSASubjectArtEdgesStr
		hasSLSASubjectArtEdges.From = []string{artifactsStr}
		hasSLSASubjectArtEdges.To = []string{hasSLSAsStr}

		var hasSLSABuiltByEdges driver.EdgeDefinition
		hasSLSABuiltByEdges.Collection = hasSLSABuiltByEdgesStr
		hasSLSABuiltByEdges.From = []string{hasSLSAsStr}
		hasSLSABuiltByEdges.To = []string{buildersStr}

		var hasSLSABuiltFromEdges driver.EdgeDefinition
		hasSLSABuiltFromEdges.Collection = hasSLSABuiltFromEdgesStr
		hasSLSABuiltFromEdges.From = []string{hasSLSAsStr}
		hasSLSABuiltFromEdges.To = []string{artifactsStr}

		// setup hashEqual collections
		var hashEqualArtEdges driver.EdgeDefinition
		hashEqualArtEdges.Collection = hashEqualArtEdgesStr
		hashEqualArtEdges.From = []string{hashEqualsStr}
		hashEqualArtEdges.To = []string{artifactsStr}

		var hashEqualSubjectArtEdges driver.EdgeDefinition
		hashEqualSubjectArtEdges.Collection = hashEqualSubjectArtEdgesStr
		hashEqualSubjectArtEdges.From = []string{artifactsStr}
		hashEqualSubjectArtEdges.To = []string{hashEqualsStr}

		// setup hasSBOM collections
		var hasSBOMPkgEdges driver.EdgeDefinition
		hasSBOMPkgEdges.Collection = hasSBOMPkgEdgesStr
		hasSBOMPkgEdges.From = []string{artifactsStr}
		hasSBOMPkgEdges.To = []string{hasSBOMsStr}

		var hasSBOMArtEdges driver.EdgeDefinition
		hasSBOMArtEdges.Collection = hasSBOMArtEdgesStr
		hasSBOMArtEdges.From = []string{artifactsStr}
		hasSBOMArtEdges.To = []string{hasSBOMsStr}

		// setup certifyVuln collections
		var certifyVulnEdges driver.EdgeDefinition
		certifyVulnEdges.Collection = certifyVulnEdgesStr
		certifyVulnEdges.From = []string{pkgVersionsStr, certifyVulnsStr}
		certifyVulnEdges.To = []string{certifyVulnsStr, cvesStr, ghsasStr, osvsStr}

		// setup certifyScorecard collections
		var certifyScorecardSrcEdges driver.EdgeDefinition
		certifyScorecardSrcEdges.Collection = scorecardSrcEdgesStr
		certifyScorecardSrcEdges.From = []string{srcNamesStr}
		certifyScorecardSrcEdges.To = []string{scorecardStr}

		// setup certifyBad collections
		var certifyBadPkgVersionEdges driver.EdgeDefinition
		certifyBadPkgVersionEdges.Collection = certifyBadPkgVersionEdgesStr
		certifyBadPkgVersionEdges.From = []string{pkgVersionsStr}
		certifyBadPkgVersionEdges.To = []string{certifyBadsStr}

		var certifyBadPkgNameEdges driver.EdgeDefinition
		certifyBadPkgNameEdges.Collection = certifyBadPkgNameEdgesStr
		certifyBadPkgNameEdges.From = []string{pkgNamesStr}
		certifyBadPkgNameEdges.To = []string{certifyBadsStr}

		var certifyBadArtEdges driver.EdgeDefinition
		certifyBadArtEdges.Collection = certifyBadArtEdgesStr
		certifyBadArtEdges.From = []string{artifactsStr}
		certifyBadArtEdges.To = []string{certifyBadsStr}

		var certifyBadSrcEdges driver.EdgeDefinition
		certifyBadSrcEdges.Collection = certifyBadSrcEdgesStr
		certifyBadSrcEdges.From = []string{srcNamesStr}
		certifyBadSrcEdges.To = []string{certifyBadsStr}

		// setup certifyGood collections
		var certifyGoodPkgVersionEdges driver.EdgeDefinition
		certifyGoodPkgVersionEdges.Collection = certifyGoodPkgVersionEdgesStr
		certifyGoodPkgVersionEdges.From = []string{pkgVersionsStr}
		certifyGoodPkgVersionEdges.To = []string{certifyGoodsStr}

		var certifyGoodPkgNameEdges driver.EdgeDefinition
		certifyGoodPkgNameEdges.Collection = certifyGoodPkgNameEdgesStr
		certifyGoodPkgNameEdges.From = []string{pkgNamesStr, pkgVersionsStr, artifactsStr, srcNamesStr}
		certifyGoodPkgNameEdges.To = []string{certifyGoodsStr}

		var certifyGoodArtEdges driver.EdgeDefinition
		certifyGoodArtEdges.Collection = certifyGoodArtEdgesStr
		certifyGoodArtEdges.From = []string{pkgNamesStr, pkgVersionsStr, artifactsStr, srcNamesStr}
		certifyGoodArtEdges.To = []string{certifyGoodsStr}

		var certifyGoodSrcEdges driver.EdgeDefinition
		certifyGoodSrcEdges.Collection = certifyGoodSrcEdgesStr
		certifyGoodSrcEdges.From = []string{pkgNamesStr, pkgVersionsStr, artifactsStr, srcNamesStr}
		certifyGoodSrcEdges.To = []string{certifyGoodsStr}

		// A graph can contain additional vertex collections, defined in the set of orphan collections
		var options driver.CreateGraphOptions
		options.EdgeDefinitions = []driver.EdgeDefinition{pkgHasType, pkgHasNamespace, pkgHasName,
			pkgHasVersion, srcHasType, srcHasNamespace, srcHasName, isDependencyDepPkgEdges, isDependencySubjectPkgEdges,
			isOccurrenceArtEdges, isOccurrenceSubjectPkgEdges, isOccurrenceSubjectSrcEdges, hasSLSASubjectArtEdges,
			hasSLSABuiltByEdges, hasSLSABuiltFromEdges, hashEqualArtEdges, hashEqualSubjectArtEdges, hasSBOMPkgEdges,
			hasSBOMArtEdges, certifyVulnEdges, certifyScorecardSrcEdges, certifyBadPkgVersionEdges, certifyBadPkgNameEdges,
			certifyBadArtEdges, certifyBadSrcEdges, certifyGoodPkgVersionEdges, certifyGoodPkgNameEdges, certifyGoodArtEdges, certifyGoodSrcEdges}

		// create a graph
		graph, err = db.CreateGraphV2(ctx, "guac", &options)
		if err != nil {
			return nil, fmt.Errorf("failed to create graph: %w", err)
		}

		// TODO (pxp928): Add missing indexes for verbs as needed

		// add indexes to artifact and edge collections
		if err := createIndexPerCollection(ctx, db, artifactsStr, []string{"digest"}, true, "byDigest"); err != nil {
			return nil, fmt.Errorf("failed to generate index for artifacts: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, artifactsStr, []string{"algorithm", "digest"}, true, "byArtAndDigest"); err != nil {
			return nil, fmt.Errorf("failed to generate index for artifacts: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, buildersStr, []string{"uri"}, true, "byUri"); err != nil {
			return nil, fmt.Errorf("failed to generate index for builders: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, cvesStr, []string{"cveID"}, false, "byCveID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for cves: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, ghsasStr, []string{"ghsaID"}, false, "byGhsaID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for ghsas: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, osvsStr, []string{"osvID"}, false, "byOsvID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for osvs: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, hashEqualsStr, []string{"artifactID", "equalArtifactID"}, true, "byArtIDEqualArtID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashEquals: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgTypesStr, []string{"_parent", "type"}, true, "byPkgTypeParent"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgTypesStr, []string{"type"}, true, "byPkgType"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgNamespacesStr, []string{"namespace"}, false, "byPkgNamespace"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgNamesStr, []string{"name"}, false, "byPkgNames"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgNames: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgVersionsStr, []string{"version"}, false, "byVersion"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgVersions: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgVersionsStr, []string{"subpath"}, false, "bySubpath"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgVersions: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgVersionsStr, []string{"qualifier_list[*]"}, false, "byQualifierList"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgVersions: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcTypesStr, []string{"_parent", "type"}, true, "bySrcTypeParent"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcTypesStr, []string{"type"}, true, "bySrcType"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcNamespacesStr, []string{"namespace"}, false, "bySrcNamespace"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcNamesStr, []string{"name"}, false, "bySrcNames"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcNames: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, isDependenciesStr, []string{"packageID", "depPackageID", "versionRange", "origin"}, false, "byPkgIDDepPkgIDversionRangeOrigin"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isDependencies: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, isOccurrencesStr, []string{"packageID", "artifactID", "origin"}, true, "byPkgIDArtIDOrigin"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isOccurrences: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, hasSBOMsStr, []string{"digest"}, true, "byDigest"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSBOMs: %w", err)
		}

		// GUAC key indices for package
		if err := createIndexPerCollection(ctx, db, pkgNamespacesStr, []string{"guacKey"}, true, "byNsGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for pkgNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgNamesStr, []string{"guacKey"}, true, "byNameGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for pkgNames: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, pkgVersionsStr, []string{"guacKey"}, true, "byVersionGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for pkgVersions: %w", err)
		}

		// GUAC key indices for source
		if err := createIndexPerCollection(ctx, db, srcNamespacesStr, []string{"guacKey"}, true, "byNsGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for srcNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcNamesStr, []string{"guacKey"}, true, "byNameGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for srcNames: %w", err)
		}

		if err := createAnalyzer(ctx, db, driver.ArangoSearchAnalyzerDefinition{
			Name: "customgram",
			Type: driver.ArangoSearchAnalyzerTypeNGram,
			Properties: driver.ArangoSearchAnalyzerProperties{
				Min:              ptrfrom.Int64(4),
				Max:              ptrfrom.Int64(7),
				PreserveOriginal: ptrfrom.Bool(true),
				StreamType:       ptrfromArangoSearchNGramStreamType(driver.ArangoSearchNGramStreamBinary),
				StartMarker:      ptrfrom.String(""),
				EndMarker:        ptrfrom.String(""),
			},
			Features: []driver.ArangoSearchAnalyzerFeature{
				// required for phrase and ngram match
				driver.ArangoSearchAnalyzerFeatureFrequency,
				driver.ArangoSearchAnalyzerFeatureNorm,
				driver.ArangoSearchAnalyzerFeaturePosition,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to create analyzer customgram: %w", err)
		}

		if err := createView(ctx, db, "GuacSearch", &driver.ArangoSearchViewProperties{
			CommitInterval:        ptrfrom.Int64(10 * 60 * 1000),
			ConsolidationInterval: ptrfrom.Int64(10 * 60 * 1000),
			Links: driver.ArangoSearchLinks{
				pkgVersionsStr: driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity", "text_en", "customgram"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"guacKey": {},
					},
					InBackground: ptrfrom.Bool(true),
				},
				pkgNamesStr: driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity", "text_en", "customgram"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"guacKey": {},
					},
				},
				srcNamesStr: driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity", "text_en", "customgram"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"guacKey": {},
					},
					InBackground: ptrfrom.Bool(true),
				},
				artifactsStr: driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"digest": {},
					},
					InBackground: ptrfrom.Bool(true),
				},
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to create GuacSearch view: %w", err)
		}
	}

	collectedPkgRootData, err := preIngestPkgRoot(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create package root: %w", err)
	}

	collectedSrcRootData, err := preIngestSrcRoot(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create source root: %w", err)
	}

	arangoClient := &arangoClient{client: arangodbClient, db: db, graph: graph, pkgRoot: collectedPkgRootData, srcRoot: collectedSrcRootData}

	return arangoClient, nil
}

func createIndexPerCollection(ctx context.Context, db driver.Database, collection string, fields []string, unique bool, indexName string) error {
	databaseCollection, err := db.Collection(ctx, collection)
	if err != nil {
		return err
	}

	_, _, err = databaseCollection.EnsurePersistentIndex(ctx, fields, &driver.EnsurePersistentIndexOptions{InBackground: true, Unique: unique, CacheEnabled: true, Name: indexName})
	if err != nil {
		return err
	}
	return nil
}

func createView(ctx context.Context, db driver.Database, viewName string, opts *driver.ArangoSearchViewProperties) error {
	_, err := db.CreateArangoSearchView(ctx, viewName, opts)
	if err != nil {
		// return nil if it already exists, for now we assume that behavior
		if driver.IsConflict(err) {
			return nil
		}
		return err
	}

	return nil
}

func createAnalyzer(ctx context.Context, db driver.Database, analyzer driver.ArangoSearchAnalyzerDefinition) error {
	_, _, err := db.EnsureAnalyzer(ctx, analyzer)
	return err
}

func executeQueryWithRetry(ctx context.Context, db driver.Database, query string, values map[string]any, executedFrom string) (driver.Cursor, error) {
	var cursor driver.Cursor
	var err error
	var retryTime = retryTimer

	for retry := 0; retry < maxRetires; retry++ {
		cursor, err = db.Query(ctx, query, values)
		if err == nil {
			return cursor, nil
		}

		fmt.Printf("Retrying query (attempt %d), executed from: %s, %v, ...\n", retry+1, executedFrom, err)
		time.Sleep(retryTime + (time.Microsecond * time.Duration(rand.Intn(10))))
		retryTime *= 2
	}

	return nil, fmt.Errorf("query execution failed after %d retries", maxRetires)
}

func newForQuery(repositoryName string, counterName string) *arangoQueryBuilder {
	aqb := &arangoQueryBuilder{}

	aqb.query.WriteString(fmt.Sprintf("FOR %s IN %s", counterName, repositoryName))

	return aqb
}

func (aqb *arangoQueryBuilder) forOutBound(edgeCollectionName string, counterVertexName string, outBoundStartVertexName string) *arangoQueryBuilder {
	aqb.query.WriteString("\n")

	aqb.query.WriteString(fmt.Sprintf("FOR %s IN OUTBOUND %s %s", counterVertexName, outBoundStartVertexName, edgeCollectionName))

	return aqb
}

func (aqb *arangoQueryBuilder) forInBound(edgeCollectionName string, counterVertexName string, inBoundStartVertexName string) *arangoQueryBuilder {
	aqb.query.WriteString("\n")

	aqb.query.WriteString(fmt.Sprintf("FOR %s IN INBOUND %s %s", counterVertexName, inBoundStartVertexName, edgeCollectionName))

	return aqb
}

func (aqb *arangoQueryBuilder) forInBoundWithEdgeCounter(edgeCollectionName string, counterVertexName string, counterEdgeName string, inBoundStartVertexName string) *arangoQueryBuilder {
	aqb.query.WriteString("\n")

	aqb.query.WriteString(fmt.Sprintf("FOR %s, %s IN INBOUND %s %s", counterVertexName, counterEdgeName, inBoundStartVertexName, edgeCollectionName))

	return aqb
}

func (aqb *arangoQueryBuilder) filter(counterName string, fieldName string, condition string, value string) *arangoQueryFilter {
	aqb.query.WriteString(" ")

	aqb.query.WriteString(fmt.Sprintf("FILTER %s.%s %s %s", counterName, fieldName, condition, value))

	return newArangoQueryFilter(aqb)
}

func (aqb *arangoQueryBuilder) string() string {
	return aqb.query.String()
}

type arangoQueryFilter struct {
	arangoQueryBuilder *arangoQueryBuilder
}

func newArangoQueryFilter(queryBuilder *arangoQueryBuilder) *arangoQueryFilter {
	return &arangoQueryFilter{
		arangoQueryBuilder: queryBuilder,
	}
}

// func (aqf *arangoQueryFilter) and(fieldName string, condition string, value interface{}, counterName string) *arangoQueryFilter {
// 	aqf.arangoQueryBuilder.query.WriteString(" ")
// 	aqf.arangoQueryBuilder.query.WriteString("AND")
// 	aqf.arangoQueryBuilder.query.WriteString(" ")

// 	switch value.(type) {
// 	case string:
// 		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %q", counterName, fieldName, condition, value))
// 	default:
// 		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %v", counterName, fieldName, condition, value))
// 	}

// 	return aqf
// }

// getPreloads get the specific graphQL query fields that are requested.
// graphql.CollectAllFields only provides the top level fields and none of the nested fields below it.
// getPreloads recursively goes through the fields and retrieves each nested field below it.
// for example:
/*
  type
  namespaces {
    namespace
    names {
      name
      tag
      commit
    }
  }
  will return:
  fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.tag namespaces.names.commit]
*/
func getPreloads(ctx context.Context) []string {
	visited := make(map[string]bool)
	return getNestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"", visited)
}

func getNestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string, visited map[string]bool) []string {
	var preloads []string
	for _, column := range fields {
		prefixColumn := getPreloadString(prefix, column.Name)
		if visited[prefixColumn] {
			continue
		}
		visited[prefixColumn] = true
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads, getNestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn, visited)...)
	}
	return preloads
}

func getPreloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}
	return name
}

// Retrieval read-only queries for evidence trees

func (c *arangoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: CertifyVEXStatement - CertifyVEXStatement"))
}
func (c *arangoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	panic(fmt.Errorf("not implemented: CertifyVuln - CertifyVuln"))
}

func (c *arangoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: HasSourceAt - HasSourceAt"))
}

func (c *arangoClient) IsVulnerability(ctx context.Context, isVulnerabilitySpec *model.IsVulnerabilitySpec) ([]*model.IsVulnerability, error) {
	panic(fmt.Errorf("not implemented: IsVulnerability - IsVulnerability"))
}
func (c *arangoClient) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: PkgEqual - PkgEqual"))
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)

func (c *arangoClient) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: IngestHasSourceAt - IngestHasSourceAt"))
}
func (c *arangoClient) IngestIsVulnerability(ctx context.Context, osv model.OSVInputSpec, vulnerability model.CveOrGhsaInput, isVulnerability model.IsVulnerabilityInputSpec) (*model.IsVulnerability, error) {
	panic(fmt.Errorf("not implemented: IngestIsVulnerability - IngestIsVulnerability"))
}
func (c *arangoClient) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: IngestPkgEqual - IngestPkgEqual"))
}
func (c *arangoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: IngestVEXStatement - IngestVEXStatement"))
}
func (c *arangoClient) IngestVulnerability(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {
	panic(fmt.Errorf("not implemented: IngestVulnerability - IngestVulnerability"))
}

// Topological queries: queries where node connectivity matters more than node type
func (c *arangoClient) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Neighbors - Neighbors"))
}
func (c *arangoClient) Node(ctx context.Context, node string) (model.Node, error) {
	panic(fmt.Errorf("not implemented: Node - Node"))
}
func (c *arangoClient) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Nodes - Nodes"))
}
func (c *arangoClient) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Path - Path"))
}

func preIngestPkgRoot(ctx context.Context, db driver.Database) (*pkgRootData, error) {
	query := `
		UPSERT { root: "pkg" }
		INSERT { root: "pkg" }
		UPDATE {}
		IN pkgRoots
		RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, db, query, nil, "preIngestPkgRoot")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest package root node: %w", err)
	}

	var createdValues []pkgRootData
	for {
		var doc pkgRootData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest pkg root: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	if len(createdValues) == 1 {
		return &createdValues[0], nil
	} else {
		return nil, fmt.Errorf("number of pkg root ingested is greater than one")
	}
}

func preIngestSrcRoot(ctx context.Context, db driver.Database) (*srcRootData, error) {
	query := `
		UPSERT { root: "src" }
		INSERT { root: "src" }
		UPDATE {}
		IN srcRoots
		RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, db, query, nil, "preIngestSrcRoot")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest source root node: %w", err)
	}

	var createdValues []srcRootData
	for {
		var doc srcRootData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest src root: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	if len(createdValues) == 1 {
		return &createdValues[0], nil
	} else {
		return nil, fmt.Errorf("number of src root ingested is greater than one")
	}
}

func ptrfromArangoSearchNGramStreamType(s driver.ArangoSearchNGramStreamType) *driver.ArangoSearchNGramStreamType {
	return &s
}
