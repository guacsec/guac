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
	maxRetires    int           = 20
	retryTImer    time.Duration = time.Microsecond
	guacEmpty     string        = "guac-empty-@@"
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

type pkgTypeData struct {
	Key     string `json:"_key"`
	Id      string `json:"_id"`
	PkgType string `json:"type"`
}

type srcRootData struct {
	Key     string `json:"_key"`
	Id      string `json:"_id"`
	SrcRoot string `json:"root"`
}

type srcTypeData struct {
	Key     string `json:"_key"`
	Id      string `json:"_id"`
	SrcType string `json:"type"`
}

type arangoClient struct {
	client     driver.Client
	db         driver.Database
	graph      driver.Graph
	pkgRoot    *pkgRootData
	pkgTypeMap map[string]*pkgTypeData
	srcRoot    *srcRootData
	srcTypeMap map[string]*srcTypeData
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
		pkgHasType.Collection = "PkgHasType"
		// define a set of collections where an edge is going out...
		pkgHasType.From = []string{"PkgRoots"}

		// repeat this for the collections where an edge is going into
		pkgHasType.To = []string{"PkgTypes"}

		var pkgHasNamespace driver.EdgeDefinition
		pkgHasNamespace.Collection = "PkgHasNamespace"
		// define a set of collections where an edge is going out...
		pkgHasNamespace.From = []string{"PkgTypes"}

		// repeat this for the collections where an edge is going into
		pkgHasNamespace.To = []string{"PkgNamespaces"}

		var pkgHasName driver.EdgeDefinition
		pkgHasName.Collection = "PkgHasName"
		// define a set of collections where an edge is going out...
		pkgHasName.From = []string{"PkgNamespaces"}

		// repeat this for the collections where an edge is going into
		pkgHasName.To = []string{"PkgNames"}

		var pkgHasVersion driver.EdgeDefinition
		pkgHasVersion.Collection = "PkgHasVersion"
		// define a set of collections where an edge is going out...
		pkgHasVersion.From = []string{"PkgNames"}

		// repeat this for the collections where an edge is going into
		pkgHasVersion.To = []string{"PkgVersions"}

		// setup source collections
		var srcHasType driver.EdgeDefinition
		srcHasType.Collection = "SrcHasType"
		// define a set of collections where an edge is going out...
		srcHasType.From = []string{"SrcRoots"}

		// repeat this for the collections where an edge is going into
		srcHasType.To = []string{"SrcTypes"}

		var srcHasNamespace driver.EdgeDefinition
		srcHasNamespace.Collection = "SrcHasNamespace"
		// define a set of collections where an edge is going out...
		srcHasNamespace.From = []string{"SrcTypes"}

		// repeat this for the collections where an edge is going into
		srcHasNamespace.To = []string{"SrcNamespaces"}

		var srcHasName driver.EdgeDefinition
		srcHasName.Collection = "SrcHasName"
		// define a set of collections where an edge is going out...
		srcHasName.From = []string{"SrcNamespaces"}

		// repeat this for the collections where an edge is going into
		pkgHasName.To = []string{"SrcNames"}

		var isDependencyEdges driver.EdgeDefinition
		isDependencyEdges.Collection = "isDependencyEdges"
		// define a set of collections where an edge is going out...
		isDependencyEdges.From = []string{"isDependencies", "PkgVersions"}

		// repeat this for the collections where an edge is going into
		isDependencyEdges.To = []string{"isDependencies", "PkgNames"}

		var isOccurrencesEdges driver.EdgeDefinition
		isOccurrencesEdges.Collection = "isOccurrencesEdges"
		// define a set of collections where an edge is going out...
		isOccurrencesEdges.From = []string{"isOccurrences", "PkgVersions"}

		// repeat this for the collections where an edge is going into
		isOccurrencesEdges.To = []string{"isOccurrences", "artifacts"}

		// define the edgeCollection to store the edges
		var hashEqualsEdges driver.EdgeDefinition
		hashEqualsEdges.Collection = "hashEqualsEdges"
		// define a set of collections where an edge is going out...
		hashEqualsEdges.From = []string{"artifacts", "hashEquals"}

		// repeat this for the collections where an edge is going into
		hashEqualsEdges.To = []string{"artifacts", "hashEquals"}

		var hasSBOMEdges driver.EdgeDefinition
		hasSBOMEdges.Collection = "hasSBOMEdges"
		// define a set of collections where an edge is going out...
		hasSBOMEdges.From = []string{"PkgVersions", "artifacts"}

		// repeat this for the collections where an edge is going into
		hasSBOMEdges.To = []string{"hasSBOMs"}

		// A graph can contain additional vertex collections, defined in the set of orphan collections
		var options driver.CreateGraphOptions
		options.EdgeDefinitions = []driver.EdgeDefinition{hashEqualsEdges, pkgHasType, pkgHasNamespace, pkgHasName, pkgHasVersion, isDependencyEdges, isOccurrencesEdges, hasSBOMEdges}

		// create a graph
		graph, err = db.CreateGraphV2(ctx, "guac", &options)
		if err != nil {
			return nil, fmt.Errorf("failed to create graph: %w", err)
		}

		// add indexes to artifact and edge collections
		if err := createIndexPerCollection(ctx, db, "artifacts", []string{"digest"}, true, "byDigest"); err != nil {
			return nil, fmt.Errorf("failed to generate index for artifacts: %w", err)
		}
		if err := createIndexPerCollection(ctx, db, "artifacts", []string{"algorithm", "digest"}, true, "byArtAndDigest"); err != nil {
			return nil, fmt.Errorf("failed to generate index for artifacts: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "hashEquals", []string{"artifactID", "equalArtifactID"}, true, "byArtIDEqualArtID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashEquals: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "hashEqualsEdges", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashEqualsEdges: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgTypes", []string{"_parent", "type"}, true, "byPkgTypeParent"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgTypes", []string{"type"}, true, "byPkgType"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgNamespaces", []string{"namespace"}, false, "byPkgNamespace"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgNamespace: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgNames", []string{"name"}, false, "byPkgNames"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgName: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgHasType", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgHasType: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgHasNamespace", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgHasNamespace: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgHasName", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgHasName: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersions", []string{"version"}, false, "byVersion"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersions: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersions", []string{"subpath"}, false, "bySubpath"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersions: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersions", []string{"qualifier_list[*]"}, false, "byQualifierList"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersions: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgHasVersion", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgHasVersion: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcTypes", []string{"_parent", "type"}, true, "bySrcTypeParent"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcTypes", []string{"type"}, true, "bySrcType"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcNamespaces", []string{"namespace"}, false, "bySrcNamespace"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcNames", []string{"name"}, false, "bySrcNames"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcNames: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcHasType", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcHasType: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcHasNamespace", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcHasNamespace: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcHasName", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for SrcHasName: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isDependencies", []string{"packageID", "depPackageID", "origin"}, true, "byPkgIDDepPkgIDOrigin"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isDependencies: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isDependencyEdges", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isDependencyEdges: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isOccurrences", []string{"packageID", "artifactID", "origin"}, true, "byPkgIDArtIDOrigin"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isOccurrences: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isOccurrencesEdges", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isOccurrencesEdges: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "hasSBOMs", []string{"digest"}, true, "byDigest"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSBOMs: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "hasSBOMEdges", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSBOMEdges: %w", err)
		}

		// GUAC key indices for package
		if err := createIndexPerCollection(ctx, db, "PkgNamespaces", []string{"guacKey"}, true, "byNsGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for PkgNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgNames", []string{"guacKey"}, true, "byNameGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for PkgNames: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersions", []string{"guacKey"}, true, "byVersionGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for PkgVersions: %w", err)
		}

		// GUAC key indices for source
		if err := createIndexPerCollection(ctx, db, "SrcNamespaces", []string{"guacKey"}, true, "byNsGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for SrcNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "SrcNames", []string{"guacKey"}, true, "byNameGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate guackey index for SrcNames: %w", err)
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
			Links: driver.ArangoSearchLinks{
				"PkgVersions": driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity", "text_en", "customgram"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"guacKey": {},
					},
				},
				"PkgNames": driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity", "text_en", "customgram"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"guacKey": {},
					},
				},
				"artifacts": driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"digest": {},
					},
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
	ingestPkgTypes := []string{"pypi", "conan", "guac", "deb", "maven", "alpine", "golang"}
	collectedPkgTypes, err := preIngestPkgTypes(ctx, db, collectedPkgRootData, ingestPkgTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to create package types: %w", err)
	}

	collectedSrcRootData, err := preIngestSrcRoot(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create source root: %w", err)
	}
	ingestSrcTypes := []string{"git"}
	collectedSrcTypes, err := preIngestSrcTypes(ctx, db, collectedSrcRootData, ingestSrcTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to create source types: %w", err)
	}

	arangoClient := &arangoClient{client: arangodbClient, db: db, graph: graph, pkgRoot: collectedPkgRootData, pkgTypeMap: collectedPkgTypes, srcRoot: collectedSrcRootData, srcTypeMap: collectedSrcTypes}

	return arangoClient, nil
}

func createIndexPerCollection(ctx context.Context, db driver.Database, collection string, fields []string, unique bool, indexName string) error {
	databaseCollection, err := db.Collection(ctx, collection)
	if err != nil {
		return err
	}

	_, _, err = databaseCollection.EnsurePersistentIndex(ctx, fields, &driver.EnsurePersistentIndexOptions{Unique: unique, CacheEnabled: true, Name: indexName})
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

	for retry := 0; retry < maxRetires; retry++ {
		cursor, err = db.Query(ctx, query, values)
		if err == nil {
			return cursor, nil
		}

		fmt.Printf("Retrying query (attempt %d), executed from: %s, %v, ...\n", retry+1, executedFrom, err)
		time.Sleep(retryTImer)
	}

	return nil, fmt.Errorf("query execution failed after %d retries", maxRetires)
}

func newForQuery(repositoryName string, counterName string) *arangoQueryBuilder {
	aqb := &arangoQueryBuilder{}

	aqb.query.WriteString(fmt.Sprintf("FOR %s IN %s", counterName, repositoryName))

	return aqb
}

func (aqb *arangoQueryBuilder) ForOutBound(edgeCollectionName string, counterName string, outBoundValueName string) *arangoQueryBuilder {
	aqb.query.WriteString("\n")
	aqb.query.WriteString(fmt.Sprintf("FOR %s IN OUTBOUND %s %s", counterName, outBoundValueName, edgeCollectionName))
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
	preloads := []string{}
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

func (c *arangoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	panic(fmt.Errorf("not implemented: Builders - Builders"))
}
func (c *arangoClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	panic(fmt.Errorf("not implemented: Cve - Cve"))
}
func (c *arangoClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: Ghsa - Ghsa"))
}
func (c *arangoClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	panic(fmt.Errorf("not implemented: Osv - Osv"))
}

// Retrieval read-only queries for evidence trees
func (c *arangoClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	panic(fmt.Errorf("not implemented: CertifyBad - CertifyBad"))
}
func (c *arangoClient) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	panic(fmt.Errorf("not implemented: CertifyGood - CertifyGood"))
}
func (c *arangoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: CertifyVEXStatement - CertifyVEXStatement"))
}
func (c *arangoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	panic(fmt.Errorf("not implemented: CertifyVuln - CertifyVuln"))
}

func (c *arangoClient) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: HasSlsa - HasSlsa"))
}
func (c *arangoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: HasSourceAt - HasSourceAt"))
}
func (c *arangoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	panic(fmt.Errorf("not implemented: IsDependency - IsDependency"))
}
func (c *arangoClient) IsVulnerability(ctx context.Context, isVulnerabilitySpec *model.IsVulnerabilitySpec) ([]*model.IsVulnerability, error) {
	panic(fmt.Errorf("not implemented: IsVulnerability - IsVulnerability"))
}
func (c *arangoClient) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: PkgEqual - PkgEqual"))
}
func (c *arangoClient) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	panic(fmt.Errorf("not implemented: Scorecards - Scorecards"))
}

// Mutations for software trees (read-write queries)
func (c *arangoClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	panic(fmt.Errorf("not implemented: IngestBuilder - IngestBuilder"))
}
func (c *arangoClient) IngestCve(ctx context.Context, cve *model.CVEInputSpec) (*model.Cve, error) {
	panic(fmt.Errorf("not implemented: IngestCve - IngestCve"))
}
func (c *arangoClient) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: IngestGhsa - IngestGhsa"))
}
func (c *arangoClient) IngestMaterials(ctx context.Context, materials []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	return nil, nil
}
func (c *arangoClient) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	panic(fmt.Errorf("not implemented: IngestOsv - IngestOsv"))
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
func (c *arangoClient) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	return &model.CertifyScorecard{}, nil
}
func (c *arangoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	panic(fmt.Errorf("not implemented: IngestCertifyBad - IngestCertifyBad"))
}
func (c *arangoClient) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
	panic(fmt.Errorf("not implemented: IngestCertifyGood - IngestCertifyGood"))
}

func (c *arangoClient) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: IngestHasSourceAt - IngestHasSourceAt"))
}
func (c *arangoClient) IngestIsVulnerability(ctx context.Context, osv model.OSVInputSpec, vulnerability model.CveOrGhsaInput, isVulnerability model.IsVulnerabilityInputSpec) (*model.IsVulnerability, error) {
	panic(fmt.Errorf("not implemented: IngestIsVulnerability - IngestIsVulnerability"))
}
func (c *arangoClient) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: IngestPkgEqual - IngestPkgEqual"))
}
func (c *arangoClient) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: IngestSLSA - IngestSLSA"))
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
		IN PkgRoots
		RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, db, query, nil, "preIngestPkgRoot")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
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

func preIngestPkgTypes(ctx context.Context, db driver.Database, pkgRoot *pkgRootData, pkgTypes []string) (map[string]*pkgTypeData, error) {
	collectedPkgTypes := map[string]*pkgTypeData{}
	for _, pkgType := range pkgTypes {
		values := map[string]any{}
		values["pkgType"] = pkgType
		values["rootID"] = pkgRoot.Id
		values["rootKey"] = pkgRoot.Key
		query := `
		  LET type = FIRST(
			UPSERT { type: @pkgType, _parent: @rootID }
			INSERT { type: @pkgType, _parent: @rootID }
			UPDATE {}
			IN PkgTypes OPTIONS { indexHint: "byPkgTypeParent" }
			RETURN NEW
		  )
	
		  LET pkgHasTypeCollection = (
			INSERT { _key: CONCAT("pkgHasType", @rootKey, type._key), _from: @rootID, _to: type._id, label : "PkgHasType" } INTO PkgHasType OPTIONS { overwriteMode: "ignore" }
		  )
	
		RETURN {
		"type": type.type,
		"_id": type._id,
		"_key": type._key
		}`

		cursor, err := executeQueryWithRetry(ctx, db, query, values, "preIngestPkgTypes")
		if err != nil {
			return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
		}

		var createdValues []pkgTypeData
		for {
			var doc pkgTypeData
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					cursor.Close()
					break
				} else {
					return nil, fmt.Errorf("failed to ingest package type: %w", err)
				}
			} else {
				createdValues = append(createdValues, doc)
			}
		}
		if len(createdValues) == 1 {
			collectedPkgTypes[createdValues[0].PkgType] = &createdValues[0]
		} else {
			return nil, fmt.Errorf("number of package types is greater than one")
		}
	}
	return collectedPkgTypes, nil
}

func preIngestSrcRoot(ctx context.Context, db driver.Database) (*srcRootData, error) {
	query := `
		UPSERT { root: "src" }
		INSERT { root: "src" }
		UPDATE {}
		IN SrcRoots
		RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, db, query, nil, "preIngestSrcRoot")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
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

func preIngestSrcTypes(ctx context.Context, db driver.Database, srcRoot *srcRootData, srcTypes []string) (map[string]*srcTypeData, error) {
	collectedSrcTypes := map[string]*srcTypeData{}
	for _, srcType := range srcTypes {
		values := map[string]any{}
		values["srcType"] = srcType
		values["rootID"] = srcRoot.Id
		values["rootKey"] = srcRoot.Key
		query := `
		  LET type = FIRST(
			UPSERT { type: @srcType, _parent: @rootID }
			INSERT { type: @srcType, _parent: @rootID }
			UPDATE {}
			IN SrcTypes OPTIONS { indexHint: "byType" }
			RETURN NEW
		  )
	
		  LET pkgHasTypeCollection = (
			INSERT { _key: CONCAT("srcHasType", @rootKey, type._key), _from: @rootID, _to: type._id, label : "SrcHasType" } INTO SrcHasType OPTIONS { overwriteMode: "ignore" }
		  )
	
		RETURN {
		"type": type.type,
		"_id": type._id,
		"_key": type._key
		}`

		cursor, err := executeQueryWithRetry(ctx, db, query, values, "preIngestPkgTypes")
		if err != nil {
			return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
		}

		var createdValues []srcTypeData
		for {
			var doc srcTypeData
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					cursor.Close()
					break
				} else {
					return nil, fmt.Errorf("failed to ingest source type: %w", err)
				}
			} else {
				createdValues = append(createdValues, doc)
			}
		}
		if len(createdValues) == 1 {
			collectedSrcTypes[createdValues[0].SrcType] = &createdValues[0]
		} else {
			return nil, fmt.Errorf("number of source type ingested is greater than one")
		}
	}
	return collectedSrcTypes, nil
}

func ptrfromArangoSearchNGramStreamType(s driver.ArangoSearchNGramStreamType) *driver.ArangoSearchNGramStreamType {
	return &s
}
