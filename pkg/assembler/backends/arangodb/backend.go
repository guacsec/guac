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

	jsoniter "github.com/json-iterator/go"

	"github.com/arangodb/go-driver"
	arangodbdriverhttp "github.com/arangodb/go-driver/http"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type ArangoConfig struct {
	User     string
	Pass     string
	DBAddr   string
	TestData bool
}

type arangoQueryBuilder struct {
	query strings.Builder
}

type arangoClient struct {
	client driver.Client
	db     driver.Database
	graph  driver.Graph
}

func init() {
	backends.Register("arango", getBackend)
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

func DeleteDatabase(ctx context.Context, args backends.BackendArgs) error {
	config, ok := args.(*ArangoConfig)
	if !ok {
		return fmt.Errorf("failed to assert arango config from backend args")
	}
	arangodbClient, err := arangoDBConnect(config.DBAddr, config.User, config.Pass)
	if err != nil {
		return fmt.Errorf("failed to connect to arango DB %s database with error: %w", config.DBAddr, err)
	}
	var db driver.Database
	// check if database exists
	dbExists, err := arangodbClient.DatabaseExists(ctx, arangoDB)
	if err != nil {
		return fmt.Errorf("failed to check %s database with error: %w", config.DBAddr, err)
	}
	if dbExists {
		db, err = arangodbClient.Database(ctx, arangoDB)
		if err != nil {
			return fmt.Errorf("failed to connect %s database with error: %w", config.DBAddr, err)
		}
		err = db.Remove(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete %s database with error: %w", config.DBAddr, err)
		}
	}
	return nil
}

func getBackend(ctx context.Context, args backends.BackendArgs) (backends.Backend, error) {
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
	dbExists, err := arangodbClient.DatabaseExists(ctx, arangoDB)
	if err != nil {
		return nil, fmt.Errorf("failed to check %s database with error: %w", config.DBAddr, err)
	}
	if dbExists {
		db, err = arangodbClient.Database(ctx, arangoDB)
		if err != nil {
			return nil, fmt.Errorf("failed to connect %s database with error: %w", config.DBAddr, err)
		}
	} else {
		// Create database
		db, err = arangodbClient.CreateDatabase(ctx, arangoDB, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create %s database with error: %w", config.DBAddr, err)
		}
	}

	var graph driver.Graph

	// check if graph exists
	graphExists, err := db.GraphExists(ctx, arangoGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to check if graph exists with error: %w", err)
	}
	if graphExists {
		graph, err = db.Graph(ctx, arangoGraph)
		if err != nil {
			return nil, fmt.Errorf("failed to get graph with error: %w", err)
		}
		err = createMissingEdgeCollection(ctx, graph, edgeDefinitions)
		if err != nil {
			return nil, fmt.Errorf("failed to get create missing edge collections: %w", err)
		}

		err = compareAndCreateIndexes(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("failed to compare with existing indexes and create new ones: %w", err)
		}

	} else {
		err := createGraph(ctx, db, arangoGraph, edgeDefinitions)
		if err != nil {
			return nil, fmt.Errorf("failed to create graph: %w", err)
		}

		// TODO (pxp928): Add missing indexes for verbs as needed

		// add indexes to artifact and edge collections
		fullCollectionIndexMap := getCollectionIndexMap()
		for collectionName, indexes := range fullCollectionIndexMap {
			for _, index := range indexes {
				createIndexPerCollection(ctx, db, collectionName, index.fields, index.unique, index.name)
			}
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
				// Only index the version string since guac files creates a lot of noise in the index
				// from the name of the file being in the subpath
				// TODO : would be a good addition to have an excludes from search field instead so files can be filtered
				pkgVersionsStr: driver.ArangoSearchElementProperties{
					Analyzers:          []string{"identity", "text_en", "customgram"},
					IncludeAllFields:   ptrfrom.Bool(false),
					TrackListPositions: ptrfrom.Bool(false),
					StoreValues:        driver.ArangoSearchStoreValuesNone,
					Fields: map[string]driver.ArangoSearchElementProperties{
						"version": {},
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

	arangoClient := &arangoClient{client: arangodbClient, db: db, graph: graph}

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

func deleteIndexPerCollection(ctx context.Context, db driver.Database, collection string, indexName string) error {
	databaseCollection, err := db.Collection(ctx, collection)
	if err != nil {
		return err
	}

	idx, err := databaseCollection.Index(ctx, indexName)
	if err != nil {
		return err
	}

	err = idx.Remove(ctx)

	return err
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

func (aqb *arangoQueryBuilder) filter(counterName string, fieldName string, condition string, value string) *arangoQueryFilter {
	aqb.query.WriteString(" ")

	aqb.query.WriteString(fmt.Sprintf("FILTER %s.%s %s %s", counterName, fieldName, condition, value))

	return newArangoQueryFilter(aqb)
}

func (aqb *arangoQueryBuilder) filterLength(counterName string, fieldName string, condition string, value int) *arangoQueryFilter {
	aqb.query.WriteString(" ")

	aqb.query.WriteString(fmt.Sprintf("FILTER LENGTH(%s.%s) %s %d", counterName, fieldName, condition, value))

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

func ptrfromArangoSearchNGramStreamType(s driver.ArangoSearchNGramStreamType) *driver.ArangoSearchNGramStreamType {
	return &s
}

func noMatch(filter *string, value string) bool {
	if filter != nil {
		return value != *filter
	}
	return false
}

func createGraph(ctx context.Context, db driver.Database, graphName string, edgeDefinitions []driver.EdgeDefinition) error {
	options := &driver.CreateGraphOptions{
		EdgeDefinitions: edgeDefinitions,
	}
	_, err := db.CreateGraphV2(ctx, graphName, options)
	if err != nil {
		return err
	}

	return nil
}

func createMissingEdgeCollection(ctx context.Context, graph driver.Graph, edgeDefinitions []driver.EdgeDefinition) error {
	fmt.Println("Checking for collection to exists ")
	for _, edgeDefination := range edgeDefinitions {
		exists, _ := graph.EdgeCollectionExists(ctx, edgeDefination.Collection)
		if !exists {
			_, err := graph.CreateEdgeCollection(ctx, edgeDefination.Collection, driver.VertexConstraints{From: edgeDefination.From, To: edgeDefination.To})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getCollectionIndexMap() map[string][]index {
	collectionIndexMap := make(map[string][]index)

	collectionIndexMap[artifactsStr] = []index{
		*(initIndex("byDigest", []string{"digest"}, true)),
		*(initIndex("byArtAndDigest", []string{"algorithm", "digest"}, true)),
	}

	collectionIndexMap[buildersStr] = []index{
		*(initIndex("byUri", []string{"uri"}, true)),
	}

	collectionIndexMap[vulnTypesStr] = []index{
		*(initIndex("byVulnType", []string{"type"}, true)),
	}

	collectionIndexMap[vulnerabilitiesStr] = []index{
		*(initIndex("byVulnID", []string{"vulnerabilityID"}, false)),
		*(initIndex("byVulnGuacKey", []string{"guacKey"}, false)),
	}

	collectionIndexMap[licensesStr] = []index{
		*(initIndex("byNameInlineListVer", []string{"name", "inline", "listversion"}, true)),
	}

	collectionIndexMap[pkgTypesStr] = []index{
		*(initIndex("byPkgType", []string{"type"}, true)),
	}

	collectionIndexMap[pkgNamespacesStr] = []index{
		*(initIndex("byPkgNamespace", []string{"namespace"}, false)),
		*(initIndex("byNsGuacKey", []string{"guacKey"}, true)),
	}

	collectionIndexMap[pkgNamesStr] = []index{
		*(initIndex("byPkgNames", []string{"name"}, false)),
		*(initIndex("byNameGuacKey", []string{"guacKey"}, true)),
	}

	collectionIndexMap[pkgVersionsStr] = []index{
		*(initIndex("byVersion", []string{"version"}, false)),
		*(initIndex("bySubpath", []string{"subpath"}, false)),
		*(initIndex("byQualifierList", []string{"qualifier_list[*]"}, false)),
		*(initIndex("byVersionGuacKey", []string{"guacKey"}, true)),
	}

	collectionIndexMap[srcTypesStr] = []index{
		*(initIndex("bySrcType", []string{"type"}, true)),
	}

	collectionIndexMap[srcNamespacesStr] = []index{
		*(initIndex("bySrcNamespace", []string{"namespace"}, false)),
		*(initIndex("byNsGuacKey", []string{"guacKey"}, true)),
	}

	collectionIndexMap[srcNamesStr] = []index{
		*(initIndex("bySrcNames", []string{"name"}, false)),
		*(initIndex("byNameGuacKey", []string{"guacKey"}, true)),
	}

	collectionIndexMap[isDependenciesStr] = []index{
		*(initIndex("byPkgIDDepPkgIDversionRangeOrigin", []string{"packageID", "depPackageID", "versionRange", "origin"}, false)),
	}

	collectionIndexMap[isOccurrencesStr] = []index{
		*(initIndex("byPkgIDArtIDOriginJust", []string{"packageID", "artifactID", "justification", "origin"}, true)),
	}

	collectionIndexMap[certifyBadsStr] = []index{
		*(initIndex("certifyBadArtifactID", []string{"artifactID", "justification", "knownSince"}, false)),
		*(initIndex("certifyBadPackageID", []string{"packageID", "justification", "knownSince"}, false)),
		*(initIndex("certifyBadSourceID", []string{"sourceID", "justification", "knownSince"}, false)),
	}

	collectionIndexMap[certifyGoodsStr] = []index{
		*(initIndex("certifyGoodArtifactID", []string{"artifactID", "justification", "knownSince"}, false)),
		*(initIndex("certifyGoodPackageID", []string{"packageID", "justification", "knownSince"}, false)),
		*(initIndex("certifyGoodSourceID", []string{"sourceID", "justification", "knownSince"}, false)),
	}

	collectionIndexMap[certifyLegalsStr] = []index{
		*(initIndex("certifyLegalPackageID", []string{"packageID", "declaredLicense", "declaredLicenses", "discoveredLicense", "discoveredLicenses", "attribution", "justification", "timeScanned", "origin"}, false)),
		*(initIndex("certifyLegalSourceID", []string{"sourceID", "declaredLicense", "declaredLicenses", "discoveredLicense", "discoveredLicenses", "attribution", "justification", "timeScanned", "origin"}, false)),
	}

	collectionIndexMap[scorecardStr] = []index{
		*(initIndex("certifyScorecard", []string{"sourceID", "checks", "aggregateScore", "timeScanned", "origin"}, true)),
	}

	collectionIndexMap[certifyVEXsStr] = []index{
		*(initIndex("certifyVexPackageID", []string{"packageID", "vulnerabilityID", "status", "vexJustification", "statement", "statusNotes", "knownSince", "origin"}, false)),
		*(initIndex("certifyVexArtifactID", []string{"artifactID", "vulnerabilityID", "status", "vexJustification", "statement", "statusNotes", "knownSince", "origin"}, false)),
	}

	collectionIndexMap[certifyVulnsStr] = []index{
		*(initIndex("certifyVuln", []string{"packageID", "vulnerabilityID", "ScannerVersion", "dbUri", "dbVersion", "scannerUri", "scannerVersion", "timeScanned", "origin"}, true)),
	}

	collectionIndexMap[hashEqualsStr] = []index{
		*(initIndex("hashEquals", []string{"artifactID", "equalArtifactID", "justification", "origin"}, true)),
	}

	collectionIndexMap[hasMetadataStr] = []index{
		*(initIndex("hashMetadataArtifactID", []string{"artifactID", "key", "value", "timestamp", "justification", "origin"}, false)),
		*(initIndex("hashMetadataPackageID", []string{"packageID", "key", "value", "timestamp", "justification", "origin"}, false)),
		*(initIndex("hashMetadataSourceID", []string{"sourceID", "key", "value", "timestamp", "justification", "origin"}, false)),
	}

	collectionIndexMap[hasSBOMsStr] = []index{
		*(initIndex("hasSbomArtifactID", []string{"artifactID", "uri", "algorithm", "digest", "knownSince", "downloadLocation", "origin"}, false)),
		*(initIndex("hasSbomPackageID", []string{"packageID", "uri", "algorithm", "digest", "knownSince", "downloadLocation", "origin"}, false)),
	}

	collectionIndexMap[hasSLSAsStr] = []index{
		*(initIndex("hasSlsa", []string{"subjectID", "builtByID", "buildType", "builtFrom", "slsaPredicate", "slsaVersion", "startedOn", "finishedOn", "origin"}, true)),
	}

	collectionIndexMap[hasSourceAtsStr] = []index{
		*(initIndex("hasSourceAt", []string{"packageID", "sourceID", "justification", "knownSince", "origin"}, true)),
	}

	collectionIndexMap[pkgEqualsStr] = []index{
		*(initIndex("pkgEqual", []string{"packageID", "equalPackageID", "justification", "origin"}, true)),
	}

	collectionIndexMap[pointOfContactStr] = []index{
		*(initIndex("pointOfContactArtifactID", []string{"artifactID", "email", "info", "since", "justification", "origin"}, false)),
		*(initIndex("pointOfContactPackageID", []string{"packageID", "email", "info", "since", "justification", "origin"}, false)),
		*(initIndex("pointOfContactSourceID", []string{"sourceID", "email", "info", "since", "justification", "origin"}, false)),
	}

	collectionIndexMap[vulnEqualsStr] = []index{
		*(initIndex("vulnEqual", []string{"vulnerabilityID", "equalVulnerabilityID", "justification", "origin"}, true)),
	}

	collectionIndexMap[vulnMetadataStr] = []index{
		*(initIndex("vulnMetadata", []string{"vulnerabilityID", "scoreType", "scoreValue", "timestamp", "origin"}, true)),
	}

	return collectionIndexMap
}

// conditionally add indexes to artifact and edge collections
func compareAndCreateIndexes(ctx context.Context, arangoDb driver.Database) error {
	fullCollectionIndexMap := getCollectionIndexMap()

	for collectionName, indexes := range fullCollectionIndexMap {
		indexExpected := make(map[string]bool)
		indexExists := make(map[string]bool)

		for _, index := range indexes {
			indexExpected[index.name] = true
		}

		// get all the existing indexes for the collection
		collection, err := arangoDb.Collection(ctx, collectionName)
		if err != nil {
			return err
		}

		existingIndexes, err := collection.Indexes(ctx)
		if err != nil {
			return err
		}

		for _, existingIndex := range existingIndexes {
			if !indexExpected[existingIndex.UserName()] {
				// TODO:: delete the outdated index
				deleteIndexPerCollection(ctx, arangoDb, collectionName, existingIndex.UserName())
			} else {
				indexExists[existingIndex.UserName()] = true
			}
		}

		for _, index := range indexes {
			// create the index if doesn't already exist
			if !indexExists[index.name] {
				createIndexPerCollection(ctx, arangoDb, collectionName, index.fields, index.unique, index.name)
			}
		}
	}

	return nil
}
