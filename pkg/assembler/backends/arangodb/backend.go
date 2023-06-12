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
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	namespaces    string        = "namespaces"
	names         string        = namespaces + ".names"
	versions      string        = names + ".versions"
	cvdID         string        = "cveId"
	origin        string        = "origin"
	collector     string        = "collector"
	justification string        = "justification"
	status        string        = "status"
	statement     string        = "statement"
	statusNotes   string        = "statusNotes"
	maxRetires    int           = 20
	retryTImer    time.Duration = time.Millisecond
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

type arangoClient struct {
	client driver.Client
	db     driver.Database
	graph  driver.Graph
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
	config := args.(*ArangoConfig)
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
		// define the edgeCollection to store the edges
		var hashEqualsEdges driver.EdgeDefinition
		hashEqualsEdges.Collection = "hashEqualsEdges"
		// define a set of collections where an edge is going out...
		hashEqualsEdges.From = []string{"artifacts", "hashEquals"}

		// repeat this for the collections where an edge is going into
		hashEqualsEdges.To = []string{"artifacts", "hashEquals"}

		var pkgHasType driver.EdgeDefinition
		pkgHasType.Collection = "PkgHasType"
		// define a set of collections where an edge is going out...
		pkgHasType.From = []string{"Pkg"}

		// repeat this for the collections where an edge is going into
		pkgHasType.To = []string{"PkgType"}

		var pkgHasNamespace driver.EdgeDefinition
		pkgHasNamespace.Collection = "PkgHasNamespace"
		// define a set of collections where an edge is going out...
		pkgHasNamespace.From = []string{"PkgType"}

		// repeat this for the collections where an edge is going into
		pkgHasNamespace.To = []string{"PkgNamespace"}

		var pkgHasName driver.EdgeDefinition
		pkgHasName.Collection = "PkgHasName"
		// define a set of collections where an edge is going out...
		pkgHasName.From = []string{"PkgNamespace"}

		// repeat this for the collections where an edge is going into
		pkgHasName.To = []string{"PkgName"}

		var pkgHasVersion driver.EdgeDefinition
		pkgHasVersion.Collection = "PkgHasVersion"
		// define a set of collections where an edge is going out...
		pkgHasVersion.From = []string{"PkgName"}

		// repeat this for the collections where an edge is going into
		pkgHasVersion.To = []string{"PkgVersion"}

		var isDependencyEdges driver.EdgeDefinition
		isDependencyEdges.Collection = "isDependencyEdges"
		// define a set of collections where an edge is going out...
		isDependencyEdges.From = []string{"isDependencies", "PkgVersion"}

		// repeat this for the collections where an edge is going into
		isDependencyEdges.To = []string{"isDependencies", "PkgName"}

		var isOccurrencesEdges driver.EdgeDefinition
		isOccurrencesEdges.Collection = "isOccurrencesEdges"
		// define a set of collections where an edge is going out...
		isOccurrencesEdges.From = []string{"isOccurrences", "PkgVersion"}

		// repeat this for the collections where an edge is going into
		isOccurrencesEdges.To = []string{"isOccurrences", "artifacts"}

		var hasSBOMEdges driver.EdgeDefinition
		hasSBOMEdges.Collection = "hasSBOMEdges"
		// define a set of collections where an edge is going out...
		hasSBOMEdges.From = []string{"PkgVersion", "artifacts"}

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

		if err := createIndexPerCollection(ctx, db, "Pkg", []string{"root", "type", "namespace"}, true, "byRootTypeNamespace"); err != nil {
			return nil, fmt.Errorf("failed to generate index for Pkg: %w", err)
		}

		// if err := createIndexPerCollection(ctx, db, "PkgHasType", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
		// 	return nil, fmt.Errorf("failed to generate index for PkgHasType: %w", err)
		// }

		// if err := createIndexPerCollection(ctx, db, "PkgNamespace", []string{"namespace"}, false, "byNamespace"); err != nil {
		// 	return nil, fmt.Errorf("failed to generate index for PkgNamespace: %w", err)
		// }
		// if err := createIndexPerCollection(ctx, db, "PkgHasNamespace", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
		// 	return nil, fmt.Errorf("failed to generate index for PkgHasNamespace: %w", err)
		// }

		if err := createIndexPerCollection(ctx, db, "PkgName", []string{"name"}, false, "byName"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgName: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgHasName", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgHasName: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersion", []string{"version"}, false, "byVersion"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersion: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersion", []string{"subpath"}, false, "bySubpath"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersion: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersion", []string{"qualifier_list[*]"}, false, "byQualifierList"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersion: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgVersion", []string{"version", "subpath", "qualifier_list[*]"}, false, "byAllVersion"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgVersion: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "PkgHasVersion", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for PkgHasVersion: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isDependencies", []string{"packageID", "depPackageID"}, true, "byPkgIDDepPkgID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isDependencies: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isDependencyEdges", []string{"_from", "_to"}, true, "byFromTo"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isDependencyEdges: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, "isOccurrences", []string{"packageID", "artifactID"}, true, "byPkgIDArtID"); err != nil {
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
	}

	arangoClient := &arangoClient{arangodbClient, db, graph}
	registerAllArtifacts(ctx, arangoClient)
	registerAllPackages(ctx, arangoClient)
	if err != nil {
		return nil, err
	}
	// err = registerAllPackages(client)
	// if err != nil {
	// 	return nil, err
	// }

	// err = registerAllBuilders(client)
	// if err != nil {
	// 	return nil, err
	// }
	// err = registerAllSources(client)
	// if err != nil {
	// 	return nil, err
	// }
	// err = registerAllCVE(client)
	// if err != nil {
	// 	return nil, err
	// }
	// err = registerAllGHSA(client)
	// if err != nil {
	// 	return nil, err
	// }
	// err = registerAllOSV(client)
	// if err != nil {
	// 	return nil, err
	// }

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

func executeQueryWithRetry(ctx context.Context, db driver.Database, query string, values map[string]any, executedFrom string) (driver.Cursor, error) {
	var cursor driver.Cursor
	var err error

	for retry := 0; retry < maxRetires; retry++ {
		cursor, err = db.Query(ctx, query, values)
		if err == nil {
			return cursor, nil
		}

		// Check if the error is due to a lock timeout or a temporary issue
		//if isRetryableError(err) {
		fmt.Printf("Retrying query (attempt %d), executed from: %s, %v, ...\n", retry+1, executedFrom, err)
		time.Sleep(retryTImer)
		continue
		//}

		// Return the error if it's not retryable
		//return nil, err
	}

	return nil, fmt.Errorf("query execution failed after %d retries", maxRetires)
}

// func isRetryableError(err error) bool {
// 	// Check the error type or message to determine if it's a retryable error
// 	// For example, you can check for specific error codes or strings
// 	// from the ArangoDB driver and return true if it's a retryable error.
// 	// Customize this function based on your specific use case.
// 	return false
// }

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

func (aqb *arangoQueryBuilder) search() *arangoQuerySearch {
	aqb.query.WriteString(" ")
	aqb.query.WriteString("SEARCH")
	return newArangoQuerySearch(aqb)
}

func (aqb *arangoQueryBuilder) filter(fieldName string, counterName string, condition string, value string) *arangoQueryFilter {
	aqb.query.WriteString(" ")

	aqb.query.WriteString(fmt.Sprintf("FILTER %s.%s %s %s", counterName, fieldName, condition, value))

	return newArangoQueryFilter(aqb)
}

func (aqb *arangoQueryBuilder) lIMIT(offset int, count int) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("LIMIT %d,%d", offset, count))
	return aqb
}

func (aqb *arangoQueryBuilder) sortBM25(desc bool, counterName string) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("SORT BM25(%s)", counterName))

	if desc {
		aqb.query.WriteString(" ")
		aqb.query.WriteString("DESC")
	}

	return aqb
}

func (aqb *arangoQueryBuilder) sort(fieldName string, desc bool, counterName string) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("SORT %s.%s", counterName, fieldName))

	if desc {
		aqb.query.WriteString(" ")
		aqb.query.WriteString("DESC")
	}

	return aqb
}

func (aqb *arangoQueryBuilder) sortBM25WithFreqScaling(desc bool, k float32, b float32, counterName string) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("SORT BM25(%s, %.2f, %.2f)", counterName, k, b))

	if desc {
		aqb.query.WriteString(" ")
		aqb.query.WriteString("DESC")
	}

	return aqb
}

func (aqb *arangoQueryBuilder) returnStatement(counterName string) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("RETURN %s", counterName))
	return aqb
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

func (aqf *arangoQueryFilter) and(fieldName string, counterName string, condition string, value string) *arangoQueryFilter {
	aqf.arangoQueryBuilder.query.WriteString(" ")
	aqf.arangoQueryBuilder.query.WriteString("AND")
	aqf.arangoQueryBuilder.query.WriteString(" ")

	aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %s", counterName, fieldName, condition, value))

	return aqf
}

func (aqf *arangoQueryFilter) or(fieldName string, condition string, value interface{}, counterName string) *arangoQueryFilter {
	aqf.arangoQueryBuilder.query.WriteString(" ")
	aqf.arangoQueryBuilder.query.WriteString("OR")
	aqf.arangoQueryBuilder.query.WriteString(" ")

	switch value.(type) {
	case string:
		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %q", counterName, fieldName, condition, value))
	default:
		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %v", counterName, fieldName, condition, value))
	}
	return aqf
}

func (aqf *arangoQueryFilter) done() *arangoQueryBuilder {
	return aqf.arangoQueryBuilder
}

type arangoQuerySearch struct {
	arangoQueryBuilder *arangoQueryBuilder
}

func newArangoQuerySearch(queryBuilder *arangoQueryBuilder) *arangoQuerySearch {
	return &arangoQuerySearch{
		arangoQueryBuilder: queryBuilder,
	}
}

func (aqs *arangoQuerySearch) phrase(fieldName string, searchKeyword string, analyzer string, counterName string) *arangoQuerySearch {
	aqs.arangoQueryBuilder.query.WriteString(" ")
	aqs.arangoQueryBuilder.query.WriteString(fmt.Sprintf("PHRASE(%s.%s, %q, %q)", counterName, fieldName, searchKeyword, analyzer))
	return aqs
}

func (aqs *arangoQuerySearch) condition(fieldName string, condition string, value interface{}, counterName string) *arangoQuerySearch {
	aqs.arangoQueryBuilder.query.WriteString(" ")

	switch value.(type) {
	case string:
		aqs.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %q", counterName, fieldName, condition, value))
	default:
		aqs.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %v", counterName, fieldName, condition, value))
	}

	return aqs
}

func (aqs *arangoQuerySearch) or() *arangoQuerySearch {
	aqs.arangoQueryBuilder.query.WriteString(" ")
	aqs.arangoQueryBuilder.query.WriteString("OR")
	return aqs
}

func (aqs *arangoQuerySearch) and() *arangoQuerySearch {
	aqs.arangoQueryBuilder.query.WriteString(" ")
	aqs.arangoQueryBuilder.query.WriteString("AND")
	return aqs
}

func (aqs *arangoQuerySearch) done() *arangoQueryBuilder {
	return aqs.arangoQueryBuilder
}

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
func (c *arangoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	panic(fmt.Errorf("not implemented: Sources - Sources"))
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
	panic(fmt.Errorf("not implemented: IngestMaterials - IngestMaterials"))
}
func (c *arangoClient) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	panic(fmt.Errorf("not implemented: IngestOsv - IngestOsv"))
}
func (c *arangoClient) IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error) {
	panic(fmt.Errorf("not implemented: IngestSource - IngestSource"))
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
