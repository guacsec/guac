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

	"github.com/99designs/gqlgen/graphql"
	"github.com/arangodb/go-driver"
	arangodbdriverhttp "github.com/arangodb/go-driver/http"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	namespaces    string = "namespaces"
	names         string = namespaces + ".names"
	versions      string = names + ".versions"
	cvdID         string = "cveId"
	origin        string = "origin"
	collector     string = "collector"
	justification string = "justification"
	status        string = "status"
	statement     string = "statement"
	statusNotes   string = "statusNotes"
)

type ArangoConfig struct {
	User     string
	Pass     string
	DBAddr   string
	TestData bool
}

type arangoQueryBuilder struct {
	query       strings.Builder
	counterName string
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
		var edgeDefinition driver.EdgeDefinition
		edgeDefinition.Collection = "myEdgeCollection"
		// define a set of collections where an edge is going out...
		edgeDefinition.From = []string{"artifacts", "hasEquals"}

		// repeat this for the collections where an edge is going into
		edgeDefinition.To = []string{"artifacts", "hasEquals"}

		// A graph can contain additional vertex collections, defined in the set of orphan collections
		var options driver.CreateGraphOptions
		options.EdgeDefinitions = []driver.EdgeDefinition{edgeDefinition}

		// create a graph
		graph, err = db.CreateGraphV2(ctx, "guac", &options)
		if err != nil {
			return nil, fmt.Errorf("failed to create graph: %w", err)
		}
	}

	arangoClient := &arangoClient{arangodbClient, db, graph}
	registerAllArtifacts(ctx, arangoClient)
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

func newForQuery(repositoryName string, counterName string) *arangoQueryBuilder {
	aqb := &arangoQueryBuilder{
		counterName: counterName,
	}

	aqb.query.WriteString(fmt.Sprintf("FOR %s IN %s", aqb.counterName, repositoryName))

	return aqb
}

func (aqb *arangoQueryBuilder) search() *arangoQuerySearch {
	aqb.query.WriteString(" ")
	aqb.query.WriteString("SEARCH")
	return newArangoQuerySearch(aqb)
}

func (aqb *arangoQueryBuilder) filter(fieldName string, condition string, value interface{}) *arangoQueryFilter {
	aqb.query.WriteString(" ")

	switch value.(type) {
	case string:
		aqb.query.WriteString(fmt.Sprintf("FILTER %s.%s %s %q", aqb.counterName, fieldName, condition, value))
	default:
		aqb.query.WriteString(fmt.Sprintf("FILTER %s.%s %s %v", aqb.counterName, fieldName, condition, value))
	}

	return newArangoQueryFilter(aqb)
}

func (aqb *arangoQueryBuilder) lIMIT(offset int, count int) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("LIMIT %d,%d", offset, count))
	return aqb
}

func (aqb *arangoQueryBuilder) sortBM25(desc bool) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("SORT BM25(%s)", aqb.counterName))

	if desc {
		aqb.query.WriteString(" ")
		aqb.query.WriteString("DESC")
	}

	return aqb
}

func (aqb *arangoQueryBuilder) sort(fieldName string, desc bool) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("SORT %s.%s", aqb.counterName, fieldName))

	if desc {
		aqb.query.WriteString(" ")
		aqb.query.WriteString("DESC")
	}

	return aqb
}

func (aqb *arangoQueryBuilder) sortBM25WithFreqScaling(desc bool, k float32, b float32) *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("SORT BM25(%s, %.2f, %.2f)", aqb.counterName, k, b))

	if desc {
		aqb.query.WriteString(" ")
		aqb.query.WriteString("DESC")
	}

	return aqb
}

func (aqb *arangoQueryBuilder) returnStatement() *arangoQueryBuilder {
	aqb.query.WriteString(" ")
	aqb.query.WriteString(fmt.Sprintf("RETURN %s", aqb.counterName))
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

func (aqf *arangoQueryFilter) and(fieldName string, condition string, value interface{}) *arangoQueryFilter {
	aqf.arangoQueryBuilder.query.WriteString(" ")
	aqf.arangoQueryBuilder.query.WriteString("AND")
	aqf.arangoQueryBuilder.query.WriteString(" ")

	switch value.(type) {
	case string:
		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %q", aqf.arangoQueryBuilder.counterName, fieldName, condition, value))
	default:
		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %v", aqf.arangoQueryBuilder.counterName, fieldName, condition, value))
	}

	return aqf
}

func (aqf *arangoQueryFilter) or(fieldName string, condition string, value interface{}) *arangoQueryFilter {
	aqf.arangoQueryBuilder.query.WriteString(" ")
	aqf.arangoQueryBuilder.query.WriteString("OR")
	aqf.arangoQueryBuilder.query.WriteString(" ")

	switch value.(type) {
	case string:
		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %q", aqf.arangoQueryBuilder.counterName, fieldName, condition, value))
	default:
		aqf.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %v", aqf.arangoQueryBuilder.counterName, fieldName, condition, value))
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

func (aqs *arangoQuerySearch) phrase(fieldName string, searchKeyword string, analyzer string) *arangoQuerySearch {
	aqs.arangoQueryBuilder.query.WriteString(" ")
	aqs.arangoQueryBuilder.query.WriteString(fmt.Sprintf("PHRASE(%s.%s, %q, %q)", aqs.arangoQueryBuilder.counterName, fieldName, searchKeyword, analyzer))
	return aqs
}

func (aqs *arangoQuerySearch) condition(fieldName string, condition string, value interface{}) *arangoQuerySearch {
	aqs.arangoQueryBuilder.query.WriteString(" ")

	switch value.(type) {
	case string:
		aqs.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %q", aqs.arangoQueryBuilder.counterName, fieldName, condition, value))
	default:
		aqs.arangoQueryBuilder.query.WriteString(fmt.Sprintf("%s.%s %s %v", aqs.arangoQueryBuilder.counterName, fieldName, condition, value))
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
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}

// Retrieval read-only queries for evidence trees
func (c *arangoClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IsVulnerability(ctx context.Context, isVulnerabilitySpec *model.IsVulnerabilitySpec) ([]*model.IsVulnerability, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}

// Mutations for software trees (read-write queries)
func (c *arangoClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestCve(ctx context.Context, cve *model.CVEInputSpec) (*model.Cve, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestMaterials(ctx context.Context, materials []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
func (c *arangoClient) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestIsVulnerability(ctx context.Context, osv model.OSVInputSpec, vulnerability model.CveOrGhsaInput, isVulnerability model.IsVulnerabilityInputSpec) (*model.IsVulnerability, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) IngestVulnerability(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}

// Topological queries: queries where node connectivity matters more than node type
func (c *arangoClient) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Node(ctx context.Context, node string) (model.Node, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
func (c *arangoClient) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}
