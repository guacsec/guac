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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	arangoDB        string        = "guac_db"
	arangoGraph     string        = "guac"
	namespaces      string        = "namespaces"
	names           string        = namespaces + ".names"
	versions        string        = names + ".versions"
	vulnerabilityID string        = "vulnerabilityIDs"
	origin          string        = "origin"
	collector       string        = "collector"
	justification   string        = "justification"
	knownSince      string        = "knownSince"
	maxRetires      int           = 100
	retryTimer      time.Duration = time.Microsecond
	guacEmpty       string        = "guac-empty-@@"

	// Package collections
	pkgTypesStr        string = "pkgTypes"
	pkgHasNamespaceStr string = "pkgHasNamespace"
	pkgNamespacesStr   string = "pkgNamespaces"
	pkgHasNameStr      string = "pkgHasName"
	pkgHasVersionStr   string = "pkgHasVersion"
	pkgNamesStr        string = "pkgNames"
	pkgVersionsStr     string = "pkgVersions"

	// source collections
	srcTypesStr        string = "srcTypes"
	srcHasNamespaceStr string = "srcHasNamespace"
	srcNamespacesStr   string = "srcNamespaces"
	srcHasNameStr      string = "srcHasName"
	srcNamesStr        string = "srcNames"

	// builder collections

	buildersStr string = "builders"

	// artifact collection

	artifactsStr string = "artifacts"

	// vulnerabilities collection

	vulnTypesStr              string = "vulnTypes"
	vulnHasVulnerabilityIDStr string = "vulnHasVulnerabilityID"
	vulnerabilitiesStr        string = "vulnerabilities"

	// license collection

	licensesStr string = "licenses"

	// isDependency collections

	isDependencyDepPkgVersionEdgesStr string = "isDependencyDepPkgVersionEdges"
	isDependencyDepPkgNameEdgesStr    string = "isDependencyDepPkgNameEdges"
	isDependencySubjectPkgEdgesStr    string = "isDependencySubjectPkgEdges"
	isDependenciesStr                 string = "isDependencies"

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

	// hasMetadata collection

	hasMetadataPkgVersionEdgesStr string = "hasMetadataPkgVersionEdges"
	hasMetadataPkgNameEdgesStr    string = "hasMetadataPkgNameEdges"
	hasMetadataSrcEdgesStr        string = "hasMetadataSrcEdges"
	hasMetadataArtEdgesStr        string = "hasMetadataArtEdges"
	hasMetadataStr                string = "hasMetadataCollection"

	// pointOfContact collection

	pointOfContactPkgVersionEdgesStr string = "pointOfContactPkgVersionEdges"
	pointOfContactPkgNameEdgesStr    string = "pointOfContactPkgNameEdges"
	pointOfContactSrcEdgesStr        string = "pointOfContactSrcEdges"
	pointOfContactArtEdgesStr        string = "pointOfContactArtEdges"
	pointOfContactStr                string = "pointOfContacts"

	// hasSBOM collection

	hasSBOMPkgEdgesStr string = "hasSBOMPkgEdges"
	hasSBOMArtEdgesStr string = "hasSBOMArtEdges"
	hasSBOMsStr        string = "hasSBOMs"

	// hasSourceAt collection

	hasSourceAtPkgVersionEdgesStr string = "hasSourceAtPkgVersionEdges"
	hasSourceAtPkgNameEdgesStr    string = "hasSourceAtPkgNameEdges"
	hasSourceAtEdgesStr           string = "hasSourceAtEdges"
	hasSourceAtsStr               string = "hasSourceAts"

	// certifyVex collection

	certifyVexPkgEdgesStr  string = "certifyVexPkgEdges"
	certifyVexArtEdgesStr  string = "certifyVexArtEdges"
	certifyVexVulnEdgesStr string = "certifyVexVulnEdges"
	certifyVEXsStr         string = "certifyVEXs"

	// certifyVuln collection

	certifyVulnPkgEdgesStr string = "certifyVulnPkgEdges"
	certifyVulnEdgesStr    string = "certifyVulnEdges"
	certifyVulnsStr        string = "certifyVulns"

	// vulnMetadata collection

	vulnMetadataEdgesStr string = "vulnMetadataEdges"
	vulnMetadataStr      string = "vulnMetadataCollection"

	// vulnEquals collections

	vulnEqualVulnEdgesStr        string = "vulnEqualVulnEdges"
	vulnEqualSubjectVulnEdgesStr string = "vulnEqualSubjectVulnEdges"
	vulnEqualsStr                string = "vulnEquals"

	// pkgEquals collections

	pkgEqualPkgEdgesStr        string = "pkgEqualPkgEdges"
	pkgEqualSubjectPkgEdgesStr string = "pkgEqualSubjectPkgEdges"
	pkgEqualsStr               string = "pkgEquals"

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

	// certifyLegal collection

	certifyLegalPkgEdgesStr                string = "certifyLegalPkgEdges"
	certifyLegalSrcEdgesStr                string = "certifyLegalSrcEdges"
	certifyLegalDeclaredLicensesEdgesStr   string = "certifyLegalDeclaredLicensesEdges"
	certifyLegalDiscoveredLicensesEdgesStr string = "certifyLegalDiscoveredLicensesEdges"
	certifyLegalsStr                       string = "certifyLegals"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var mapEdgeToArangoEdgeCollection = map[model.Edge][]string{
	model.EdgeArtifactCertifyBad:               {certifyBadArtEdgesStr},
	model.EdgeArtifactCertifyGood:              {certifyGoodArtEdgesStr},
	model.EdgeArtifactCertifyVexStatement:      {certifyVexArtEdgesStr},
	model.EdgeArtifactHashEqual:                {hashEqualSubjectArtEdgesStr},
	model.EdgeArtifactHasMetadata:              {hasMetadataArtEdgesStr},
	model.EdgeArtifactHasSbom:                  {hasSBOMArtEdgesStr},
	model.EdgeArtifactHasSlsa:                  {hasSLSASubjectArtEdgesStr},
	model.EdgeArtifactIsOccurrence:             {isOccurrenceArtEdgesStr},
	model.EdgeArtifactPointOfContact:           {pointOfContactArtEdgesStr},
	model.EdgeBuilderHasSlsa:                   {hasSLSABuiltByEdgesStr},
	model.EdgeLicenseCertifyLegal:              {certifyLegalDeclaredLicensesEdgesStr, certifyLegalDiscoveredLicensesEdgesStr},
	model.EdgePackageCertifyBad:                {certifyBadPkgVersionEdgesStr, certifyBadPkgNameEdgesStr},
	model.EdgePackageCertifyGood:               {certifyGoodPkgVersionEdgesStr, certifyGoodPkgNameEdgesStr},
	model.EdgePackageCertifyLegal:              {certifyLegalPkgEdgesStr},
	model.EdgePackageCertifyVexStatement:       {certifyVexPkgEdgesStr},
	model.EdgePackageCertifyVuln:               {certifyVulnPkgEdgesStr},
	model.EdgePackageHasMetadata:               {hasMetadataPkgNameEdgesStr, hasMetadataPkgVersionEdgesStr},
	model.EdgePackageHasSbom:                   {hasSBOMPkgEdgesStr},
	model.EdgePackageHasSourceAt:               {hasMetadataPkgVersionEdgesStr, hasSourceAtPkgNameEdgesStr},
	model.EdgePackageIsDependency:              {isDependencySubjectPkgEdgesStr},
	model.EdgePackageIsOccurrence:              {isOccurrenceSubjectPkgEdgesStr},
	model.EdgePackageNamePackageNamespace:      {},
	model.EdgePackageNamePackageVersion:        {pkgHasVersionStr},
	model.EdgePackageNamespacePackageName:      {pkgHasNameStr},
	model.EdgePackageNamespacePackageType:      {},
	model.EdgePackageTypePackageNamespace:      {pkgHasNamespaceStr},
	model.EdgePackageVersionPackageName:        {},
	model.EdgePackagePkgEqual:                  {pkgEqualSubjectPkgEdgesStr},
	model.EdgePackagePointOfContact:            {pointOfContactPkgVersionEdgesStr, pointOfContactPkgNameEdgesStr},
	model.EdgeSourceCertifyBad:                 {certifyBadSrcEdgesStr},
	model.EdgeSourceCertifyGood:                {certifyGoodSrcEdgesStr},
	model.EdgeSourceCertifyLegal:               {certifyLegalSrcEdgesStr},
	model.EdgeSourceCertifyScorecard:           {scorecardSrcEdgesStr},
	model.EdgeSourceHasMetadata:                {hasMetadataSrcEdgesStr},
	model.EdgeSourceHasSourceAt:                {hasSourceAtEdgesStr},
	model.EdgeSourceIsOccurrence:               {isOccurrenceSubjectSrcEdgesStr},
	model.EdgeSourceNameSourceNamespace:        {},
	model.EdgeSourceNamespaceSourceName:        {srcHasNameStr},
	model.EdgeSourceNamespaceSourceType:        {},
	model.EdgeSourceTypeSourceNamespace:        {srcHasNamespaceStr},
	model.EdgeSourcePointOfContact:             {pointOfContactSrcEdgesStr},
	model.EdgeVulnerabilityCertifyVexStatement: {certifyVexVulnEdgesStr},
	model.EdgeVulnerabilityCertifyVuln:         {certifyVulnEdgesStr},
	model.EdgeVulnerabilityVulnEqual:           {vulnEqualVulnEdgesStr},
	model.EdgeVulnerabilityVulnMetadata:        {vulnMetadataEdgesStr},
	model.EdgeCertifyBadArtifact:               {certifyBadArtEdgesStr},
	model.EdgeCertifyBadPackage:                {certifyBadPkgVersionEdgesStr, certifyBadPkgNameEdgesStr},
	model.EdgeCertifyBadSource:                 {certifyBadSrcEdgesStr},
	model.EdgeCertifyGoodArtifact:              {certifyGoodArtEdgesStr},
	model.EdgeCertifyGoodPackage:               {certifyGoodPkgVersionEdgesStr, certifyGoodPkgNameEdgesStr},
	model.EdgeCertifyGoodSource:                {certifyGoodSrcEdgesStr},
	model.EdgeCertifyLegalLicense:              {certifyLegalDeclaredLicensesEdgesStr, certifyLegalDiscoveredLicensesEdgesStr},
	model.EdgeCertifyLegalPackage:              {certifyLegalsStr},
	model.EdgeCertifyScorecardSource:           {scorecardSrcEdgesStr},
	model.EdgeCertifyVexStatementArtifact:      {certifyVexArtEdgesStr},
	model.EdgeCertifyVexStatementPackage:       {certifyVexPkgEdgesStr},
	model.EdgeCertifyVexStatementVulnerability: {certifyVexVulnEdgesStr},
	model.EdgeCertifyVulnPackage:               {certifyVulnPkgEdgesStr},
	model.EdgeCertifyVulnVulnerability:         {certifyVulnsStr},
	model.EdgeHashEqualArtifact:                {hashEqualArtEdgesStr},
	model.EdgeHasMetadataArtifact:              {hasMetadataArtEdgesStr},
	model.EdgeHasMetadataPackage:               {hasMetadataPkgVersionEdgesStr, hasMetadataPkgNameEdgesStr},
	model.EdgeHasMetadataSource:                {hasMetadataSrcEdgesStr},
	model.EdgeHasSbomArtifact:                  {hasSBOMArtEdgesStr},
	model.EdgeHasSbomPackage:                   {hasSBOMPkgEdgesStr},
	model.EdgeHasSlsaBuiltBy:                   {hasSLSABuiltByEdgesStr},
	model.EdgeHasSlsaMaterials:                 {hasSLSABuiltFromEdgesStr},
	model.EdgeHasSlsaSubject:                   {hasSLSASubjectArtEdgesStr},
	model.EdgeHasSourceAtPackage:               {hasSourceAtPkgVersionEdgesStr, hasSourceAtPkgNameEdgesStr},
	model.EdgeHasSourceAtSource:                {hasSourceAtEdgesStr},
	model.EdgeIsDependencyPackage:              {isDependencyDepPkgVersionEdgesStr, isDependencyDepPkgNameEdgesStr},
	model.EdgeIsOccurrenceArtifact:             {isOccurrenceArtEdgesStr},
	model.EdgeIsOccurrencePackage:              {isOccurrenceSubjectPkgEdgesStr},
	model.EdgeIsOccurrenceSource:               {isOccurrenceSubjectSrcEdgesStr},
	model.EdgePkgEqualPackage:                  {pkgEqualPkgEdgesStr},
	model.EdgePointOfContactArtifact:           {pointOfContactArtEdgesStr},
	model.EdgePointOfContactPackage:            {pointOfContactPkgVersionEdgesStr, pointOfContactPkgNameEdgesStr},
	model.EdgePointOfContactSource:             {pointOfContactSrcEdgesStr},
	model.EdgeVulnEqualVulnerability:           {vulnEqualVulnEdgesStr},
	model.EdgeVulnerabilityIDVulnerabilityType: {},
	model.EdgeVulnerabilityTypeVulnerabilityID: {vulnHasVulnerabilityIDStr},
	model.EdgeVulnMetadataVulnerability:        {vulnMetadataEdgesStr},
}

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

func deleteDatabase(ctx context.Context, args backends.BackendArgs) error {
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
	} else {

		// setup package collections
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
		var srcHasNamespace driver.EdgeDefinition
		srcHasNamespace.Collection = srcHasNamespaceStr
		srcHasNamespace.From = []string{srcTypesStr}
		srcHasNamespace.To = []string{srcNamespacesStr}

		var srcHasName driver.EdgeDefinition
		srcHasName.Collection = srcHasNameStr
		srcHasName.From = []string{srcNamespacesStr}
		srcHasName.To = []string{srcNamesStr}

		// setup vulnerability collections
		var vulnHasVulnerabilityID driver.EdgeDefinition
		vulnHasVulnerabilityID.Collection = vulnHasVulnerabilityIDStr
		vulnHasVulnerabilityID.From = []string{vulnTypesStr}
		vulnHasVulnerabilityID.To = []string{vulnerabilitiesStr}

		// setup isDependency collections
		var isDependencySubjectPkgEdges driver.EdgeDefinition
		isDependencySubjectPkgEdges.Collection = isDependencySubjectPkgEdgesStr
		isDependencySubjectPkgEdges.From = []string{pkgVersionsStr}
		isDependencySubjectPkgEdges.To = []string{isDependenciesStr}

		var isDependencyDepPkgVersionEdges driver.EdgeDefinition
		isDependencyDepPkgVersionEdges.Collection = isDependencyDepPkgVersionEdgesStr
		isDependencyDepPkgVersionEdges.From = []string{isDependenciesStr}
		isDependencyDepPkgVersionEdges.To = []string{pkgVersionsStr}

		var isDependencyDepPkgNameEdges driver.EdgeDefinition
		isDependencyDepPkgNameEdges.Collection = isDependencyDepPkgNameEdgesStr
		isDependencyDepPkgNameEdges.From = []string{isDependenciesStr}
		isDependencyDepPkgNameEdges.To = []string{pkgNamesStr}

		// setup isOccurrence collections
		var isOccurrenceArtEdges driver.EdgeDefinition
		isOccurrenceArtEdges.Collection = isOccurrenceArtEdgesStr
		isOccurrenceArtEdges.From = []string{isOccurrencesStr}
		isOccurrenceArtEdges.To = []string{artifactsStr}

		var isOccurrenceSubjectPkgEdges driver.EdgeDefinition
		isOccurrenceSubjectPkgEdges.Collection = isOccurrenceSubjectPkgEdgesStr
		isOccurrenceSubjectPkgEdges.From = []string{pkgVersionsStr}
		isOccurrenceSubjectPkgEdges.To = []string{isOccurrencesStr}

		var isOccurrenceSubjectSrcEdges driver.EdgeDefinition
		isOccurrenceSubjectSrcEdges.Collection = isOccurrenceSubjectSrcEdgesStr
		isOccurrenceSubjectSrcEdges.From = []string{srcNamesStr}
		isOccurrenceSubjectSrcEdges.To = []string{isOccurrencesStr}

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

		// setup hasMetadata collections
		var hasMetadataPkgVersionEdges driver.EdgeDefinition
		hasMetadataPkgVersionEdges.Collection = hasMetadataPkgVersionEdgesStr
		hasMetadataPkgVersionEdges.From = []string{pkgVersionsStr}
		hasMetadataPkgVersionEdges.To = []string{hasMetadataStr}

		var hasMetadataPkgNameEdges driver.EdgeDefinition
		hasMetadataPkgNameEdges.Collection = hasMetadataPkgNameEdgesStr
		hasMetadataPkgNameEdges.From = []string{pkgNamesStr}
		hasMetadataPkgNameEdges.To = []string{hasMetadataStr}

		var hasMetadataArtEdges driver.EdgeDefinition
		hasMetadataArtEdges.Collection = hasMetadataArtEdgesStr
		hasMetadataArtEdges.From = []string{artifactsStr}
		hasMetadataArtEdges.To = []string{hasMetadataStr}

		var hasMetadataSrcEdges driver.EdgeDefinition
		hasMetadataSrcEdges.Collection = hasMetadataSrcEdgesStr
		hasMetadataSrcEdges.From = []string{srcNamesStr}
		hasMetadataSrcEdges.To = []string{hasMetadataStr}

		// setup pointOfContact collections
		var pointOfContactPkgVersionEdges driver.EdgeDefinition
		pointOfContactPkgVersionEdges.Collection = pointOfContactPkgVersionEdgesStr
		pointOfContactPkgVersionEdges.From = []string{pkgVersionsStr}
		pointOfContactPkgVersionEdges.To = []string{pointOfContactStr}

		var pointOfContactPkgNameEdges driver.EdgeDefinition
		pointOfContactPkgNameEdges.Collection = pointOfContactPkgNameEdgesStr
		pointOfContactPkgNameEdges.From = []string{pkgNamesStr}
		pointOfContactPkgNameEdges.To = []string{pointOfContactStr}

		var pointOfContactArtEdges driver.EdgeDefinition
		pointOfContactArtEdges.Collection = pointOfContactArtEdgesStr
		pointOfContactArtEdges.From = []string{artifactsStr}
		pointOfContactArtEdges.To = []string{pointOfContactStr}

		var pointOfContactSrcEdges driver.EdgeDefinition
		pointOfContactSrcEdges.Collection = pointOfContactSrcEdgesStr
		pointOfContactSrcEdges.From = []string{srcNamesStr}
		pointOfContactSrcEdges.To = []string{pointOfContactStr}

		// setup hasSBOM collections
		var hasSBOMPkgEdges driver.EdgeDefinition
		hasSBOMPkgEdges.Collection = hasSBOMPkgEdgesStr
		hasSBOMPkgEdges.From = []string{pkgVersionsStr}
		hasSBOMPkgEdges.To = []string{hasSBOMsStr}

		var hasSBOMArtEdges driver.EdgeDefinition
		hasSBOMArtEdges.Collection = hasSBOMArtEdgesStr
		hasSBOMArtEdges.From = []string{artifactsStr}
		hasSBOMArtEdges.To = []string{hasSBOMsStr}

		// setup hasSourceAt collections
		var hasSourceAtPkgVersionEdges driver.EdgeDefinition
		hasSourceAtPkgVersionEdges.Collection = hasSourceAtPkgVersionEdgesStr
		hasSourceAtPkgVersionEdges.From = []string{pkgVersionsStr}
		hasSourceAtPkgVersionEdges.To = []string{hasSourceAtsStr}

		var hasSourceAtPkgNameEdges driver.EdgeDefinition
		hasSourceAtPkgNameEdges.Collection = hasSourceAtPkgNameEdgesStr
		hasSourceAtPkgNameEdges.From = []string{pkgNamesStr}
		hasSourceAtPkgNameEdges.To = []string{hasSourceAtsStr}

		var hasSourceAtEdges driver.EdgeDefinition
		hasSourceAtEdges.Collection = hasSourceAtEdgesStr
		hasSourceAtEdges.From = []string{hasSourceAtsStr}
		hasSourceAtEdges.To = []string{srcNamesStr}

		// setup certifyVex collections
		var certifyVexPkgEdges driver.EdgeDefinition
		certifyVexPkgEdges.Collection = certifyVexPkgEdgesStr
		certifyVexPkgEdges.From = []string{pkgVersionsStr}
		certifyVexPkgEdges.To = []string{certifyVEXsStr}

		var certifyVexArtEdges driver.EdgeDefinition
		certifyVexArtEdges.Collection = certifyVexArtEdgesStr
		certifyVexArtEdges.From = []string{artifactsStr}
		certifyVexArtEdges.To = []string{certifyVEXsStr}

		var certifyVexVulnEdges driver.EdgeDefinition
		certifyVexVulnEdges.Collection = certifyVexVulnEdgesStr
		certifyVexVulnEdges.From = []string{certifyVEXsStr}
		certifyVexVulnEdges.To = []string{vulnerabilitiesStr}

		// setup certifyVuln collections
		var certifyVulnPkgEdges driver.EdgeDefinition
		certifyVulnPkgEdges.Collection = certifyVulnPkgEdgesStr
		certifyVulnPkgEdges.From = []string{pkgVersionsStr}
		certifyVulnPkgEdges.To = []string{certifyVulnsStr}

		var certifyVulnEdges driver.EdgeDefinition
		certifyVulnEdges.Collection = certifyVulnEdgesStr
		certifyVulnEdges.From = []string{certifyVulnsStr}
		certifyVulnEdges.To = []string{vulnerabilitiesStr}

		// setup vulnMetadata collections
		var vulnMetadataEdges driver.EdgeDefinition
		vulnMetadataEdges.Collection = vulnMetadataEdgesStr
		vulnMetadataEdges.From = []string{vulnerabilitiesStr}
		vulnMetadataEdges.To = []string{vulnMetadataStr}

		// setup vulnEqual collections
		var vulnEqualVulnEdges driver.EdgeDefinition
		vulnEqualVulnEdges.Collection = vulnEqualVulnEdgesStr
		vulnEqualVulnEdges.From = []string{vulnEqualsStr}
		vulnEqualVulnEdges.To = []string{vulnerabilitiesStr}

		var vulnEqualSubjectVulnEdges driver.EdgeDefinition
		vulnEqualSubjectVulnEdges.Collection = vulnEqualSubjectVulnEdgesStr
		vulnEqualSubjectVulnEdges.From = []string{vulnerabilitiesStr}
		vulnEqualSubjectVulnEdges.To = []string{vulnEqualsStr}

		// setup pkgEqual collections
		var pkgEqualPkgEdges driver.EdgeDefinition
		pkgEqualPkgEdges.Collection = pkgEqualPkgEdgesStr
		pkgEqualPkgEdges.From = []string{pkgEqualsStr}
		pkgEqualPkgEdges.To = []string{pkgVersionsStr}

		var pkgEqualSubjectPkgEdges driver.EdgeDefinition
		pkgEqualSubjectPkgEdges.Collection = pkgEqualSubjectPkgEdgesStr
		pkgEqualSubjectPkgEdges.From = []string{pkgVersionsStr}
		pkgEqualSubjectPkgEdges.To = []string{pkgEqualsStr}

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
		certifyGoodPkgNameEdges.From = []string{pkgNamesStr}
		certifyGoodPkgNameEdges.To = []string{certifyGoodsStr}

		var certifyGoodArtEdges driver.EdgeDefinition
		certifyGoodArtEdges.Collection = certifyGoodArtEdgesStr
		certifyGoodArtEdges.From = []string{artifactsStr}
		certifyGoodArtEdges.To = []string{certifyGoodsStr}

		var certifyGoodSrcEdges driver.EdgeDefinition
		certifyGoodSrcEdges.Collection = certifyGoodSrcEdgesStr
		certifyGoodSrcEdges.From = []string{srcNamesStr}
		certifyGoodSrcEdges.To = []string{certifyGoodsStr}

		// setup certifyLegal collections
		var certifyLegalPkgEdges driver.EdgeDefinition
		certifyLegalPkgEdges.Collection = certifyLegalPkgEdgesStr
		certifyLegalPkgEdges.From = []string{pkgVersionsStr}
		certifyLegalPkgEdges.To = []string{certifyLegalsStr}

		var certifyLegalSrcEdges driver.EdgeDefinition
		certifyLegalSrcEdges.Collection = certifyLegalSrcEdgesStr
		certifyLegalSrcEdges.From = []string{srcNamesStr}
		certifyLegalSrcEdges.To = []string{certifyLegalsStr}

		var certifyLegalDeclaredLicensesEdges driver.EdgeDefinition
		certifyLegalDeclaredLicensesEdges.Collection = certifyLegalDeclaredLicensesEdgesStr
		certifyLegalDeclaredLicensesEdges.From = []string{certifyLegalsStr}
		certifyLegalDeclaredLicensesEdges.To = []string{licensesStr}

		var certifyLegalDiscoveredLicensesEdges driver.EdgeDefinition
		certifyLegalDiscoveredLicensesEdges.Collection = certifyLegalDiscoveredLicensesEdgesStr
		certifyLegalDiscoveredLicensesEdges.From = []string{certifyLegalsStr}
		certifyLegalDiscoveredLicensesEdges.To = []string{licensesStr}

		// A graph can contain additional vertex collections, defined in the set of orphan collections
		var options driver.CreateGraphOptions
		options.EdgeDefinitions = []driver.EdgeDefinition{pkgHasNamespace, pkgHasName,
			pkgHasVersion, srcHasNamespace, srcHasName, vulnHasVulnerabilityID, isDependencyDepPkgVersionEdges, isDependencyDepPkgNameEdges, isDependencySubjectPkgEdges,
			isOccurrenceArtEdges, isOccurrenceSubjectPkgEdges, isOccurrenceSubjectSrcEdges, hasSLSASubjectArtEdges,
			hasSLSABuiltByEdges, hasSLSABuiltFromEdges, hashEqualArtEdges, hashEqualSubjectArtEdges, hasSBOMPkgEdges,
			hasSBOMArtEdges, certifyVulnPkgEdges, certifyVulnEdges, certifyScorecardSrcEdges, certifyBadPkgVersionEdges, certifyBadPkgNameEdges,
			certifyBadArtEdges, certifyBadSrcEdges, certifyGoodPkgVersionEdges, certifyGoodPkgNameEdges, certifyGoodArtEdges, certifyGoodSrcEdges,
			certifyVexPkgEdges, certifyVexArtEdges, certifyVexVulnEdges, vulnMetadataEdges, vulnEqualVulnEdges, vulnEqualSubjectVulnEdges,
			pkgEqualPkgEdges, pkgEqualSubjectPkgEdges, hasMetadataPkgVersionEdges, hasMetadataPkgNameEdges,
			hasMetadataArtEdges, hasMetadataSrcEdges, pointOfContactPkgVersionEdges, pointOfContactPkgNameEdges,
			pointOfContactArtEdges, pointOfContactSrcEdges, hasSourceAtEdges, hasSourceAtPkgVersionEdges, hasSourceAtPkgNameEdges,
			certifyLegalPkgEdges, certifyLegalSrcEdges, certifyLegalDeclaredLicensesEdges, certifyLegalDiscoveredLicensesEdges}

		// create a graph
		graph, err = db.CreateGraphV2(ctx, arangoGraph, &options)
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

		if err := createIndexPerCollection(ctx, db, vulnTypesStr, []string{"type"}, true, "byVulnType"); err != nil {
			return nil, fmt.Errorf("failed to generate index for vulnTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, vulnerabilitiesStr, []string{"vulnerabilityID"}, false, "byVulnID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for vulnerabilities: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, licensesStr, []string{"name", "inline", "listversion"}, true, "byNameInlineListVer"); err != nil {
			return nil, fmt.Errorf("failed to generate index for licenses: %w", err)
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

		if err := createIndexPerCollection(ctx, db, srcTypesStr, []string{"type"}, true, "bySrcType"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcTypes: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcNamespacesStr, []string{"namespace"}, false, "bySrcNamespace"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcNamespaces: %w", err)
		}

		if err := createIndexPerCollection(ctx, db, srcNamesStr, []string{"name"}, false, "bySrcNames"); err != nil {
			return nil, fmt.Errorf("failed to generate index for srcNames: %w", err)
		}

		// index for isDependency
		if err := createIndexPerCollection(ctx, db, isDependenciesStr, []string{"packageID", "depPackageID", "versionRange", "origin"}, false, "byPkgIDDepPkgIDversionRangeOrigin"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isDependencies: %w", err)
		}

		// index for isOccurrence
		if err := createIndexPerCollection(ctx, db, isOccurrencesStr, []string{"packageID", "artifactID", "justification", "origin"}, true, "byPkgIDArtIDOriginJust"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isOccurrences: %w", err)
		}

		// index for certifyBad - Artifact
		if err := createIndexPerCollection(ctx, db, certifyBadsStr, []string{"artifactID", "justification", "knownSince"}, false, "certifyBadArtifactID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyBad: %w", err)
		}

		// index for certifyBad - Package
		if err := createIndexPerCollection(ctx, db, certifyBadsStr, []string{"packageID", "justification", "knownSince"}, false, "certifyBadPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyBad: %w", err)
		}

		// index for certifyBad - Source
		if err := createIndexPerCollection(ctx, db, certifyBadsStr, []string{"sourceID", "justification", "knownSince"}, false, "certifyBadSourceID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyBad: %w", err)
		}

		// index for certifyGood - Artifact
		if err := createIndexPerCollection(ctx, db, certifyGoodsStr, []string{"artifactID", "justification", "knownSince"}, false, "certifyGoodArtifactID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyGood: %w", err)
		}

		// index for certifyGood - Package
		if err := createIndexPerCollection(ctx, db, certifyGoodsStr, []string{"packageID", "justification", "knownSince"}, false, "certifyGoodPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyGood: %w", err)
		}

		// index for certifyGood - Source
		if err := createIndexPerCollection(ctx, db, certifyGoodsStr, []string{"sourceID", "justification", "knownSince"}, false, "certifyGoodSourceID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyGood: %w", err)
		}

		// index for certifyLegal - Package
		if err := createIndexPerCollection(ctx, db, certifyLegalsStr, []string{"packageID", "declaredLicense", "declaredLicenses", "discoveredLicense", "discoveredLicenses", "attribution", "justification", "timeScanned", "origin"}, false, "certifyLegalPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyLegal: %w", err)
		}

		// index for certifyLegal - Source
		if err := createIndexPerCollection(ctx, db, certifyLegalsStr, []string{"sourceID", "declaredLicense", "declaredLicenses", "discoveredLicense", "discoveredLicenses", "attribution", "justification", "timeScanned", "origin"}, false, "certifyLegalSourceID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isOccurrences: %w", err)
		}

		// index for certifyScorecard
		if err := createIndexPerCollection(ctx, db, scorecardStr, []string{"sourceID", "checks", "aggregateScore", "timeScanned", "origin"}, true, "certifyScorecard"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyScorecard: %w", err)
		}

		// index for certifyVex - Package
		if err := createIndexPerCollection(ctx, db, certifyVEXsStr, []string{"packageID", "vulnerabilityID", "status", "vexJustification", "statement", "statusNotes", "knownSince", "origin"}, false, "certifyVexPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyVex: %w", err)
		}

		// index for certifyVex - Artifact
		if err := createIndexPerCollection(ctx, db, certifyVEXsStr, []string{"artifactID", "vulnerabilityID", "status", "vexJustification", "statement", "statusNotes", "knownSince", "origin"}, false, "certifyVexArtifactID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for isOccurrences: %w", err)
		}

		// index for certifyVuln
		if err := createIndexPerCollection(ctx, db, certifyVulnsStr, []string{"packageID", "vulnerabilityID", "ScannerVersion", "dbUri", "dbVersion", "scannerUri", "scannerVersion", "timeScanned", "origin"}, true, "certifyVuln"); err != nil {
			return nil, fmt.Errorf("failed to generate index for certifyVuln: %w", err)
		}

		// index for hashEquals
		if err := createIndexPerCollection(ctx, db, hashEqualsStr, []string{"artifactID", "equalArtifactID", "justification", "origin"}, true, "hashEquals"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashEquals: %w", err)
		}

		// index for hashMetadata - Artifact
		if err := createIndexPerCollection(ctx, db, hasMetadataStr, []string{"artifactID", "key", "value", "timestamp", "justification", "origin"}, false, "hashMetadataArtifactID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashMetadata: %w", err)
		}

		// index for hashMetadata - Package
		if err := createIndexPerCollection(ctx, db, hasMetadataStr, []string{"packageID", "key", "value", "timestamp", "justification", "origin"}, false, "hashMetadataPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashMetadata: %w", err)
		}

		// index for hashMetadata - Source
		if err := createIndexPerCollection(ctx, db, hasMetadataStr, []string{"sourceID", "key", "value", "timestamp", "justification", "origin"}, false, "hashMetadataSourceID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hashMetadata: %w", err)
		}

		// index for hasSbom - Artifact
		if err := createIndexPerCollection(ctx, db, hasSBOMsStr, []string{"artifactID", "uri", "algorithm", "digest", "knownSince", "downloadLocation", "origin"}, false, "hasSbomArtifactID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSbom: %w", err)
		}

		// index for hasSbom - Package
		if err := createIndexPerCollection(ctx, db, hasSBOMsStr, []string{"packageID", "uri", "algorithm", "digest", "knownSince", "downloadLocation", "origin"}, false, "hasSbomPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSbom: %w", err)
		}

		// index for hasSlsa
		if err := createIndexPerCollection(ctx, db, hasSLSAsStr, []string{"subjectID", "builtByID", "buildType", "builtFrom", "slsaPredicate", "slsaVersion", "startedOn", "finishedOn", "origin"}, true, "hasSlsa"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSlsa: %w", err)
		}

		// index for hasSourceAt
		if err := createIndexPerCollection(ctx, db, hasSourceAtsStr, []string{"packageID", "sourceID", "justification", "knownSince", "origin"}, true, "hasSourceAt"); err != nil {
			return nil, fmt.Errorf("failed to generate index for hasSourceAt: %w", err)
		}

		// index for pkgEqual
		if err := createIndexPerCollection(ctx, db, pkgEqualsStr, []string{"packageID", "equalPackageID", "justification", "origin"}, true, "pkgEqual"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pkgEqual: %w", err)
		}

		// index for pointOfContact - Artifact
		if err := createIndexPerCollection(ctx, db, pointOfContactStr, []string{"artifactID", "email", "info", "since", "justification", "origin"}, false, "pointOfContactArtifactID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pointOfContact: %w", err)
		}

		// index for pointOfContact - Package
		if err := createIndexPerCollection(ctx, db, pointOfContactStr, []string{"packageID", "email", "info", "since", "justification", "origin"}, false, "pointOfContactPackageID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pointOfContact: %w", err)
		}

		// index for pointOfContact - Source
		if err := createIndexPerCollection(ctx, db, pointOfContactStr, []string{"sourceID", "email", "info", "since", "justification", "origin"}, false, "pointOfContactSourceID"); err != nil {
			return nil, fmt.Errorf("failed to generate index for pointOfContact: %w", err)
		}

		// index for vulnEqual
		if err := createIndexPerCollection(ctx, db, vulnEqualsStr, []string{"vulnerabilityID", "equalVulnerabilityID", "justification", "origin"}, true, "vulnEqual"); err != nil {
			return nil, fmt.Errorf("failed to generate index for vulnEqual: %w", err)
		}

		// index for vulnMetadata
		if err := createIndexPerCollection(ctx, db, vulnMetadataStr, []string{"vulnerabilityID", "scoreType", "scoreValue", "timestamp", "origin"}, true, "vulnMetadata"); err != nil {
			return nil, fmt.Errorf("failed to generate index for vulnMetadata: %w", err)
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

		// GUAC key indices for vulnerabilities
		if err := createIndexPerCollection(ctx, db, vulnerabilitiesStr, []string{"guacKey"}, false, "byVulnGuacKey"); err != nil {
			return nil, fmt.Errorf("failed to generate index for vulnerabilities: %w", err)
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
