package arangodb

import (
	"time"

	"github.com/arangodb/go-driver"
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
	hasSBOMPkgEdgesStr                 string = "hasSBOMPkgEdges"
	hasSBOMArtEdgesStr                 string = "hasSBOMArtEdges"
	hasSBOMIncludedSoftwarePkgEdgesStr string = "hasSBOMIncludedSoftwarePkgEdges"
	hasSBOMIncludedSoftwareArtEdgesStr string = "hasSBOMIncludedSoftwareArtEdges"
	hasSBOMIncludedDependencyEdgesStr  string = "hasSBOMIncludedDependencyEdges"
	hasSBOMIncludedOccurrenceEdgesStr  string = "hasSBOMIncludedOccurrenceEdges"
	hasSBOMsStr                        string = "hasSBOMs"

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
	model.EdgeHasSbomIncludedSoftware:          {hasSBOMIncludedSoftwarePkgEdgesStr, hasMetadataArtEdgesStr},
	model.EdgeHasSbomIncludedDependencies:      {hasSBOMIncludedDependencyEdgesStr},
	model.EdgeHasSbomIncludedOccurrences:       {hasSBOMIncludedOccurrenceEdgesStr},
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

var edgeDefinitions = []driver.EdgeDefinition{

	// setup package collections
	{Collection: pkgHasNamespaceStr, From: []string{pkgTypesStr}, To: []string{pkgNamespacesStr}},
	{Collection: pkgHasNameStr, From: []string{pkgNamespacesStr}, To: []string{pkgNamesStr}},
	{Collection: pkgHasVersionStr, From: []string{pkgNamesStr}, To: []string{pkgVersionsStr}},

	// setup source collections
	{Collection: srcHasNamespaceStr, From: []string{srcTypesStr}, To: []string{srcNamespacesStr}},
	{Collection: srcHasNameStr, From: []string{srcNamespacesStr}, To: []string{srcNamesStr}},

	// setup vulnerability collections
	{Collection: vulnHasVulnerabilityIDStr, From: []string{vulnTypesStr}, To: []string{vulnerabilitiesStr}},

	// setup isDependency collections
	{Collection: isDependencySubjectPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{isDependenciesStr}},
	{Collection: isDependencyDepPkgVersionEdgesStr, From: []string{isDependenciesStr}, To: []string{pkgVersionsStr}},
	{Collection: isDependencyDepPkgNameEdgesStr, From: []string{isDependenciesStr}, To: []string{pkgNamesStr}},

	// setup isOccurrence collections
	{Collection: isOccurrenceArtEdgesStr, From: []string{isOccurrencesStr}, To: []string{artifactsStr}},
	{Collection: isOccurrenceSubjectPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{isOccurrencesStr}},
	{Collection: isOccurrenceSubjectSrcEdgesStr, From: []string{srcNamesStr}, To: []string{isOccurrencesStr}},

	// setup hasSLSA collections
	{Collection: hasSLSASubjectArtEdgesStr, From: []string{artifactsStr}, To: []string{hasSLSAsStr}},
	{Collection: hasSLSABuiltByEdgesStr, From: []string{hasSLSAsStr}, To: []string{buildersStr}},
	{Collection: hasSLSABuiltFromEdgesStr, From: []string{hasSLSAsStr}, To: []string{artifactsStr}},

	// setup hashEqual collections
	{Collection: hashEqualArtEdgesStr, From: []string{hashEqualsStr}, To: []string{artifactsStr}},
	{Collection: hashEqualSubjectArtEdgesStr, From: []string{artifactsStr}, To: []string{hashEqualsStr}},

	// setup hasMetadata collections
	{Collection: hasMetadataPkgVersionEdgesStr, From: []string{pkgVersionsStr}, To: []string{hasMetadataStr}},
	{Collection: hasMetadataPkgNameEdgesStr, From: []string{pkgNamesStr}, To: []string{hasMetadataStr}},
	{Collection: hasMetadataArtEdgesStr, From: []string{artifactsStr}, To: []string{hasMetadataStr}},
	{Collection: hasMetadataSrcEdgesStr, From: []string{srcNamesStr}, To: []string{hasMetadataStr}},

	// setup pointOfContact collections
	{Collection: pointOfContactPkgVersionEdgesStr, From: []string{pkgVersionsStr}, To: []string{pointOfContactStr}},
	{Collection: pointOfContactPkgNameEdgesStr, From: []string{pkgNamesStr}, To: []string{pointOfContactStr}},
	{Collection: pointOfContactArtEdgesStr, From: []string{artifactsStr}, To: []string{pointOfContactStr}},
	{Collection: pointOfContactSrcEdgesStr, From: []string{srcNamesStr}, To: []string{pointOfContactStr}},

	// setup hasSBOM collections
	{Collection: hasSBOMPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{hasSBOMsStr}},
	{Collection: hasSBOMArtEdgesStr, From: []string{artifactsStr}, To: []string{hasSBOMsStr}},
	{Collection: hasSBOMIncludedSoftwarePkgEdgesStr, From: []string{hasSBOMsStr}, To: []string{pkgVersionsStr}},
	{Collection: hasSBOMIncludedSoftwareArtEdgesStr, From: []string{hasSBOMsStr}, To: []string{artifactsStr}},
	{Collection: hasSBOMIncludedDependencyEdgesStr, From: []string{hasSBOMsStr}, To: []string{isDependenciesStr}},
	{Collection: hasSBOMIncludedOccurrenceEdgesStr, From: []string{hasSBOMsStr}, To: []string{isOccurrencesStr}},

	// setup hasSourceAt collections
	{Collection: hasSourceAtPkgVersionEdgesStr, From: []string{pkgVersionsStr}, To: []string{hasSourceAtsStr}},
	{Collection: hasSourceAtPkgNameEdgesStr, From: []string{pkgNamesStr}, To: []string{hasSourceAtsStr}},
	{Collection: hasSourceAtEdgesStr, From: []string{hasSourceAtsStr}, To: []string{srcNamesStr}},

	// setup certifyVex collections
	{Collection: certifyVexPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{certifyVEXsStr}},
	{Collection: certifyVexArtEdgesStr, From: []string{artifactsStr}, To: []string{certifyVEXsStr}},
	{Collection: certifyVexVulnEdgesStr, From: []string{certifyVEXsStr}, To: []string{vulnerabilitiesStr}},

	// setup certifyVuln collections
	{Collection: certifyVulnPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{certifyVulnsStr}},
	{Collection: certifyVulnEdgesStr, From: []string{certifyVulnsStr}, To: []string{vulnerabilitiesStr}},

	// setup vulnMetadata collections
	{Collection: vulnMetadataEdgesStr, From: []string{vulnerabilitiesStr}, To: []string{vulnMetadataStr}},

	// setup vulnEqual collections
	{Collection: vulnEqualVulnEdgesStr, From: []string{vulnEqualsStr}, To: []string{vulnerabilitiesStr}},
	{Collection: vulnEqualSubjectVulnEdgesStr, From: []string{vulnerabilitiesStr}, To: []string{vulnEqualsStr}},

	// setup pkgEqual collections
	{Collection: pkgEqualPkgEdgesStr, From: []string{pkgEqualsStr}, To: []string{pkgVersionsStr}},
	{Collection: pkgEqualSubjectPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{pkgEqualsStr}},

	// setup certifyScorecard collections
	{Collection: scorecardSrcEdgesStr, From: []string{srcNamesStr}, To: []string{scorecardStr}},

	// setup certifyBad collections
	{Collection: certifyBadPkgVersionEdgesStr, From: []string{pkgVersionsStr}, To: []string{certifyBadsStr}},
	{Collection: certifyBadPkgNameEdgesStr, From: []string{pkgNamesStr}, To: []string{certifyBadsStr}},
	{Collection: certifyBadArtEdgesStr, From: []string{artifactsStr}, To: []string{certifyBadsStr}},
	{Collection: certifyBadSrcEdgesStr, From: []string{srcNamesStr}, To: []string{certifyBadsStr}},

	// setup certifyGood collections
	{Collection: certifyGoodPkgVersionEdgesStr, From: []string{pkgVersionsStr}, To: []string{certifyGoodsStr}},
	{Collection: certifyGoodPkgNameEdgesStr, From: []string{pkgNamesStr}, To: []string{certifyGoodsStr}},
	{Collection: certifyGoodArtEdgesStr, From: []string{artifactsStr}, To: []string{certifyGoodsStr}},
	{Collection: certifyGoodSrcEdgesStr, From: []string{srcNamesStr}, To: []string{certifyGoodsStr}},

	// setup certifyLegal collections
	{Collection: certifyLegalPkgEdgesStr, From: []string{pkgVersionsStr}, To: []string{certifyLegalsStr}},
	{Collection: certifyLegalSrcEdgesStr, From: []string{srcNamesStr}, To: []string{certifyLegalsStr}},
	{Collection: certifyLegalDeclaredLicensesEdgesStr, From: []string{certifyLegalsStr}, To: []string{licensesStr}},
	{Collection: certifyLegalDiscoveredLicensesEdgesStr, From: []string{certifyLegalsStr}, To: []string{licensesStr}},
}
