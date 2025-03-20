// Package client provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package client

import (
	"time"
)

// Defines values for AnalyzeDependenciesParamsSort.
const (
	Frequency AnalyzeDependenciesParamsSort = "frequency"
	Scorecard AnalyzeDependenciesParamsSort = "scorecard"
)

// Error defines model for Error.
type Error struct {
	Message string `json:"Message"`
}

// PackageName defines model for PackageName.
type PackageName struct {
	DependentCount int  `json:"DependentCount"`
	Name           Purl `json:"Name"`
}

// PaginationInfo Contains the cursor to retrieve more pages. If there are no more,  NextCursor will be nil.
type PaginationInfo struct {
	NextCursor *string `json:"NextCursor,omitempty"`
	TotalCount *int    `json:"TotalCount,omitempty"`
}

// Purl defines model for Purl.
type Purl = string

// ScanMetadata defines model for ScanMetadata.
type ScanMetadata struct {
	Collector      *string    `json:"collector,omitempty"`
	DbUri          *string    `json:"dbUri,omitempty"`
	DbVersion      *string    `json:"dbVersion,omitempty"`
	Origin         *string    `json:"origin,omitempty"`
	ScannerUri     *string    `json:"scannerUri,omitempty"`
	ScannerVersion *string    `json:"scannerVersion,omitempty"`
	TimeScanned    *time.Time `json:"timeScanned,omitempty"`
}

// Vulnerability defines model for Vulnerability.
type Vulnerability struct {
	Metadata      ScanMetadata         `json:"metadata"`
	Package       string               `json:"package"`
	Vulnerability VulnerabilityDetails `json:"vulnerability"`
}

// VulnerabilityDetails defines model for VulnerabilityDetails.
type VulnerabilityDetails struct {
	Type *string `json:"type,omitempty"`

	// VulnerabilityIDs A list of vulnerability identifiers. These can be CVE IDs or other  formats used to identify vulnerabilities.
	VulnerabilityIDs []string `json:"vulnerabilityIDs"`
}

// PaginationSpec defines model for PaginationSpec.
type PaginationSpec struct {
	Cursor   *string `json:"Cursor,omitempty"`
	PageSize *int    `json:"PageSize,omitempty"`
}

// BadGateway defines model for BadGateway.
type BadGateway = Error

// BadRequest defines model for BadRequest.
type BadRequest = Error

// InternalServerError defines model for InternalServerError.
type InternalServerError = Error

// PackageNameList defines model for PackageNameList.
type PackageNameList = []PackageName

// PurlList defines model for PurlList.
type PurlList struct {
	// PaginationInfo Contains the cursor to retrieve more pages. If there are no more,  NextCursor will be nil.
	PaginationInfo PaginationInfo `json:"PaginationInfo"`
	PurlList       []Purl         `json:"PurlList"`
}

// VulnerabilityList defines model for VulnerabilityList.
type VulnerabilityList = []Vulnerability

// AnalyzeDependenciesParams defines parameters for AnalyzeDependencies.
type AnalyzeDependenciesParams struct {
	// PaginationSpec The pagination configuration for the query.
	//   * 'PageSize' specifies the number of results returned
	//   * 'Cursor' is returned by previous calls and specifies what page to return
	PaginationSpec *PaginationSpec `form:"paginationSpec,omitempty" json:"paginationSpec,omitempty"`

	// Sort The sort order of the packages
	//   * 'frequency' - The packages with the highest number of dependents
	//   * 'scorecard' - The packages with the lowest OpenSSF scorecard score
	Sort AnalyzeDependenciesParamsSort `form:"sort" json:"sort"`
}

// AnalyzeDependenciesParamsSort defines parameters for AnalyzeDependencies.
type AnalyzeDependenciesParamsSort string

// GetPackageVulnsParams defines parameters for GetPackageVulns.
type GetPackageVulnsParams struct {
	// IncludeDependencies A flag to include vulnerabilities of the dependencies. If true, the  response will include vulnerabilities for the purl and its dependencies  instead of the vulnerabilities of just the purl.
	IncludeDependencies *bool `form:"includeDependencies,omitempty" json:"includeDependencies,omitempty"`
}
