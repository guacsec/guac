package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.36

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestVulnerabilityMetadata is the resolver for the ingestVulnerabilityMetadata field.
func (r *mutationResolver) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase
	return r.Backend.IngestVulnerabilityMetadata(ctx,
		model.VulnerabilityInputSpec{Type: strings.ToLower(vulnerability.Type), VulnerabilityID: strings.ToLower(vulnerability.VulnerabilityID)}, vulnerabilityMetadata)
}

// IngestVulnerabilityMetadatas is the resolver for the ingestVulnerabilityMetadatas field.
func (r *mutationResolver) IngestVulnerabilityMetadatas(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, vulnerabilityMetadatas []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase
	var lowercaseVulnInputList []*model.VulnerabilityInputSpec
	for _, v := range vulnerabilities {
		lowercaseVulnInput := model.VulnerabilityInputSpec{
			Type:            strings.ToLower(v.Type),
			VulnerabilityID: strings.ToLower(v.VulnerabilityID),
		}
		lowercaseVulnInputList = append(lowercaseVulnInputList, &lowercaseVulnInput)
	}
	return r.Backend.IngestVulnerabilityMetadatas(ctx, lowercaseVulnInputList, vulnerabilityMetadatas)
}

// VulnerabilityMetadata is the resolver for the vulnerabilityMetadata field.
func (r *queryResolver) VulnerabilityMetadata(ctx context.Context, vulnerabilityMetadataSpec model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {
	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase

	if vulnerabilityMetadataSpec.Comparator != nil && vulnerabilityMetadataSpec.ScoreValue == nil {
		return []*model.VulnerabilityMetadata{}, gqlerror.Errorf("comparator cannot be set without a score value specified")
	}

	if vulnerabilityMetadataSpec.Vulnerability != nil {

		if vulnerabilityMetadataSpec.Vulnerability.NoVuln != nil && !*vulnerabilityMetadataSpec.Vulnerability.NoVuln {
			if vulnerabilityMetadataSpec.Vulnerability.Type != nil && *vulnerabilityMetadataSpec.Vulnerability.Type == "novuln" {
				return []*model.VulnerabilityMetadata{}, gqlerror.Errorf("novuln boolean set to false, cannot specify vulnerability type to be novuln")
			}
		}

		lowercaseVulnFilter := model.VulnerabilitySpec{
			ID:              vulnerabilityMetadataSpec.Vulnerability.ID,
			Type:            toLower(vulnerabilityMetadataSpec.Vulnerability.Type),
			VulnerabilityID: toLower(vulnerabilityMetadataSpec.Vulnerability.VulnerabilityID),
			NoVuln:          vulnerabilityMetadataSpec.Vulnerability.NoVuln,
		}

		lowercaseVulnerabilityMetadataSpec := model.VulnerabilityMetadataSpec{
			ID:            vulnerabilityMetadataSpec.ID,
			Vulnerability: &lowercaseVulnFilter,
			ScoreType:     vulnerabilityMetadataSpec.ScoreType,
			ScoreValue:    vulnerabilityMetadataSpec.ScoreValue,
			Comparator:    vulnerabilityMetadataSpec.Comparator,
			Timestamp:     vulnerabilityMetadataSpec.Timestamp,
			Origin:        vulnerabilityMetadataSpec.Origin,
			Collector:     vulnerabilityMetadataSpec.Collector,
		}
		return r.Backend.VulnerabilityMetadata(ctx, &lowercaseVulnerabilityMetadataSpec)
	} else {
		return r.Backend.VulnerabilityMetadata(ctx, &vulnerabilityMetadataSpec)
	}
}
