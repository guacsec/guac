package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.36

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestVulnEqual is the resolver for the ingestVulnEqual field.
func (r *mutationResolver) IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (string, error) {
	funcName := "IngestVulnEqual"
	err := helper.ValidateNoVul(vulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	err = helper.ValidateVulnerabilityIDInputSpec(vulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	err = helper.ValidateNoVul(otherVulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	err = helper.ValidateVulnerabilityIDInputSpec(otherVulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase
	ingestedVulnEqual, err := r.Backend.IngestVulnEqual(ctx,
		model.VulnerabilityInputSpec{Type: strings.ToLower(vulnerability.Type), VulnerabilityID: strings.ToLower(vulnerability.VulnerabilityID)},
		model.VulnerabilityInputSpec{Type: strings.ToLower(otherVulnerability.Type), VulnerabilityID: strings.ToLower(otherVulnerability.VulnerabilityID)},
		vulnEqual)
	if err != nil {
		return "", err
	}
	return ingestedVulnEqual.ID, err
}

// VulnEqual is the resolver for the vulnEqual field.
func (r *queryResolver) VulnEqual(ctx context.Context, vulnEqualSpec model.VulnEqualSpec) ([]*model.VulnEqual, error) {
	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase

	if vulnEqualSpec.Vulnerabilities != nil && len(vulnEqualSpec.Vulnerabilities) > 2 {
		return nil, gqlerror.Errorf("VulnEqual :: cannot specify more than 2 vulnerabilities in VulnEqual")
	}

	if len(vulnEqualSpec.Vulnerabilities) > 0 {
		var lowercaseVulnFilterList []*model.VulnerabilitySpec
		for _, v := range vulnEqualSpec.Vulnerabilities {
			var typeLowerCase *string = nil
			var vulnIDLowerCase *string = nil
			if v.Type != nil {
				lower := strings.ToLower(*v.Type)
				typeLowerCase = &lower
			}
			if v.VulnerabilityID != nil {
				lower := strings.ToLower(*v.VulnerabilityID)
				vulnIDLowerCase = &lower
			}

			lowercaseVulnFilter := model.VulnerabilitySpec{
				ID:              v.ID,
				Type:            typeLowerCase,
				VulnerabilityID: vulnIDLowerCase,
				NoVuln:          v.NoVuln,
			}
			lowercaseVulnFilterList = append(lowercaseVulnFilterList, &lowercaseVulnFilter)
		}

		lowercaseVulnEqualFilter := model.VulnEqualSpec{
			ID:              vulnEqualSpec.ID,
			Vulnerabilities: lowercaseVulnFilterList,
			Justification:   vulnEqualSpec.Justification,
			Origin:          vulnEqualSpec.Origin,
			Collector:       vulnEqualSpec.Collector,
		}
		return r.Backend.VulnEqual(ctx, &lowercaseVulnEqualFilter)
	} else {
		return r.Backend.VulnEqual(ctx, &vulnEqualSpec)
	}
}
