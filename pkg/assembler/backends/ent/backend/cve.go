package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerability"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// type advisoryQuerySpec struct {
// 	CveID  *string
// 	GhsaID *string
// 	OsvID  *string
// 	Year   *int
// 	ID     *string
// }

// func (b *EntBackend) Cve(ctx context.Context, spec *model.VulnerabilitySpec) ([]*model.Cve, error) {
// 	results, err := getAdvisories(ctx, b.client, &advisoryQuerySpec{
// 		ID:    spec.ID,
// 		CveID: spec.CveID,
// 		Year:  spec.Year,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}

// 	return collect(results, toModelCVE), nil
// }

// func (b *EntBackend) IngestCve(ctx context.Context, spec *model.CVEInputSpec) (*model.Cve, error) {
// 	advisory, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SecurityAdvisory, error) {
// 		return upsertVulnerability(ctx, ent.TxFromContext(ctx), advisoryQuerySpec{
// 			CveID: &spec.CveID,
// 			Year:  &spec.Year,
// 		})
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return toModelCVE(advisory), nil
// }

// func toModelCVE(cve *ent.SecurityAdvisory) *model.Cve {
// 	if cve.CveID == nil {
// 		return nil
// 	}

// 	return &model.Cve{
// 		ID:    nodeID(cve.ID),
// 		CveID: *cve.CveID,
// 		Year:  *cve.CveYear,
// 	}
// }

func getVulnerability(ctx context.Context, client *ent.Client, query model.VulnerabilitySpec) (*ent.Vulnerability, error) {
	results, err := getAdvisories(ctx, client, query)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, &ent.NotFoundError{}
	}

	if len(results) > 1 {
		return nil, &ent.NotSingularError{}
	}

	return results[0], nil
}

func getAdvisories(ctx context.Context, client *ent.Client, query model.VulnerabilitySpec) (ent.Vulnerabilities, error) {
	results, err := client.Vulnerability.Query().
		Where(
			optionalPredicate(query.ID, IDEQ),
			optionalPredicate(query.Type, vulnerability.TypeEqualFold),
			optionalPredicate(query.VulnerabilityID, vulnerability.VulnerabilityIDEqualFold),
		).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// func applyGHSAMutations(mut *ent.SecurityAdvisoryMutation, spec advisoryQuerySpec) ([]string, *sql.Predicate) {
// 	mut.SetGhsaID(strings.ToLower(*spec.GhsaID))
// 	return []string{securityadvisory.FieldGhsaID}, sql.And(
// 		sql.NotNull(securityadvisory.FieldGhsaID),
// 		sql.IsNull(securityadvisory.FieldCveID),
// 		sql.IsNull(securityadvisory.FieldOsvID),
// 	)
// }

// func applyCVEMutations(mut *ent.SecurityAdvisoryMutation, spec advisoryQuerySpec) ([]string, *sql.Predicate) {
// 	mut.SetCveID(strings.ToLower(*spec.CveID))
// 	mut.SetCveYear(*spec.Year)
// 	return []string{securityadvisory.FieldCveID},
// 		sql.And(
// 			sql.IsNull(securityadvisory.FieldGhsaID),
// 			sql.NotNull(securityadvisory.FieldCveID),
// 			sql.IsNull(securityadvisory.FieldOsvID),
// 		)
// }

// func applyOSVMutations(mut *ent.SecurityAdvisoryMutation, spec advisoryQuerySpec) ([]string, *sql.Predicate) {
// 	mut.SetOsvID(strings.ToLower(*spec.OsvID))
// 	return []string{securityadvisory.FieldOsvID},
// 		sql.And(
// 			sql.IsNull(securityadvisory.FieldGhsaID),
// 			sql.IsNull(securityadvisory.FieldCveID),
// 			sql.NotNull(securityadvisory.FieldOsvID),
// 		)
// }
