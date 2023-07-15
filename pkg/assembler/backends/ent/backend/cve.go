package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/securityadvisory"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type advisoryQuerySpec struct {
	CveID  *string
	GhsaID *string
	OsvID  *string
	Year   *int
	ID     *string
}

func (b *EntBackend) Cve(ctx context.Context, spec *model.CVESpec) ([]*model.Cve, error) {
	results, err := getAdvisories(ctx, b.client, &advisoryQuerySpec{
		ID:    spec.ID,
		CveID: spec.CveID,
		Year:  spec.Year,
	})
	if err != nil {
		return nil, err
	}

	return collect(results, toModelCVE), nil
}

func (b *EntBackend) IngestCve(ctx context.Context, spec *model.CVEInputSpec) (*model.Cve, error) {
	advisory, err := WithinTX(ctx, b.client, func(context.Context) (*ent.SecurityAdvisory, error) {
		return upsertAdvisory(ctx, ent.TxFromContext(ctx), advisoryQuerySpec{
			CveID: &spec.CveID,
			Year:  &spec.Year,
		})
	})
	if err != nil {
		return nil, err
	}
	return toModelCVE(advisory), nil
}

func toModelCVE(cve *ent.SecurityAdvisory) *model.Cve {
	if cve.CveID == nil {
		return nil
	}

	return &model.Cve{
		ID:    nodeID(cve.ID),
		CveID: *cve.CveID,
		Year:  *cve.CveYear,
	}
}

func getAdvisory(ctx context.Context, client *ent.Client, query *advisoryQuerySpec) (*ent.SecurityAdvisory, error) {
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

func getAdvisories(ctx context.Context, client *ent.Client, query *advisoryQuerySpec) (ent.SecurityAdvisories, error) {
	results, err := client.SecurityAdvisory.Query().
		Where(
			optionalPredicate(query.CveID, securityadvisory.CveIDEqualFold),
			optionalPredicate(query.GhsaID, securityadvisory.GhsaIDEqualFold),
			optionalPredicate(query.OsvID, securityadvisory.OsvIDEqualFold),
			optionalPredicate(query.Year, securityadvisory.CveYearEQ),
			optionalPredicate(query.ID, IDEQ),
		).All(ctx)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func upsertAdvisory(ctx context.Context, client *ent.Tx, spec advisoryQuerySpec) (*ent.SecurityAdvisory, error) {
	insert := client.SecurityAdvisory.Create()

	columns := []string{}
	var uniqueConstraint *sql.Predicate
	switch {
	case spec.GhsaID != nil:
		columns, uniqueConstraint = applyGHSAMutations(insert.Mutation(), spec)
	case spec.CveID != nil:
		columns, uniqueConstraint = applyCVEMutations(insert.Mutation(), spec)
	case spec.OsvID != nil:
		columns, uniqueConstraint = applyOSVMutations(insert.Mutation(), spec)
	}

	id, err := insert.
		OnConflict(
			sql.ConflictColumns(columns...),
			sql.ConflictWhere(uniqueConstraint),
		).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, err
	}
	return client.SecurityAdvisory.Get(ctx, id)
}

func applyGHSAMutations(mut *ent.SecurityAdvisoryMutation, spec advisoryQuerySpec) ([]string, *sql.Predicate) {
	mut.SetGhsaID(strings.ToLower(*spec.GhsaID))
	return []string{securityadvisory.FieldGhsaID}, sql.And(
		sql.NotNull(securityadvisory.FieldGhsaID),
		sql.IsNull(securityadvisory.FieldCveID),
		sql.IsNull(securityadvisory.FieldOsvID),
	)
}

func applyCVEMutations(mut *ent.SecurityAdvisoryMutation, spec advisoryQuerySpec) ([]string, *sql.Predicate) {
	mut.SetCveID(strings.ToLower(*spec.CveID))
	mut.SetCveYear(*spec.Year)
	return []string{securityadvisory.FieldCveID},
		sql.And(
			sql.IsNull(securityadvisory.FieldGhsaID),
			sql.NotNull(securityadvisory.FieldCveID),
			sql.IsNull(securityadvisory.FieldOsvID),
		)
}

func applyOSVMutations(mut *ent.SecurityAdvisoryMutation, spec advisoryQuerySpec) ([]string, *sql.Predicate) {
	mut.SetOsvID(strings.ToLower(*spec.OsvID))
	return []string{securityadvisory.FieldOsvID},
		sql.And(
			sql.IsNull(securityadvisory.FieldGhsaID),
			sql.IsNull(securityadvisory.FieldCveID),
			sql.NotNull(securityadvisory.FieldOsvID),
		)
}
