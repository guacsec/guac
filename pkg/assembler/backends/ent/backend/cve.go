package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/securityadvisory"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Cve(ctx context.Context, spec *model.CVESpec) ([]*model.Cve, error) {
	results, err := b.client.SecurityAdvisory.Query().
		Where(
			optionalPredicate(spec.CveID, securityadvisory.CveIDEqualFold),
			optionalPredicate(spec.Year, securityadvisory.CveYearEQ),
			optionalPredicate(spec.ID, IDEQ),
		).All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(results, toModelCVE), nil
}

func (b *EntBackend) IngestCve(ctx context.Context, spec *model.CVEInputSpec) (*model.Cve, error) {
	advisory, err := WithinTX(ctx, b.client, func(context.Context) (*ent.SecurityAdvisory, error) {
		client := ent.FromContext(ctx)
		id, err := client.SecurityAdvisory.Create().
			SetCveID(strings.ToLower(spec.CveID)).
			SetCveYear(spec.Year).
			OnConflict(
				sql.ConflictColumns(securityadvisory.FieldCveID),
				sql.ConflictWhere(sql.And(
					sql.IsNull(securityadvisory.FieldGhsaID),
					sql.NotNull(securityadvisory.FieldCveID),
					sql.IsNull(securityadvisory.FieldOsvID),
				)),
			).
			Ignore().
			ID(ctx)
		if err != nil {
			return nil, err
		}
		return client.SecurityAdvisory.Get(ctx, id)
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
