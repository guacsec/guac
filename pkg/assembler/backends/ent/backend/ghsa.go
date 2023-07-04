package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/securityadvisory"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Ghsa(ctx context.Context, spec *model.GHSASpec) ([]*model.Ghsa, error) {
	results, err := b.client.SecurityAdvisory.Query().
		Where(
			optionalPredicate(spec.GhsaID, securityadvisory.GhsaIDEqualFold),
			optionalPredicate(spec.ID, IDEQ),
		).All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(results, toModelGHSA), nil
}

func (b *EntBackend) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	advisory, err := WithinTX(ctx, b.client, func(context.Context) (*ent.SecurityAdvisory, error) {
		client := ent.FromContext(ctx)
		id, err := client.SecurityAdvisory.Create().
			SetGhsaID(strings.ToLower(ghsa.GhsaID)).
			OnConflict(
				sql.ConflictColumns(securityadvisory.FieldGhsaID),
				sql.ConflictWhere(sql.And(sql.NotNull(securityadvisory.FieldGhsaID), sql.IsNull(securityadvisory.FieldCveID))),
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
	return toModelGHSA(advisory), nil
}

func toModelGHSA(ghsa *ent.SecurityAdvisory) *model.Ghsa {
	if ghsa.GhsaID == nil {
		return nil
	}

	return &model.Ghsa{
		ID:     nodeID(ghsa.ID),
		GhsaID: *ghsa.GhsaID,
	}
}
