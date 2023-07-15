package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Ghsa(ctx context.Context, spec *model.GHSASpec) ([]*model.Ghsa, error) {
	results, err := getAdvisories(ctx, b.client, &advisoryQuerySpec{
		ID:     spec.ID,
		GhsaID: spec.GhsaID,
	})
	if err != nil {
		return nil, err
	}

	return collect(results, toModelGHSA), nil
}

func (b *EntBackend) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	advisory, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SecurityAdvisory, error) {
		return upsertAdvisory(ctx, ent.TxFromContext(ctx), advisoryQuerySpec{
			GhsaID: &ghsa.GhsaID,
		})
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
