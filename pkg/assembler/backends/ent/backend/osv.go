package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

func (b *EntBackend) Osv(ctx context.Context, spec *model.OSVSpec) ([]*model.Osv, error) {
	results, err := getAdvisories(ctx, b.client, &advisoryQuerySpec{
		ID:    spec.ID,
		OsvID: spec.OsvID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Osv")
	}

	return collect(results, toModelOSV), nil
}

func (b *EntBackend) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	advisory, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SecurityAdvisory, error) {
		return upsertAdvisory(ctx, ent.TxFromContext(ctx), advisoryQuerySpec{
			OsvID: &osv.OsvID,
		})
	})
	if err != nil {
		return nil, errors.Wrap(err, "IngestOsv")
	}
	return toModelOSV(advisory), nil
}

func toModelOSV(osv *ent.SecurityAdvisory) *model.Osv {
	if osv == nil {
		return nil
	}

	if osv.OsvID == nil {
		return nil
	}

	return &model.Osv{
		ID:    nodeID(osv.ID),
		OsvID: *osv.OsvID,
	}
}
