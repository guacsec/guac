package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	return nil, nil
}

func (b *EntBackend) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {

	return nil, nil
}

// func upsertSLSA(ctx context.Context, client *ent.Tx, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*ent.HasSlsa, error) {

// 	return nil, nil
// }
