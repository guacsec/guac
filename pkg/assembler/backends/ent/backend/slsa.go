package backend

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	return nil, nil
}

func (b *EntBackend) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	att, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SLSAAttestation, error) {
		return upsertSLSA(ctx, ent.TxFromContext(ctx), subject, builtFrom, builtBy, slsa)
	})
	if err != nil {
		return nil, err
	}

	return toModelHasSLSA(att), nil
}

func upsertSLSA(ctx context.Context, client *ent.Tx, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*ent.SLSAAttestation, error) {

	builder, err := upsertBuilder(ctx, client, builtBy)
	if err != nil {
		return nil, err
	}

	artifacts, err := ingestArtifacts(ctx, client.Client(), builtFrom)
	if err != nil {
		return nil, err
	}

	subjectArtifacts, err := ingestArtifacts(ctx, client.Client(), []*model.ArtifactInputSpec{&subject})
	if err != nil {
		return nil, err
	}

	id, err := client.SLSAAttestation.Create().
		SetSubject(subjectArtifacts[0]).
		SetBuildType(slsa.BuildType).
		SetBuiltBy(builder).
		SetCollector(slsa.Collector).
		SetOrigin(slsa.Origin).
		SetSlsaPredicate(toSLSAInputPredicate(slsa.SlsaPredicate)).
		SetNillableStartedOn(slsa.StartedOn).
		SetNillableFinishedOn(slsa.FinishedOn).
		AddBuiltFrom(artifacts...).
		OnConflict(
			sql.ConflictColumns(""),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.SLSAAttestation.Query().
		Where(slsaattestation.IDEQ(id)).
		WithBuiltBy().
		WithBuiltFrom().
		WithSubject().
		Only(ctx)
}

func upsertBuilder(ctx context.Context, client *ent.Tx, spec model.BuilderInputSpec) (*ent.Builder, error) {
	id, err := client.Builder.Create().SetURI(spec.URI).OnConflict(
		sql.ConflictColumns(builder.FieldURI),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.Builder.Get(ctx, id)
}

func toSLSAInputPredicate(rows []*model.SLSAPredicateInputSpec) []*model.SLSAPredicate {
	preds := make([]*model.SLSAPredicate, len(rows))
	for i, row := range rows {
		preds[i] = &model.SLSAPredicate{
			Key:   row.Key,
			Value: row.Value,
		}
	}

	return preds
}

func toModelHasSLSA(att *ent.SLSAAttestation) *model.HasSlsa {
	return &model.HasSlsa{
		ID:      nodeID(att.ID),
		Subject: toModelArtifact(att.Edges.Subject),
		Slsa: &model.Slsa{
			BuiltFrom:     collect(att.Edges.BuiltFrom, toModelArtifact),
			BuiltBy:       toModelBuilder(att.Edges.BuiltBy),
			BuildType:     att.BuildType,
			SlsaPredicate: att.SlsaPredicate,
			SlsaVersion:   att.SlsaVersion,
			StartedOn:     att.StartedOn,
			FinishedOn:    att.FinishedOn,
			Origin:        att.Origin,
			Collector:     att.Collector,
		},
	}
}
