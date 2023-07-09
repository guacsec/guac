package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) HashEqual(ctx context.Context, spec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	if spec == nil {
		return nil, nil
	}

	query := b.client.HashEqual.Query().Where(
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Origin, hashequal.OriginEQ),
		optionalPredicate(spec.Collector, hashequal.CollectorEQ),
		optionalPredicate(spec.Justification, hashequal.JustificationEQ),
	)

	for _, art := range spec.Artifacts {
		query.Where(hashequal.HasArtifactsWith(artifactQueryPredicates(art)))
	}

	records, err := query.
		WithArtifacts().
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelHashEqual), nil
}

func (b *EntBackend) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, spec model.HashEqualInputSpec) (*model.HashEqual, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.HashEqual, error) {
		tx := ent.TxFromContext(ctx)
		return upsertHashEqual(ctx, tx, artifact, equalArtifact, spec)
	})
	if err != nil {
		return nil, err
	}

	return toModelHashEqual(record.Unwrap()), nil
}

func upsertHashEqual(ctx context.Context, client *ent.Tx, artifactA model.ArtifactInputSpec, artifactB model.ArtifactInputSpec, spec model.HashEqualInputSpec) (*ent.HashEqual, error) {
	artifactARecord, err := client.Artifact.Query().Where(artifactQueryInputPredicates(artifactA)).Only(ctx)
	if err != nil {
		return nil, err
	}
	artifactBRecord, err := client.Artifact.Query().Where(artifactQueryInputPredicates(artifactB)).Only(ctx)
	if err != nil {
		return nil, err
	}

	record, err := artifactARecord.QuerySame().Where(hashequal.HasArtifactsWith(artifact.DigestEQ(artifactB.Digest))).Only(ctx)
	if ent.MaskNotFound(err) != nil {
		return nil, err
	}

	if record == nil {
		record, err = client.HashEqual.Create().
			AddArtifacts(artifactARecord, artifactBRecord).
			SetJustification(spec.Justification).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector).
			Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	return record, nil
}

func toModelHashEqual(record *ent.HashEqual) *model.HashEqual {
	return &model.HashEqual{
		ID:            nodeID(record.ID),
		Artifacts:     collect(record.Edges.Artifacts, toModelArtifact),
		Justification: record.Justification,
		Collector:     record.Collector,
		Origin:        record.Origin,
	}
}
