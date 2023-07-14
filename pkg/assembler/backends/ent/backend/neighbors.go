package backend

import (
	"context"
	"log"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}

func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) {
	id, err := strconv.Atoi(node)
	if err != nil {
		return nil, err
	}

	record, err := b.client.Noder(ctx, id)
	if err != nil {
		return nil, err
	}

	switch v := record.(type) {
	case *ent.Artifact:
		return toModelArtifact(v), nil
	case *ent.PackageVersion:
		return toModelPackage(backReferencePackageVersion(v)), nil
	case *ent.PackageName:
		return toModelPackage(backReferencePackageName(v)), nil
	case *ent.PackageType:
		return toModelPackage(v), nil
	default:
		log.Printf("Unknown node type: %T", v)
	}

	return nil, nil
}
