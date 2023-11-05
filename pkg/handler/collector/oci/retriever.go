package oci

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type ArtifactRetriever interface {
	RetrieveArtifacts(context.Context, name.Reference, chan<- *processor.Document, ...remote.Option) error
}
