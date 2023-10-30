package oci

import (
	"context"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/guacsec/guac/pkg/handler/processor"
	cosign_remote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"golang.org/x/sync/errgroup"
)

type attestationCollector struct{}

func (c *attestationCollector) Collect(ctx context.Context, ref name.Reference, docChannel chan<- *processor.Document, opts ...remote.Option) error {
	signedEntity, err := cosign_remote.SignedEntity(ref, cosign_remote.WithRemoteOptions(opts...))
	atts, err := signedEntity.Attestations()
	if err != nil {
		return err
	}

	attRef, err := cosign_remote.AttestationTag(ref, cosign_remote.WithRemoteOptions(opts...))
	if err != nil {
		return err
	}

	signatures, err := atts.Get()
	if err != nil {
		return err
	}

	g := new(errgroup.Group)
	for _, signature := range signatures {
		signature := signature //https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			payload, err := signature.Payload()
			if err != nil {
				return fmt.Errorf("getting payload for signature: %w", err)
			}
			artifactType, err := signature.MediaType()
			if err != nil {
				return err
			}
			if err != nil {
				return err
			}
			pushBlobData(attRef, payload, string(artifactType), docChannel)
			return nil
		})
	}
	return g.Wait()
}

func (c *attestationCollector) Type() string {
	return "attestation"
}

func init() {
	c := &attestationCollector{}
	collectors[c.Type()] = c
}
