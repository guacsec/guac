package oci

import (
	"context"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	cosign_remote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

type sbomCollector struct{}

func (c *sbomCollector) Collect(ctx context.Context, ref name.Reference, docChannel chan<- *processor.Document, opts ...remote.Option) error {
	sbomTag, err := cosign_remote.SBOMTag(ref, cosign_remote.WithRemoteOptions(opts...))
	if err != nil {
		return fmt.Errorf("failed retrieving tag for sbom oci manifest: %w", err)
	}
	img, err := remote.Image(sbomTag, opts...)
	if err != nil {
		logging.FromContext(ctx).Infof("image does not have a sbom tag at reference: %s", sbomTag)
		return nil
	}
	return collectLayersOfImage(sbomTag, img, docChannel)
}
func (c *sbomCollector) Type() string {
	return "sbom"
}

func init() {
	c := &sbomCollector{}
	collectors[c.Type()] = c
}
