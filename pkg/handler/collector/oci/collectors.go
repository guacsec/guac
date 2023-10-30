package oci

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	cosign_remote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"io"
)

func collect(ctx context.Context, ref name.Reference, docChannel chan<- *processor.Document, remoteOpts ...remote.Option) error {
	attestationErr := collectAttestations(ref, docChannel, remoteOpts...)
	sbomErr := collectSBOM(ctx, ref, docChannel, remoteOpts...)
	referrerErr := collectFromReferrers(ref, docChannel, remoteOpts...)
	return errors.Join(attestationErr, sbomErr, referrerErr)
}

func collectFromReferrers(ref name.Reference, docChannel chan<- *processor.Document, remoteOpts ...remote.Option) error {
	digest, err := cosign_remote.ResolveDigest(ref, cosign_remote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}
	index, err := remote.Referrers(digest, remoteOpts...)
	if err != nil {
		return err
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return err
	}

	var processErr error

	for _, manifest := range indexManifest.Manifests {
		manifestDigest := ref.Context().Digest(manifest.Digest.String())
		img, err := remote.Image(manifestDigest)
		if err != nil {
			processErr = errors.Join(processErr, err)
		}
		processErr = errors.Join(processErr, collecetLayersOfImage(manifestDigest, img, docChannel))
	}
	return processErr
}

func collectSBOM(ctx context.Context, ref name.Reference, docChannel chan<- *processor.Document, opts ...remote.Option) error {
	sbomTag, err := cosign_remote.SBOMTag(ref, cosign_remote.WithRemoteOptions(opts...))
	if err != nil {
		return fmt.Errorf("failed retrieving tag for sbom oci manifest: %w", err)
	}
	img, err := remote.Image(sbomTag, opts...)
	if err != nil {
		logging.FromContext(ctx).Infof("image does not have a sbom tag at reference: %s", sbomTag)
		return nil
	}
	return collecetLayersOfImage(sbomTag, img, docChannel)
}

func collecetLayersOfImage(ref name.Reference, img v1.Image, docChannel chan<- *processor.Document) error {
	manifest, err := img.Manifest()
	if err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for _, layer := range layers {
		blob, err := layer.Compressed()
		if err != nil {
			return err
		}
		defer blob.Close()
		blobData, err := io.ReadAll(blob)
		if err != nil {
			return fmt.Errorf("failed reading blob: %w", err)
		}
		artifactType := "unknown"
		// referrers store their artifactType inside the manifest mediatype
		if mediaType := manifest.Config.MediaType; mediaType != "" {
			artifactType = string(mediaType)
		}
		// attestations and sbom store their artifactType in the layer mediatype
		mediaType, err := layer.MediaType()
		if err == nil && mediaType != "" {
			artifactType = string(mediaType)
		}
		pushBlobData(ref, blobData, artifactType, docChannel)
	}
	return nil
}

func collectAttestations(ref name.Reference, docChannel chan<- *processor.Document, remoteOpts ...remote.Option) error {
	signedEntity, err := cosign_remote.SignedEntity(ref, cosign_remote.WithRemoteOptions(remoteOpts...))
	atts, err := signedEntity.Attestations()
	if err != nil {
		return err
	}

	attRef, err := cosign_remote.AttestationTag(ref, cosign_remote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	signatures, err := atts.Get()
	if err != nil {
		return err
	}

	var processErr error
	for _, signature := range signatures {
		payload, err := signature.Payload()
		if err != nil {
			processErr = errors.Join(processErr, fmt.Errorf("getting payload for signature: %w", err))
			continue
		}
		artifactType, err := signature.MediaType()
		if err != nil {
			processErr = errors.Join(processErr, err)
			continue
		}
		if err != nil {
			processErr = errors.Join(processErr, err)
			continue
		}

		pushBlobData(attRef, payload, string(artifactType), docChannel)
	}
	return processErr
}
