//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/scheme"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
)

const (
	OCICollector = "OCICollector"
)

// OCI artifact types
const (
	SpdxJson   = "application/spdx+json"
	InTotoJson = "application/vnd.in-toto+json"
)

// wellKnownOCIArtifactTypes is a map of OCI media types to document type and format
// document and format is returned as a tuple
var wellKnownOCIArtifactTypes = map[string]struct {
	documentType processor.DocumentType
	formatType   processor.FormatType
}{
	SpdxJson: {
		documentType: processor.DocumentSPDX,
		formatType:   processor.FormatJSON,
	},
	InTotoJson: {
		documentType: processor.DocumentITE6SLSA,
		formatType:   processor.FormatJSON,
	},
}

type ociCollector struct {
	collectDataSource datasource.CollectSource
	checkedDigest     map[string][]string
	poll              bool
	interval          time.Duration
}

// NewOCICollector initializes the oci collector by passing in the repo and tag being collected.
// Note: OCI collector can be called upon by a upstream registry collector in the future to collect from all
// repos in a given registry. For further details see issue #298
//
// Interval should be set to about 5 mins or more for production so that it doesn't clobber registries.
func NewOCICollector(ctx context.Context, collectDataSource datasource.CollectSource, poll bool, interval time.Duration) *ociCollector {
	return &ociCollector{
		collectDataSource: collectDataSource,
		checkedDigest:     map[string][]string{},
		poll:              poll,
		interval:          interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	repoTags := map[string][]string{}

	if o.poll {
		for {
			if err := o.populateRepoTags(ctx, repoTags); err != nil {
				return fmt.Errorf("unable to populate repotags: %w", err)
			}
			for repo, tags := range repoTags {
				// when polling if tags are specified, it will never get any new tags
				// that might be added after the fact. Defeating the point of the polling
				if len(tags) > 0 {
					return errors.New("image tag should not specified when using polling")
				}
				if err := o.getTagsAndFetch(ctx, repo, tags, docChannel); err != nil {
					return err
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.interval):
			}
		}
	} else {
		if err := o.populateRepoTags(ctx, repoTags); err != nil {
			return fmt.Errorf("unable to populate repotags: %w", err)
		}
		for repo, tags := range repoTags {
			if err := o.getTagsAndFetch(ctx, repo, tags, docChannel); err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *ociCollector) populateRepoTags(ctx context.Context, repoTags map[string][]string) error {
	logger := logging.FromContext(ctx)
	ds, err := o.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	for _, d := range ds.OciDataSources {
		imageRef, err := ref.New(d.Value)
		if err != nil {
			logger.Errorf("unable to parse OCI path: %v", d.Value)
			continue
		}
		imagePath := fmt.Sprintf("%s/%s", imageRef.Registry, imageRef.Repository)

		// If a image reference has no tag, then it is considered as getting all tags
		if hasNoTag(imageRef) {
			repoTags[imagePath] = []string{}
		} else {
			// if the list is equal to the empty list, it is already looking for
			// all tags
			if repoTags[imagePath] == nil || len(repoTags[imagePath]) > 0 {
				repoTags[imagePath] = append(repoTags[imagePath], imageRef.Tag)
			}

		}
	}
	return nil
}

func (o *ociCollector) getTagsAndFetch(ctx context.Context, repo string, tags []string, docChannel chan<- *processor.Document) error {
	rcOpts := []regclient.Opt{}
	rcOpts = append(rcOpts, regclient.WithDockerCreds())
	rcOpts = append(rcOpts, regclient.WithDockerCerts())
	rcOpts = append(rcOpts, regclient.WithUserAgent(version.UserAgent))

	if len(tags) > 0 {
		for _, tag := range tags {
			if tag == "" {
				return errors.New("image tag not specified to fetch")
			}
			imageTag := fmt.Sprintf("%v:%v", repo, tag)
			r, err := ref.New(imageTag)
			if err != nil {
				return err
			}

			rc := regclient.New(rcOpts...)
			defer rc.Close(ctx, r)

			if err := o.fetchOCIArtifacts(ctx, repo, rc, r, docChannel); err != nil {
				return err
			}
		}
	} else {
		r, err := ref.New(repo)
		if err != nil {
			return err
		}

		rc := regclient.New(rcOpts...)
		defer rc.Close(ctx, r)

		tags, err := rc.TagList(ctx, r)
		if err != nil {
			return fmt.Errorf("reading tags for %s: %w", repo, err)
		}

		for _, tag := range tags.Tags {
			if !strings.HasSuffix(tag, "sbom") && !strings.HasSuffix(tag, "att") && !strings.HasSuffix(tag, "sig") {
				imageTag := fmt.Sprintf("%v:%v", repo, tag)
				r, err := ref.New(imageTag)
				if err != nil {
					return err
				}
				if err := o.fetchOCIArtifacts(ctx, repo, rc, r, docChannel); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Note: fetchOCIArtifacts currently does not re-check if a new sbom or attestation get reuploaded during polling with the same image digest.
// A workaround for this would be to run the collector again with a specific tag without polling and ingest like normal
func (o *ociCollector) fetchOCIArtifacts(ctx context.Context, repo string, rc *regclient.RegClient, image ref.Ref, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	// attempt to request only the headers, avoids Docker Hub rate limits
	m, err := rc.ManifestHead(ctx, image)
	if err != nil {
		return fmt.Errorf("failed retrieving manifest head: %w", err)
	}

	if m.IsList() {
		m, err := rc.ManifestGet(ctx, image)
		if err != nil {
			return fmt.Errorf("failed retrieving manifest: %w", err)
		}
		pl, _ := manifest.GetPlatformList(m)
		logger.Infof("%s is manifest list with %d platforms", image.Reference, len(pl))
		for _, p := range pl {
			logger.Infof("Fetching platform %s", p)
			desc, err := manifest.GetPlatformDesc(m, p)
			if err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
			platformImage := ref.Ref{
				Scheme:     image.Scheme,
				Registry:   image.Registry,
				Repository: image.Repository,
				Digest:     desc.Digest.String(),
			}
			logger.Infof("Fetching %s for platform %s", platformImage.Digest, desc.Platform)
			if err := o.fetchOCIArtifacts(ctx, repo, rc, platformImage, docChannel); err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
		}
	}

	digest := manifest.GetDigest(m)
	image.Digest = digest.String()

	// check for fallback artifacts
	digestFormatted := fmt.Sprintf("%v-%v", digest.Algorithm(), digest.Encoded())
	suffixList := []string{"att", "sbom"}
	for _, suffix := range suffixList {
		digestTag := fmt.Sprintf("%v.%v", digestFormatted, suffix)
		// check to see if the digest + suffix has already been collected
		if !contains(o.checkedDigest[repo], digestTag) {
			imageTag := fmt.Sprintf("%v:%v", repo, digestTag)
			err = fetchOCIArtifactBlobs(ctx, rc, imageTag, "unknown", docChannel)
			if err != nil {
				return fmt.Errorf("failed retrieving artifact blobs from registry fallback artifacts: %w", err)
			}
			o.checkedDigest[repo] = append(o.checkedDigest[repo], digestTag)
		}
	}

	referrerOpts := []scheme.ReferrerOpts{}
	referrerList, err := rc.ReferrerList(ctx, image, referrerOpts...)
	if err != nil {
		return fmt.Errorf("failed retrieving referrer list: %w", err)
	}

	logger.Infof("Found %d referrers for %s", len(referrerList.Descriptors), image.Digest)

	for _, referrerDesc := range referrerList.Descriptors {
		if _, ok := wellKnownOCIArtifactTypes[referrerDesc.ArtifactType]; !ok {
			logger.Infof("Skipping referrer %s with unknown artifact type %s", referrerDesc.Digest, referrerDesc.ArtifactType)
			continue
		}

		referrerDescDigest := referrerDesc.Digest.String()

		if !contains(o.checkedDigest[repo], referrerDescDigest) {
			logger.Infof("Fetching referrer %s with artifact type %s", referrerDescDigest, referrerDesc.ArtifactType)
			referrerDigest := fmt.Sprintf("%v@%v", repo, referrerDescDigest)
			err = fetchOCIArtifactBlobs(ctx, rc, referrerDigest, referrerDesc.ArtifactType, docChannel)
			if err != nil {
				return err
			}
			o.checkedDigest[repo] = append(o.checkedDigest[repo], referrerDescDigest)
		}
	}

	return nil
}

func fetchOCIArtifactBlobs(ctx context.Context, rc *regclient.RegClient, artifact string, artifactType string, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	r, err := ref.New(artifact)
	if err != nil {
		return fmt.Errorf("unable to parse OCI reference: %v", artifact)
	}

	m, err := rc.ManifestGet(ctx, r)
	if err != nil {
		// this is a normal behavior, not an error when the digest does not have an attestation
		// explicitly logging it as info to avoid call-stack when logging
		logger.Infof("unable to get manifest for %v: %v", artifact, err)
		return nil
	}

	// go through layers in reverse
	mi, ok := m.(manifest.Imager)
	if !ok {
		return fmt.Errorf("reference is not a known image media type")
	}
	layers, err := mi.GetLayers()
	if err != nil {
		return err
	}
	for i := len(layers) - 1; i >= 0; i-- {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		blob, err := rc.BlobGet(ctx, r, layers[i])
		if err != nil {
			return fmt.Errorf("failed pulling layer %d: %w", i, err)
		}
		defer blob.Close()
		btr1, err := blob.RawBody()
		if err != nil {
			return fmt.Errorf("failed reading layer %d: %w", i, err)
		}

		var docType = processor.DocumentUnknown
		var docFormat = processor.FormatUnknown

		// check if artifactType is in wellKnownOCIArtifactTypes
		if artifactType != "" {
			if wellKnownArtifactType, ok := wellKnownOCIArtifactTypes[artifactType]; ok {
				docType = wellKnownArtifactType.documentType
				docFormat = wellKnownArtifactType.formatType
			}
		}

		doc := &processor.Document{
			Blob:   btr1,
			Type:   docType,
			Format: docFormat,
			SourceInformation: processor.SourceInformation{
				Collector: string(OCICollector),
				Source:    artifact,
			},
		}
		docChannel <- doc
	}

	return nil
}

func contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

// Type is the collector type of the collector
func (o *ociCollector) Type() string {
	return OCICollector
}

// hasNoTag determines if an OCI string passed in had no tag
func hasNoTag(r ref.Ref) bool {
	// the reference parsing automatically sets the tag to latest if there is no tag
	// specified, thus we need to check the reference to see if the latest tag was actually
	// included.
	return r.Tag == "latest" && r.Digest == "" && !strings.HasSuffix(r.Reference, "latest")
}
