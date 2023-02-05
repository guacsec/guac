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

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/pkg/errors"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
)

const (
	OCICollector = "OCICollector"
)

type ociCollector struct {
	repoTags      map[string][]string
	checkedDigest map[string][]string
	poll          bool
	interval      time.Duration
}

// NewOCICollector initializes the oci collector by passing in the repo and tag being collected.
// Note: OCI collector can be called upon by a upstream registry collector in the future to collect from all
// repos in a given registry. For further details see issue #298
func NewOCICollector(ctx context.Context, repoTags map[string][]string, poll bool, interval time.Duration) *ociCollector {
	return &ociCollector{
		repoTags:      repoTags,
		checkedDigest: map[string][]string{},
		poll:          poll,
		interval:      interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if docChannel == nil {
		return fmt.Errorf("nil channel passed to %s", OCICollector)
	}

	for {
		for repo, tags := range o.repoTags {
			if len(tags) > 0 && o.poll {
				return errors.New("image tag should not specified when using polling")
			}
			if err := o.getTagsAndFetch(ctx, repo, tags, docChannel); err != nil {
				return fmt.Errorf("fetching artifacts for %s: %w", repo, err)
			}
		}
		if !o.poll {
			break
		}
		select {
		case <-ctx.Done():
			// This way the function will not block for a fixed
			// interval and can be stopped immediately when the context is canceled.
			return ctx.Err()
		case <-time.After(o.interval):
		}
	}

	return nil
}

func (o *ociCollector) getTagsAndFetch(ctx context.Context, repo string, tags []string, docChannel chan<- *processor.Document) error {
	if repo == "" {
		return errors.New("repository name not specified")
	}

	if docChannel == nil {
		return errors.New("invalid document channel")
	}

	rcOpts := []regclient.Opt{
		regclient.WithDockerCreds(),
		regclient.WithDockerCerts(),
	}

	rc := regclient.New(rcOpts...)

	repoRef, err := ref.New(repo)
	defer rc.Close(ctx, repoRef)

	if err != nil {
		return fmt.Errorf("parsing repository reference: %w", err)
	}

	var fetchTags []string
	if len(tags) > 0 {
		fetchTags = tags
	} else {
		allTags, err := rc.TagList(ctx, repoRef)
		if err != nil {
			return fmt.Errorf("reading tags for %s: %w", repo, err)
		}

		// Filter out tags that are not images
		for _, tag := range allTags.Tags {
			// filter out tags that looking for sha256- followed by a 64 character hex string
			if !(strings.HasPrefix(tag, "sha256-") && len(tag) == 71) {
				fetchTags = append(fetchTags, tag)
			}
		}
	}

	for _, tag := range fetchTags {
		if tag == "" {
			return errors.New("image tag not specified to fetch")
		}
		imageTag := fmt.Sprintf("%v:%v", repo, tag)
		tagRef, err := ref.New(imageTag)
		if err != nil {
			return fmt.Errorf("parsing tag reference: %w", err)
		}

		if err = o.fetchOCIArtifacts(ctx, repo, rc, tagRef, docChannel); err != nil {
			return fmt.Errorf("fetching artifacts for %s: %w", imageTag, err)
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
		return err
	}

	if m.IsList() {
		m, err := rc.ManifestGet(ctx, image)
		if err != nil {
			return err
		}
		pl, _ := manifest.GetPlatformList(m)
		for _, p := range pl {
			desc, err := manifest.GetPlatformDesc(m, p)
			if err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
			image.Digest = desc.Digest.String()
			err = o.fetchOCIArtifacts(ctx, repo, rc, image, docChannel)
			if err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
		}
	}

	digest := manifest.GetDigest(m)
	digestFormatted := fmt.Sprintf("%v-%v", digest.Algorithm(), digest.Encoded())
	suffixList := []string{"att", "sbom"}
	for _, suffix := range suffixList {
		digestTag := fmt.Sprintf("%v.%v", digestFormatted, suffix)
		// check to see if the digest + suffix has already been collected
		if !contains(o.checkedDigest[repo], digestTag) {
			imageTag := fmt.Sprintf("%v:%v", repo, digestTag)
			r, err := ref.New(imageTag)
			if err != nil {
				return err
			}

			// if `.att` or `.sbom`` do not exist for specified digest
			// log error and continue
			m, err = rc.ManifestGet(ctx, r)
			if err != nil {
				logger.Error(err)
				continue
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
				blob, err := rc.BlobGet(ctx, r, layers[i])
				if err != nil {
					return fmt.Errorf("failed pulling layer %d: %w", i, err)
				}
				btr1, err := blob.RawBody()
				if err != nil {
					return err
				}

				doc := &processor.Document{
					Blob:   btr1,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatUnknown,
					SourceInformation: processor.SourceInformation{
						Collector: string(OCICollector),
						Source:    imageTag,
					},
				}
				docChannel <- doc
			}
			o.checkedDigest[repo] = append(o.checkedDigest[repo], digestTag)
		}
	}

	return nil
}

// contains checks if a slice contains a value
func contains[T comparable](elems []T, v T) bool {
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
