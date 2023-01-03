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
	repo          string
	tag           string
	checkedDigest []string
	poll          bool
	interval      time.Duration
}

// NewOCICollector initializes the oci collector by passing in the repo and tag being collected.
// Note: Implementation of a registry collector, where the collector would query for all repositories and pull
// all metadata stored for each, was put on hold as "_catalog" API is not implemented the same across all registries.
// This would result in fixes and bugs depending on which registry (cloud or private) the user utilized.
// Each cloud-hosted registry adds its own custom API for listing things within a single org.
// We can revisit this later if needed but oci collector is currently setup such that it can be called by an
// upstream "registry collector" to collect from all repos in a registry in the future if needed.
// This can be done by the following using regclient API:
/*
   r, err := ref.New(o.registry)
   if err != nil {
     return fmt.Errorf("failed to parse ref %s: %v", r, err)
   }
   defer rc.Close(ctx, r)

   rl, err := rc.RepoList(ctx, o.registry)
   if err != nil && errors.Is(err, types.ErrNotImplemented) {
     return fmt.Errorf("registry %s does not support underlying _catalog API: %w", o.registry, err)
   }

   for _, repo := range rl.Repositories {
     r, err := ref.New(repo)
     if err != nil {
       return err
     }
     collectedTags, err := getTagList(ctx, rc, r)
     if err != nil {
       return err
     }
     for _, tag := range collectedTags {
       ociRepoCollector := NewOCIRepoCollector(ctx, repo, tag, false, time.Second)
       ociRepoCollector.checkedDigest = o.checkedDigest[repo]
       ociRepoCollector.RetrieveArtifacts(ctx, docChannel)
       o.checkedDigest[repo] = ociRepoCollector.checkedDigest
     }
   }
   return nil
*/
func NewOCICollector(ctx context.Context, repo string, tag string, poll bool, interval time.Duration) *ociCollector {
	return &ociCollector{
		repo:          repo,
		tag:           tag,
		checkedDigest: []string{},
		poll:          poll,
		interval:      interval,
	}
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (o *ociCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if o.poll {
		if o.tag != "" {
			return errors.New("image tag should not specified when using polling")
		}
		for {
			err := o.getTagsAndFetch(ctx, docChannel)
			if err != nil {
				return err
			}
			// set interval to about 5 mins or more
			time.Sleep(o.interval)
		}
	} else {
		if o.tag == "" {
			return errors.New("image tag not specified to fetch")
		}
		err := o.getTagsAndFetch(ctx, docChannel)
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *ociCollector) getTagsAndFetch(ctx context.Context, docChannel chan<- *processor.Document) error {
	rcOpts := []regclient.Opt{}
	rcOpts = append(rcOpts, regclient.WithDockerCreds())
	rcOpts = append(rcOpts, regclient.WithDockerCerts())

	if o.tag != "" {
		imageTag := fmt.Sprintf("%v:%v", o.repo, o.tag)
		r, err := ref.New(imageTag)
		if err != nil {
			return err
		}

		rc := regclient.New(rcOpts...)
		defer rc.Close(ctx, r)

		err = o.fetchOCIArtifacts(ctx, rc, r, docChannel)
		if err != nil {
			return err
		}
	} else {
		r, err := ref.New(o.repo)
		if err != nil {
			return err
		}

		rc := regclient.New(rcOpts...)
		defer rc.Close(ctx, r)

		tags, err := rc.TagList(ctx, r)
		if err != nil {
			return fmt.Errorf("reading tags for %s: %w", o.repo, err)
		}

		for _, tag := range tags.Tags {
			if !strings.HasSuffix(tag, "sbom") && !strings.HasSuffix(tag, "att") && !strings.HasSuffix(tag, "sig") {
				imageTag := fmt.Sprintf("%v:%v", o.repo, tag)
				r, err := ref.New(imageTag)
				if err != nil {
					return err
				}
				err = o.fetchOCIArtifacts(ctx, rc, r, docChannel)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (o *ociCollector) fetchOCIArtifacts(ctx context.Context, rc *regclient.RegClient, image ref.Ref, docChannel chan<- *processor.Document) error {
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
			err = o.fetchOCIArtifacts(ctx, rc, image, docChannel)
			if err != nil {
				return fmt.Errorf("failed retrieving platform specific digest: %w", err)
			}
		}
	}

	digest := manifest.GetDigest(m)
	digestFormatted := fmt.Sprintf("%v-%v", digest.Algorithm(), digest.Encoded())
	// check to see if the digest has already been collected
	if !contains(o.checkedDigest, digestFormatted) {
		suffixList := []string{"att", "sbom"}
		for _, suffix := range suffixList {
			digestTag := fmt.Sprintf("%v.%v", digestFormatted, suffix)
			imageTag := fmt.Sprintf("%v:%v", o.repo, digestTag)
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
			o.checkedDigest = append(o.checkedDigest, fmt.Sprintf("%v-%v", digest.Algorithm(), digest.Encoded()))
		}
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
