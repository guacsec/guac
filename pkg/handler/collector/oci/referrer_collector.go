//
// Copyright * The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/guacsec/guac/pkg/handler/processor"
	cosign_remote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"golang.org/x/sync/errgroup"
)

type referrerCollector struct{}

func (c *referrerCollector) Collect(ctx context.Context, ref name.Reference, docChannel chan<- *processor.Document, opts ...remote.Option) error {
	digest, err := cosign_remote.ResolveDigest(ref, cosign_remote.WithRemoteOptions(opts...))
	if err != nil {
		return err
	}
	index, err := remote.Referrers(digest, opts...)
	if err != nil {
		return err
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return err
	}

	g := new(errgroup.Group)

	for _, manifest := range indexManifest.Manifests {
		manifest := manifest //https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			manifestDigest := ref.Context().Digest(manifest.Digest.String())
			img, err := remote.Image(manifestDigest)
			if err != nil {
				return err
			}
			return collectLayersOfImage(manifestDigest, img, docChannel)
		})
	}
	return g.Wait()
}

func (c *referrerCollector) Type() string {
	return "referrer"
}

func init() {
	c := &referrerCollector{}
	collectors[c.Type()] = c
}
