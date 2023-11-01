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
