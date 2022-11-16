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

package testdata

import _ "embed"

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed testdata/small-spdx.json
	SpdxExampleSmall []byte

	//go:embed testdata/alpine-spdx.json
	SpdxExampleBig []byte

	//go:embed testdata/alpine-small-spdx.json
	SpdxExampleAlpine []byte

	// Invalid types for field spdxVersion
	//go:embed testdata/invalid-spdx.json
	SpdxInvalidExample []byte

	// Example scorecard
	//go:embed testdata/kubernetes-scorecard.json
	ScorecardExample []byte

	// Invalid scorecard
	//go:embed testdata/invalid-scorecard.json
	ScorecardInvalid []byte

	//go:embed testdata/alpine-cyclonedx.json
	CycloneDXExampleAlpine []byte

	//go:embed testdata/invalid-cyclonedx.json
	CycloneDXInvalidExample []byte

	//go:embed testdata/distroless-cyclonedx.json
	CycloneDXDistrolessExample []byte

	//go:embed testdata/busybox-cyclonedx.json
	CycloneDXBusyboxExample []byte

	//go:embed testdata/big-mongo-cyclonedx.json
	CycloneDXBigExample []byte

	//go:embed testdata/crev-review.json
	ITE6CREVExample []byte

	//go:embed testdata/github-review.json
	ITE6ReviewExample []byte

	//go:embed testdata/certify-osv.json
	ITE6OSVExmple []byte
)
