//
// Copyright 2023 The GUAC Authors.
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

package client

// Most of this is inspired by the work in: https://github.com/ossf/scorecard/tree/main/clients

// TODO: Once we support Gitlab and other VCS this should include an interface

// Release represents a generic artifact/package release tied to a VCS
type Release struct {
	// Tag is either the tag associated with a release or empty string
	Tag    string
	Commit string
	Assets []ReleaseAsset
}

// ReleaseAsset represents the name and URL of an asset associated with a release.
// This is usually things like packages as well as metadata documents.
type ReleaseAsset struct {
	Name string
	URL  string
}

type ReleaseAssetContent struct {
	Name  string
	Bytes []byte
}

// NOTE: Copying the Github owner/repo naming
type Repo struct {
	Owner string
	Repo  string
}
