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

package assembler

const (
	packageName    = "name"
	packageDigest  = "digest"
	packageVersion = "version"
	packagePurl    = "purl"
	packageCPEs    = "cpes"
	packageTags    = "tags"
)

type PackageNode struct {
	Name     string
	Digest   []string
	Version  string
	Purl     string
	CPEs     []string
	Tags     []string
	NodeData objectMetadata
}

func (pn PackageNode) Type() string {
	return "Package"
}

func (pn PackageNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	if len(pn.Name) > 0 {
		properties[packageName] = pn.Name
	}
	if len(pn.Purl) > 0 {
		properties[packagePurl] = pn.Purl
	}
	if len(pn.Version) > 0 {
		properties[packageVersion] = pn.Version
	}
	if len(pn.CPEs) > 0 {
		properties[packageCPEs] = pn.CPEs
	}
	if len(pn.Digest) > 0 {
		properties[packageDigest] = toLower(pn.Digest...)
	}
	if len(pn.Tags) > 0 {
		properties[packageTags] = pn.Tags
	}
	pn.NodeData.addProperties(properties)
	return properties
}

func (pn PackageNode) PropertyNames() []string {
	fields := []string{packageName, packageDigest, packagePurl, packageCPEs, packageTags, packageVersion}
	fields = append(fields, pn.NodeData.getProperties()...)
	return fields
}

func (pn PackageNode) IdentifiablePropertyNames() []string {
	return []string{"purl"}
}
