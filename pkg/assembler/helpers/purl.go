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

package helpers

import (
	"fmt"
	"path/filepath"
	"strings"

	purl "github.com/package-url/packageurl-go"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	PurlTypeGuac              = "guac"
	repositoryUrlQualifierKey = "repository_url"
)

// PurlToPkg converts a purl URI string into a graphql package node
func PurlToPkg(purlUri string) (*model.Package, error) {
	p, err := purl.FromString(purlUri)
	if err != nil {
		return nil, fmt.Errorf("unable to parse purl: %v", err)
	}

	return purlConvert(p)
}

// purlConvert converts a purl URI into a graphql package node.
func purlConvert(p purl.PackageURL) (*model.Package, error) {
	purlTypeMap := map[string]func(purl.PackageURL) (*model.Package, error){
		"alpm":             genericHandler,
		"apk":              genericHandler,
		"huggingface":      genericHandler,
		"mlflow":           genericHandler,
		"qpkg":             genericHandler,
		"pub":              genericHandler,
		"swid":             genericHandler,
		PurlTypeGuac:       genericHandler,
		purl.TypeBitbucket: genericHandler,
		purl.TypeCocoapods: genericHandler,
		purl.TypeCargo:     genericHandler,
		purl.TypeComposer:  genericHandler,
		purl.TypeConan:     genericHandler,
		purl.TypeConda:     genericHandler,
		purl.TypeCran:      genericHandler,
		purl.TypeDebian:    genericHandler,
		purl.TypeGem:       genericHandler,
		purl.TypeGithub:    genericHandler,
		purl.TypeGolang:    genericHandler,
		purl.TypeHackage:   genericHandler,
		purl.TypeHex:       genericHandler,
		purl.TypeMaven:     genericHandler,
		purl.TypeNPM:       genericHandler,
		purl.TypeNuget:     genericHandler,
		purl.TypePyPi:      genericHandler,
		purl.TypeRPM:       genericHandler,
		purl.TypeSwift:     genericHandler,
		purl.TypeGeneric:   genericHandler,
		purl.TypeOCI:       ociHandler,
		purl.TypeDocker:    dockerHandler,
	}

	if handler, ok := purlTypeMap[p.Type]; ok {
		return handler(p)
	}

	return nil, fmt.Errorf("unhandled PURL type")
}

// genericHandler is a generic handler for all purl types that do not require special handling
func genericHandler(p purl.PackageURL) (*model.Package, error) {
	r := pkg(p.Type, p.Namespace, p.Name, p.Version, p.Subpath, p.Qualifiers.Map())
	return r, nil
}

// ociHandler is a handler for OCI purl types
func ociHandler(p purl.PackageURL) (*model.Package, error) {
	// For OCI, the namespace is not used and respository_url may contain a namespace
	// as part of the physical location of the package. Therefore, in order to use it
	// in the graphQL model consistently with other types, we special case OCI to take
	// the respository_url and encode it as the Package namespace.
	//
	// Ref: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#oci
	qs := p.Qualifiers.Map()
	var ns string
	for k, v := range qs {
		if k == repositoryUrlQualifierKey {
			ns = v
		}
	}

	delete(qs, repositoryUrlQualifierKey)
	ns = strings.TrimRight(ns, "/"+p.Name)
	r := pkg(p.Type, ns, p.Name, p.Version, p.Subpath, qs)
	return r, nil
}

// dockerHandler is a handler for Docker purl types
func dockerHandler(p purl.PackageURL) (*model.Package, error) {
	// Similar to the case of OCI as above, but difference is that the namespace can be
	// used to specify registry/user/organization if present.
	//
	// It states
	// - The default repository is https://hub.docker.com.
	// - The namespace is the registry/user/organization if present.
	// - The version should be the image id sha256 or a tag. Since tags can
	// be moved, a sha256 image id is preferred.  as part of the physical
	// location of the package.. However, this is not enforced, and examples use tags
	//
	// Ref: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#docker
	qs := p.Qualifiers.Map()
	var repUrl string
	for k, v := range qs {
		if k == repositoryUrlQualifierKey {
			repUrl = v
		}
	}
	delete(qs, repositoryUrlQualifierKey)

	ns := filepath.Join(repUrl, p.Namespace)
	ns = strings.Trim(ns, "/")

	r := pkg(p.Type, ns, p.Name, p.Version, p.Subpath, qs)
	return r, nil
}

func pkg(typ, namespace, name, version, subpath string, qualifiers map[string]string) *model.Package {
	var pQualifiers []*model.PackageQualifier
	for k, v := range qualifiers {
		pQualifiers = append(pQualifiers, &model.PackageQualifier{
			Key:   k,
			Value: v,
		})
	}

	p := &model.Package{
		Type: typ,
		Namespaces: []*model.PackageNamespace{{
			Namespace: namespace,
			Names: []*model.PackageName{{
				Name: name,
				Versions: []*model.PackageVersion{{
					Version:    version,
					Subpath:    subpath,
					Qualifiers: pQualifiers,
				}},
			}},
		}},
	}

	return p
}
