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
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	purl "github.com/package-url/packageurl-go"
)

const (
	PurlTypeGuac  = "guac"
	PurlFilesGuac = "pkg:guac/files/"
	PurlPkgGuac   = "pkg:guac/pkg/"
)

// PurlToPkg converts a purl URI string into a graphql package node
func PurlToPkg(purlUri string) (*model.PkgInputSpec, error) {
	p, err := purl.FromString(purlUri)
	if err != nil {
		return nil, fmt.Errorf("unable to parse purl %s: %v", purlUri, err)
	}

	return purlConvert(p)
}

func PkgInputSpecToPurl(currentPkg *model.PkgInputSpec) string {
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range currentPkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}

	var ns, ver, subpath string

	if currentPkg.Namespace != nil {
		ns = *currentPkg.Namespace
	}

	if currentPkg.Version != nil {
		ver = *currentPkg.Version
	}

	if currentPkg.Subpath != nil {
		subpath = *currentPkg.Subpath
	}
	return PkgToPurl(currentPkg.Type, ns, currentPkg.Name, ver, subpath, qualifiers)
}

func PkgToPurl(purlType, namespace, name, version, subpath string, qualifiersList []string) string {
	collectedQualifiers := purl.Qualifiers{}
	for i := range qualifiersList {
		if i%2 == 0 {
			qualifier := purl.Qualifier{
				Key:   qualifiersList[i],
				Value: qualifiersList[i+1],
			}
			collectedQualifiers = append(collectedQualifiers, qualifier)
		}
	}

	if purlType == purl.TypeOCI || purlType == purl.TypeDocker {
		if namespace != "" {
			collectedQualifiers = append(collectedQualifiers, purl.Qualifier{Key: "repository_url", Value: namespace})
			namespace = ""
		}
	}

	pkg := purl.NewPackageURL(purlType, namespace, name, version, collectedQualifiers, subpath)
	return pkg.ToString()
}

func purlConvert(p purl.PackageURL) (*model.PkgInputSpec, error) {
	switch p.Type {

	// Enumeration of https://github.com/package-url/purl-spec#known-purl-types
	// TODO(lumjjb): each PURL definition usually comes with a default repository
	// we should consider addition of default repository to the prefix of the namespace
	// so that they can be referenced with higher specificity in GUAC
	//
	// PURL types not defined in purl library handled generically
	case "alpine", "alpm", "apk", "huggingface", "githubactions", "mlflow", "qpkg", "pub", "swid", PurlTypeGuac:
		fallthrough
	// PURL types defined in purl library handled generically
	case purl.TypeBitbucket, purl.TypeCocoapods, purl.TypeCargo,
		purl.TypeComposer, purl.TypeConan, purl.TypeConda, purl.TypeCran,
		purl.TypeDebian, purl.TypeGem, purl.TypeGithub,
		purl.TypeGolang, purl.TypeHackage, purl.TypeHex, purl.TypeMaven,
		purl.TypeNPM, purl.TypeNuget, purl.TypePyPi, purl.TypeRPM, purl.TypeSwift,
		purl.TypeGeneric:
		// some code
		r := pkg(p.Type, p.Namespace, p.Name, p.Version, p.Subpath, p.Qualifiers.Map())
		return r, nil

	// Special cases handled separately
	case purl.TypeOCI:
		// For OCI, the namespace is not used and respository_url may contain a namespace
		// as part of the physical location of the package. Therefore, in order to use it
		// in the graphQL model consistently with other types, we special case OCI to take
		// the respository_url and encode it as the Package namespace.
		//
		// Ref: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#oci
		qs := p.Qualifiers.Map()

		// Not technically part of the spec but some PURLs still include the namespace
		// as part of the PURL
		var ns string = p.Namespace
		for k, v := range qs {
			if k == "repository_url" {
				ns = v
			}
		}

		delete(qs, "repository_url")
		ns = strings.TrimRight(ns, "/"+p.Name)
		r := pkg(p.Type, ns, p.Name, p.Version, p.Subpath, qs)
		return r, nil
	case purl.TypeDocker:
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
			if k == "repository_url" {
				repUrl = v
			}
		}
		delete(qs, "repository_url")

		ns := filepath.Join(repUrl, p.Namespace)
		ns = strings.Trim(ns, "/")

		r := pkg(p.Type, ns, p.Name, p.Version, p.Subpath, qs)
		return r, nil

	default:
		// unhandled types should throw an error so we can make sure to review the
		// implementation of newly introduced PURL types.
		return nil, fmt.Errorf("unhandled PURL type: %s", p.Type)
	}
}

func pkg(typ, namespace, name, version, subpath string, qualifiers map[string]string) *model.PkgInputSpec {
	var pQualifiers []model.PackageQualifierInputSpec
	for k, v := range qualifiers {
		pQualifiers = append(pQualifiers, model.PackageQualifierInputSpec{
			Key:   k,
			Value: v,
		})
	}

	p := &model.PkgInputSpec{
		Type:       typ,
		Namespace:  &namespace,
		Name:       name,
		Version:    &version,
		Subpath:    &subpath,
		Qualifiers: pQualifiers,
	}

	return p
}

func SanitizeString(s string) string {
	escapedName := ""
	if strings.Contains(s, "/") {
		var ns []string
		for _, item := range strings.Split(s, "/") {
			ns = append(ns, url.QueryEscape(item))
		}
		escapedName = strings.Join(ns, "/")
	} else {
		escapedName = url.QueryEscape(s)
	}
	return escapedName
}

func GuacPkgPurl(pkgName string, pkgVersion *string) string {
	escapedName := SanitizeString(pkgName)
	if pkgVersion == nil {
		return fmt.Sprintf(PurlPkgGuac+"%s", escapedName)
	}
	return fmt.Sprintf(PurlPkgGuac+"%s@%s", escapedName, *pkgVersion)
}

func GuacFilePurl(alg string, digest string, filename *string) string {
	s := fmt.Sprintf(PurlFilesGuac+"%s:%s", strings.ToLower(alg), digest)
	if filename != nil {
		s += fmt.Sprintf("#%s", SanitizeString(*filename))
	}
	return s
}

func GuacGenericPurl(s string) string {
	sanitizedString := SanitizeString(s)
	if strings.HasPrefix(sanitizedString, "/") {
		return fmt.Sprintf("pkg:guac/generic%s", sanitizedString)
	} else {
		return fmt.Sprintf("pkg:guac/generic/%s", sanitizedString)
	}
}
