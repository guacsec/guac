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

package testdata

import (
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var A1 = &model.ArtifactInputSpec{
	Algorithm: "sha256",
	Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
}

var A2 = &model.ArtifactInputSpec{
	Algorithm: "sha1",
	Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
}

var A2out = &model.Artifact{
	Algorithm: "sha1",
	Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
}

var S1 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/jeff",
	Name:      "myrepo",
}

var S1out = &model.Source{
	Type: "git",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/jeff",
		Names: []*model.SourceName{{
			Name:   "myrepo",
			Tag:    ptrfrom.String(""),
			Commit: ptrfrom.String(""),
		}},
	}},
}
var S2 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/bob",
	Name:      "bobsrepo",
}

var S2out = &model.Source{
	Type: "git",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/bob",
		Names: []*model.SourceName{{
			Name:   "bobsrepo",
			Tag:    ptrfrom.String(""),
			Commit: ptrfrom.String(""),
		}},
	}},
}
var P1 = &model.PkgInputSpec{
	Type: "pypi",
	Name: "tensorflow",
}

var P1out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var P1outName = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name:     "tensorflow",
			Versions: []*model.PackageVersion{},
		}},
	}},
}

var P2 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
}

var P2out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "2.11.1",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var CB1out = &model.CertifyBad{
	Subject:       S2out,
	Justification: "test justification",
}
