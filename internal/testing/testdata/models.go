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
	"time"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var T1, _ = time.Parse(time.RFC3339, "2023-01-01T00:00:00Z")
var T2 = time.Unix(1e9, 0)
var T3 = time.Unix(1e9+5, 0)

var A1 = &model.ArtifactInputSpec{
	Algorithm: "sha256",
	Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
}

var A2 = &model.ArtifactInputSpec{
	Algorithm: "sha1",
	Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
}

var A1out = &model.Artifact{
	Algorithm: "sha256",
	Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
}

var A2out = &model.Artifact{
	Algorithm: "sha1",
	Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
}

var A3 = &model.ArtifactInputSpec{
	Algorithm: "sha512",
	Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
}

var A3out = &model.Artifact{
	Algorithm: "sha512",
	Digest:    "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7",
}

var A4 = &model.ArtifactInputSpec{
	Algorithm: "sha1",
	Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
}

var A4out = &model.Artifact{
	Algorithm: "sha1",
	Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
}

var B1 = &model.BuilderInputSpec{
	URI: "asdf",
}

var B1out = &model.Builder{
	URI: "asdf",
}

var B2 = &model.BuilderInputSpec{
	URI: "qwer",
}

var B2out = &model.Builder{
	URI: "qwer",
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
			Name: "myrepo",
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
			Name: "bobsrepo",
		}},
	}},
}

var S3 = &model.SourceInputSpec{
	Type:      "git",
	Namespace: "github.com/jeff",
	Name:      "myrepo",
	Tag:       ptrfrom.String("v1.0"),
}
var S3out = &model.Source{
	Type: "git",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/jeff",
		Names: []*model.SourceName{{
			Name: "myrepo",
			Tag:  ptrfrom.String("v1.0"),
		}},
	}},
}

var S4 = &model.SourceInputSpec{
	Type:      "svn",
	Namespace: "github.com/bob",
	Name:      "bobsrepo",
	Commit:    ptrfrom.String("5e7c41f"),
}
var S4out = &model.Source{
	Type: "svn",
	Namespaces: []*model.SourceNamespace{{
		Namespace: "github.com/bob",
		Names: []*model.SourceName{{
			Name:   "bobsrepo",
			Commit: ptrfrom.String("5e7c41f"),
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

var P2outName = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name:     "tensorflow",
			Versions: []*model.PackageVersion{},
		}},
	}},
}

var P3 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
	Subpath: ptrfrom.String("saved_model_cli.py"),
}
var P3out = &model.Package{
	Type: "pypi",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "tensorflow",
			Versions: []*model.PackageVersion{{
				Version:    "2.11.1",
				Subpath:    "saved_model_cli.py",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var P4 = &model.PkgInputSpec{
	Type:      "conan",
	Namespace: ptrfrom.String("openssl.org"),
	Name:      "openssl",
	Version:   ptrfrom.String("3.0.3"),
}

var P4out = &model.Package{
	Type: "conan",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "openssl.org",
		Names: []*model.PackageName{{
			Name: "openssl",
			Versions: []*model.PackageVersion{{
				Version:    "3.0.3",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}

var P4outName = &model.Package{
	Type: "conan",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "openssl.org",
		Names: []*model.PackageName{{
			Name:     "openssl",
			Versions: []*model.PackageVersion{},
		}},
	}},
}

var P5 = &model.PkgInputSpec{
	Type:      "conan",
	Namespace: ptrfrom.String("openssl.org"),
	Name:      "openssl",
	Version:   ptrfrom.String("3.0.3"),
	Qualifiers: []*model.PackageQualifierInputSpec{{
		Key:   "test",
		Value: "test",
	}},
}

var P5out = &model.Package{
	Type: "conan",
	Namespaces: []*model.PackageNamespace{{
		Namespace: "openssl.org",
		Names: []*model.PackageName{{
			Name: "openssl",
			Versions: []*model.PackageVersion{{
				Version: "3.0.3",
				Qualifiers: []*model.PackageQualifier{
					{
						Key:   "test",
						Value: "test",
					},
				},
			}},
		}},
	}},
}

var MAll = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}

var CB1out = &model.CertifyBad{
	Subject:       S2out,
	Justification: "test justification",
}

var CG1out = &model.CertifyGood{
	Subject:       P1out,
	Justification: "test justification one",
}

var SC1out = &model.CertifyScorecard{
	Source: S1out,
	Scorecard: &model.Scorecard{
		Checks: []*model.ScorecardCheck{},
		Origin: "test origin",
	},
}

var V1 = &model.VulnerabilityInputSpec{
	Type:            "OSV",
	VulnerabilityID: "CVE-2014-8140",
}

var VEX1out = &model.CertifyVEXStatement{
	ID: "1",
}

var C1 = &model.VulnerabilityInputSpec{
	Type:            "cve",
	VulnerabilityID: "CVE-2019-13110",
}
var C1out = &model.VulnerabilityID{
	VulnerabilityID: "cve-2019-13110",
}

var C2 = &model.VulnerabilityInputSpec{
	Type:            "cve",
	VulnerabilityID: "CVE-2014-8139",
}
var C2out = &model.VulnerabilityID{
	VulnerabilityID: "cve-2014-8139",
}

var C3 = &model.VulnerabilityInputSpec{
	Type:            "CVE",
	VulnerabilityID: "cVe-2014-8140",
}
var C3out = &model.VulnerabilityID{
	VulnerabilityID: "cve-2014-8140",
}

var G1 = &model.VulnerabilityInputSpec{
	Type:            "GHSA",
	VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
}
var G1out = &model.VulnerabilityID{
	VulnerabilityID: "ghsa-h45f-rjvw-2rv2",
}

var G2 = &model.VulnerabilityInputSpec{
	Type:            "ghsa",
	VulnerabilityID: "GHSA-xrw3-wqph-3fxg",
}
var G2out = &model.VulnerabilityID{
	VulnerabilityID: "ghsa-xrw3-wqph-3fxg",
}

var G3 = &model.VulnerabilityInputSpec{
	Type:            "ghsa",
	VulnerabilityID: "GHSA-8v4j-7jgf-5rg9",
}
var G3out = &model.VulnerabilityID{
	VulnerabilityID: "ghsa-8v4j-7jgf-5rg9",
}

var O1 = &model.VulnerabilityInputSpec{
	Type:            "OSV",
	VulnerabilityID: "CVE-2014-8140",
}

var O1out = &model.VulnerabilityID{
	VulnerabilityID: "cve-2014-8140",
}

var O2 = &model.VulnerabilityInputSpec{
	Type:            "osv",
	VulnerabilityID: "CVE-2022-26499",
}
var O2out = &model.VulnerabilityID{
	VulnerabilityID: "cve-2022-26499",
}

var O3 = &model.VulnerabilityInputSpec{
	Type:            "osv",
	VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
}
var O3out = &model.VulnerabilityID{
	VulnerabilityID: "ghsa-h45f-rjvw-2rv2",
}

var NoVulnInput = &model.VulnerabilityInputSpec{
	Type:            "noVuln",
	VulnerabilityID: "",
}
var NoVulnOut = &model.VulnerabilityID{
	VulnerabilityID: "",
}

var L1 = &model.LicenseInputSpec{
	Name:        "BSD-3-Clause",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var L1out = &model.License{
	Name:        "BSD-3-Clause",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var L2 = &model.LicenseInputSpec{
	Name:        "GPL-2.0-or-later",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var L2out = &model.License{
	Name:        "GPL-2.0-or-later",
	ListVersion: ptrfrom.String("3.21 2023-06-18"),
}
var L3 = &model.LicenseInputSpec{
	Name:        "MPL-2.0",
	ListVersion: ptrfrom.String("1.23 2020"),
}
var L3out = &model.License{
	Name:        "MPL-2.0",
	ListVersion: ptrfrom.String("1.23 2020"),
}

var InlineLicense = `
Redistribution and use of the MAME code or any derivative works are permitted provided that the following conditions are met:
* Redistributions may not be sold, nor may they be used in a commercial product or activity.
* Redistributions that are modified from the original source must include the complete source code, including the source code for all components used by a binary built from the modified sources. However, as a special exception, the source code distributed need not include anything that is normally distributed (in either source or binary form) with the major components (compiler, kernel, and so on) of the operating system on which the executable runs, unless that component itself accompanies the executable.
* Redistributions must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`

var L4 = &model.LicenseInputSpec{
	Name:   "LicenseRef-d58b4101",
	Inline: &InlineLicense,
}
var L4out = &model.License{
	Name:   "LicenseRef-d58b4101",
	Inline: &InlineLicense,
}

var ArtifactData = []*model.Artifact{
	{
		ID:        "artifacts/7086201",
		Algorithm: "sha256",
		Digest:    "fac901167c6638ec9c7ffd682fbac8483219d5328f709f1e052135232d72e2de",
	}, {
		ID:        "artifacts/7086296",
		Algorithm: "sha256",
		Digest:    "fadf546602de3973d230a6b50a27a4df780a082acda2f7fe6d9a7e67e419ba1e",
	},
}

var Metadata = []*model.HasMetadata{
	{
		ID:            "hasMetadataCollection/7098935",
		Key:           "cpe",
		Value:         "cpe:2.3:a:dpkg:dpkg:1.20.11:*:*:*:*:*:*:*",
		Justification: "spdx cpe external reference",
		Origin:        "GUAC SPDX",
		Collector:     "GUAC",
	}, {
		ID:            "hasMetadataCollection/7099035",
		Key:           "cpe",
		Value:         "cpe:2.3:a:libgcc_s1:libgcc_s1:10.2.1-6:*:*:*:*:*:*:*",
		Justification: "spdx cpe external reference",
		Origin:        "GUAC SPDX",
		Collector:     "GUAC",
	},
}

var H1 = []*model.HasSlsa{{
	Subject: &model.Artifact{
		Algorithm: "sha256",
		Digest:    "2d86b329a6a9fd3b65afbdca3e35f25823ee8b39b2479cbae0ce7a4aff417454",
	}}, {
	Subject: &model.Artifact{
		Algorithm: "sha1",
		Digest:    "efb60583822daea996ed487f862d970f64509143",
	}}, {
	Subject: &model.Artifact{
		Algorithm: "sha256",
		Digest:    "907260e18ac13cdfc47077e621567e990a2a988acebc8fcbb38674001e76c210",
	}},
}

var H1out = []*model.HasSlsa{{
	Subject: &model.Artifact{
		Algorithm: "sha256",
		Digest:    "2d86b329a6a9fd3b65afbdca3e35f25823ee8b39b2479cbae0ce7a4aff417454",
	}}, {
	Subject: &model.Artifact{
		Algorithm: "sha256",
		Digest:    "907260e18ac13cdfc47077e621567e990a2a988acebc8fcbb38674001e76c210",
	}},
}

var P6 = []*model.Package{{
	Type: "golang",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "github.com/opentracing",
			Versions: []*model.PackageVersion{{
				Version: "v1.1.0",
				Qualifiers: []*model.PackageQualifier{{
					Key:   "arch",
					Value: "x86_64",
				}, {
					Key:   "distro",
					Value: "alpine-3.16.2",
				}},
			}},
		}, {
			Name: "github.com/oklog",
			Versions: []*model.PackageVersion{{
				Version:    "v1.3.1",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}, {
			Name:     "golang",
			Versions: []*model.PackageVersion{},
		}},
	}},
}}

var P6out = []*model.Package{{
	Type: "golang",
	Namespaces: []*model.PackageNamespace{{
		Names: []*model.PackageName{{
			Name: "github.com/opentracing",
			Versions: []*model.PackageVersion{{
				Version: "v1.1.0",
				Qualifiers: []*model.PackageQualifier{{
					Key:   "arch",
					Value: "x86_64",
				}, {
					Key:   "distro",
					Value: "alpine-3.16.2",
				}},
			}},
		}, {
			Name: "github.com/oklog",
			Versions: []*model.PackageVersion{{
				Version:    "v1.3.1",
				Qualifiers: []*model.PackageQualifier{},
			}},
		}},
	}},
}}

var P7 = &model.PkgInputSpec{
	Type:      P5.Type,
	Namespace: P5.Namespace,
	Name:      P5.Name,
	Version:   P5.Version,
	Qualifiers: []*model.PackageQualifierInputSpec{{
		Key:   P5.Qualifiers[0].Key,
		Value: P5.Qualifiers[0].Value,
	}, {
		Key:   "repository_url",
		Value: "https://alternative.report.url/",
	}},
}

// ITE6EOLNodejs is a test document for the EOL ingestor
var ITE6EOLNodejs = []byte(`{
    "type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "uri": "pkg:npm/nodejs@14.17.0"
        }
    ],
    "predicateType": "https://in-toto.io/attestation/eol/v0.1",
    "predicate": {
        "product": "nodejs",
        "cycle": "14",
        "version": "14.17.0",
        "isEOL": true,
        "eolDate": "2023-04-30",
        "lts": true,
        "latest": "14.21.3",
        "releaseDate": "2021-05-11",
        "metadata": {
            "scannedOn": "2024-03-15T12:00:00Z"
        }
    }
}`)

// ITE6EOLPython is a test document for the EOL ingestor
var ITE6EOLPython = []byte(`{
    "type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "uri": "pkg:pypi/python@3.9.5"
        }
    ],
    "predicateType": "https://in-toto.io/attestation/eol/v0.1",
    "predicate": {
        "product": "python",
        "cycle": "3.9",
        "version": "3.9.5",
        "isEOL": false,
        "eolDate": "2025-10-05",
        "lts": false,
        "latest": "3.9.16",
        "releaseDate": "2021-05-03",
        "metadata": {
            "scannedOn": "2024-03-15T12:00:00Z"
        }
    }
}`)

// ITE6ReferenceSingle is a test document for the Reference ingestor with a single reference
var ITE6ReferenceSingle = []byte(`{
    "type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "uri": "pkg:npm/example-pkg@1.0.0"
        }
    ],
    "predicateType": "https://in-toto.io/attestation/reference/v0.1",
    "predicate": {
        "attester": {
            "id": "attester-123"
        },
        "references": [
            {
                "downloadLocation": "https://example.com/downloads/pkg.tar.gz",
                "digest": {
                    "sha256": "abcd1234..."
                },
                "mediaType": "application/x-tar"
            }
        ]
    }
}`)

// ITE6ReferenceMultiple is a test document for the Reference ingestor with multiple references
var ITE6ReferenceMultiple = []byte(`{
    "type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "uri": "pkg:pypi/example-python@3.9.0"
        }
    ],
    "predicateType": "https://in-toto.io/attestation/reference/v0.1",
    "predicate": {
        "attester": {
            "id": "attester-xyz"
        },
        "references": [
            {
                "downloadLocation": "https://example.com/artifacts/python-ref1.tgz",
                "digest": {
                    "sha256": "aa1111111111111111111111111111111111111111111111111111111111111111"
                },
                "mediaType": "application/octet-stream"
            },
            {
                "downloadLocation": "https://example.com/artifacts/python-ref2.whl",
                "digest": {
                    "sha256": "bb2222222222222222222222222222222222222222222222222222222222222222"
                },
                "mediaType": "application/zip"
            }
        ]
    }
}`)

// ITE6ReferenceNoSubject is a test document for the Reference ingestor with no subject provided
var ITE6ReferenceNoSubject = []byte(`{
    "type": "https://in-toto.io/Statement/v1",
    "subject": [],
    "predicateType": "https://in-toto.io/attestation/reference/v0.1",
    "predicate": {
        "attester": {
            "id": "attester-nobody"
        },
        "references": [
            {
                "downloadLocation": "https://example.com/artifacts/no-subject.tgz",
                "digest": {
                    "sha256": "no-subject-digest"
                },
                "mediaType": "application/octet-stream"
            }
        ]
    }
}`)
