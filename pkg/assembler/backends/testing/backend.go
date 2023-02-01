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

package backend

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type DemoCredentials struct{}

type demoClient struct {
	packages []*model.Package
}

// Define some demo packages to test the query without also ingesting into Neo4j
var demo demoClient

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	demo = demoClient{
		packages: []*model.Package{
			&model.Package{
				Type: "apk",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "alpine",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "apk",
								Versions: []*model.PackageVersion{
									// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
									&model.PackageVersion{
										Version: "2.12.9-r3",
									},
								},
							},
							&model.PackageName{
								Name: "curl",
								Versions: []*model.PackageVersion{
									// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
									&model.PackageVersion{
										Version: "7.83.0-r0",
									},
								},
							},
						},
					},
				},
			},
			&model.Package{
				Type: "conan",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "openssl.org",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "openssl",
								Versions: []*model.PackageVersion{
									// pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c
									// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
									&model.PackageVersion{
										Version: "3.0.3",
									},
								},
							},
						},
					},
					&model.PackageNamespace{
						Namespace: "",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "openssl",
								Versions: []*model.PackageVersion{
									// pkg:conan/openssl@3.0.3
									&model.PackageVersion{
										Version: "3.0.3",
									},
								},
							},
						},
					},
				},
			},
			&model.Package{
				Type: "deb",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "debian",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "attr",
								Versions: []*model.PackageVersion{
									// pkg:deb/debian/attr@1:2.4.47-2%2Bb1?arch=amd64
									// pkg:deb/debian/attr@1:2.4.47-2?arch=source
									&model.PackageVersion{
										Version: "1:2.4.47-2",
									},
								},
							},
							&model.PackageName{
								Name: "curl",
								Versions: []*model.PackageVersion{
									// pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
									&model.PackageVersion{
										Version: "7.50.3-1",
									},
								},
							},
							&model.PackageName{
								Name: "dpkg",
								Versions: []*model.PackageVersion{
									// pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
									&model.PackageVersion{
										Version: "1.19.0.4",
									},
								},
							},
						},
					},
					&model.PackageNamespace{
						Namespace: "ubuntu",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "dpkg",
								Versions: []*model.PackageVersion{
									// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
									&model.PackageVersion{
										Version: "1.19.0.4",
									},
								},
							},
						},
					},
				},
			},
			&model.Package{
				Type: "docker",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "cassandra",
								Versions: []*model.PackageVersion{
									// pkg:docker/cassandra@latest
									&model.PackageVersion{
										Version: "latest",
									},
									// pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
									&model.PackageVersion{
										Version: "sha256:244fd47e07d1004f0aed9c",
									},
								},
							},
						},
					},
					&model.PackageNamespace{
						Namespace: "customer",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "dockerimage",
								Versions: []*model.PackageVersion{
									// pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io
									&model.PackageVersion{
										Version: "sha256:244fd47e07d1004f0aed9c",
									},
								},
							},
						},
					},
					&model.PackageNamespace{
						Namespace: "smartentry",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "debian",
								Versions: []*model.PackageVersion{
									// pkg:docker/smartentry/debian@dc437cc87d10
									&model.PackageVersion{
										Version: "dc437cc87d10",
									},
								},
							},
						},
					},
				},
			},
			&model.Package{
				Type: "generic",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "bitwarderl",
								Versions: []*model.PackageVersion{
									// pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32
									&model.PackageVersion{
										Version: "",
									},
								},
							},
							&model.PackageName{
								Name: "openssl",
								Versions: []*model.PackageVersion{
									// pkg:generic/openssl@1.1.10g
									// pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
									&model.PackageVersion{
										Version: "1.1.10g",
									},
								},
							},
						},
					},
				},
			},
			&model.Package{
				Type: "oci",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "debian",
								Versions: []*model.PackageVersion{
									// pkg:oci/debian@sha256:A244fd47e07d10?repository_url=docker.io/library/debian&arch=amd64&tag=latest
									// pkg:oci/debian@sha256:A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
									&model.PackageVersion{
										Version: "sha256:A244fd47e07d10",
									},
								},
							},
							&model.PackageName{
								Name: "hellow-wasm",
								Versions: []*model.PackageVersion{
									// pkg:oci/hello-wasm@sha256:244fd47e07d10?tag=v1
									&model.PackageVersion{
										Version: "sha256:244fd47e07d10",
									},
								},
							},
							&model.PackageName{
								Name: "static",
								Versions: []*model.PackageVersion{
									// pkg:oci/static@sha256:244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
									&model.PackageVersion{
										Version: "sha256:244fd47e07d10",
									},
								},
							},
						},
					},
				},
			},
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{
					&model.PackageNamespace{
						Namespace: "",
						Names: []*model.PackageName{
							&model.PackageName{
								Name: "django-allauth",
								Versions: []*model.PackageVersion{
									// pkg:pypi/django-allauth@12.23
									&model.PackageVersion{
										Version: "12.23",
									},
								},
							},
							&model.PackageName{
								Name: "django",
								Versions: []*model.PackageVersion{
									// pkg:pypi/django@1.11.1
									&model.PackageVersion{
										Version: "1.11.1",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &demo, nil
}

func (c *demoClient) Artifacts(ctx context.Context) ([]*model.Artifact, error) {
	panic(fmt.Errorf("not implemented: Artifacts - artifacts in testing backend"))
}

func (c *demoClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	var packages []*model.Package
	for _, p := range c.packages {
		if pkgSpec.Type == nil || p.Type == *pkgSpec.Type {
			newPkg := filterNamespace(p, pkgSpec)
			if newPkg != nil {
				packages = append(packages, newPkg)
			}
		}
	}
	return packages, nil
}

func filterNamespace(pkg *model.Package, pkgSpec *model.PkgSpec) *model.Package {
	var namespaces []*model.PackageNamespace
	for _, ns := range pkg.Namespaces {
		if pkgSpec.Namespace == nil || ns.Namespace == *pkgSpec.Namespace {
			newNs := filterName(ns, pkgSpec)
			if newNs != nil {
				namespaces = append(namespaces, newNs)
			}
		}
	}
	if len(namespaces) == 0 {
		return nil
	}
	return &model.Package{
		Type:       pkg.Type,
		Namespaces: namespaces,
	}
}

func filterName(ns *model.PackageNamespace, pkgSpec *model.PkgSpec) *model.PackageNamespace {
	var names []*model.PackageName
	for _, n := range ns.Names {
		if pkgSpec.Name == nil || n.Name == *pkgSpec.Name {
			newN := filterVersion(n, pkgSpec)
			if newN != nil {
				names = append(names, newN)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &model.PackageNamespace{
		Namespace: ns.Namespace,
		Names:     names,
	}
}

func filterVersion(n *model.PackageName, pkgSpec *model.PkgSpec) *model.PackageName {
	var versions []*model.PackageVersion
	for _, v := range n.Versions {
		if pkgSpec.Version == nil || v.Version == *pkgSpec.Version {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return nil
	}
	return &model.PackageName{
		Name:     n.Name,
		Versions: versions,
	}
}
