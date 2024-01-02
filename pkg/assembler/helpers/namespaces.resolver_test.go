package helpers

import (
	"fmt"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var Package = &model.Package{
	Type: "conan",
	Namespaces: []*model.PackageNamespace{
		{
			Namespace: "openssl.org",
			Names: []*model.PackageName{
				{
					Name: "openssl",
					Versions: []*model.PackageVersion{
						{
							Version: "3.0.3",
							Qualifiers: []*model.PackageQualifier{
								{
									Key: "distro",
									Value: "debian-11",
								},
							},
						},
					},
				},
				{
					Name: "libp11-kit0",
					Versions: []*model.PackageVersion{
						{
							Version: "3.0.3",
							Qualifiers: []*model.PackageQualifier{
								{
									Key: "arch",
									Value: "amd64",
								  },
								  {
									Key: "distro",
									Value: "debian-11",
								  },
							},
						},
					},
				},
			},
		},
		{
			Namespace: "ubuntu",
			Names: []*model.PackageName{
				{
					Name: "openssl",
					Versions: []*model.PackageVersion{
						{
							Version: "3.0.3",
							Qualifiers: []*model.PackageQualifier{
								{
									Key: "arch",
									Value: "amd64",
								},
							},
							Subpath: "api",
						},
					},
				},
			},
		},
	},
}

var PackageNamespaces = []*model.PackageNamespace{
	{
		Namespace: "openssl.org",
		Names: []*model.PackageName{
			{
				Name: "openssl",
				Versions: []*model.PackageVersion{
					{
						Purl:    "pkg:conan/openssl.org/openssl@3.0.3?distro=debian-11",
						Version: "3.0.3",
						Qualifiers: []*model.PackageQualifier{
							{
								Key: "distro",
								Value: "debian-11",
							  },
						},
					},
				},
			},
			{
				Name: "libp11-kit0",
				Versions: []*model.PackageVersion{
					{
						Purl:    "pkg:conan/openssl.org/libp11-kit0@3.0.3?arch=amd64&distro=debian-11",
						Version: "3.0.3",
						Qualifiers: []*model.PackageQualifier{
							{
								Key: "arch",
								Value: "amd64",
							  },
							  {
								Key: "distro",
								Value: "debian-11",
							  },
						},
					},
				},
			},
		},
	},
	{
		Namespace: "ubuntu",
		Names: []*model.PackageName{
			{
				Name: "openssl",
				Versions: []*model.PackageVersion{
					{
						Purl:    "pkg:conan/ubuntu/openssl@3.0.3?arch=amd64#api",
						Version: "3.0.3",
						Qualifiers: []*model.PackageQualifier{
							{
								Key: "arch",
								Value: "amd64",
							},
						},
						Subpath: "api",
					},
				},
			},
		},
	},
}

func TestUpdatePurlForNamespaces(t *testing.T) {
	tests := []struct {
		Name        string
		Package     *model.Package
		ExpResult   []*model.PackageNamespace
		ExpQueryErr bool
	}{
		{
			Name:        "Happy Path",
			Package:     Package,
			ExpResult:   PackageNamespaces,
			ExpQueryErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result, err := UpdatePurlForPackageNamespaces(test.Package)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if len(result) != len(test.ExpResult) {
				t.Errorf("Length mismatch: expected %d, got %d", len(test.ExpResult), len(result))
				return
			}
			fmt.Println(result)
			for i := range result {
				if !comparePackageNames(result[i].Names, test.ExpResult[i].Names) {
					t.Errorf("Mismatch at index %d:", i)
					fmt.Printf("Expected: %#v\n", test.ExpResult[i].Names)
					fmt.Printf("Actual:   %#v\n", result[i].Names)
				}
			}
		})
	}

}

func comparePackageNames(packageNameOne, packageNameTwo []*model.PackageName) bool {
	if len(packageNameOne) != len(packageNameTwo) {
		return false
	}
	for i := range packageNameOne {
		if packageNameOne[i].Name != packageNameTwo[i].Name {
			return false
		}
		if len(packageNameOne[i].Versions) != len(packageNameTwo[i].Versions) {
			return false
		}
		for j := range packageNameOne[i].Versions {
			if packageNameOne[i].Versions[j].Purl != packageNameTwo[i].Versions[j].Purl {
				return false
			}
		}
	}
	return true
}
