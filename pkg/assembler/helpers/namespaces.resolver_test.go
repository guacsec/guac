package helpers

import (
	"fmt"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)


var P6 = &model.Package{
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
									Key:   "test",
									Value: "test",
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
									Key:   "test",
									Value: "test",
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
									Key:   "test",
									Value: "test",
								},
							},
						},
					},
				},
			},
		},
	},
}


var P6Namespaces = []*model.PackageNamespace{
	{
		Namespace: "openssl.org",
		Names: []*model.PackageName{
			{
				Name: "openssl",
				Versions: []*model.PackageVersion{
					{
						Purl:    "pkg:conan/openssl.org/openssl",
						Version: "3.0.3",
						Qualifiers: []*model.PackageQualifier{
							{
								Key:   "test",
								Value: "test",
							},
						},
					},
				},
			},
			{
				Name: "libp11-kit0",
				Versions: []*model.PackageVersion{
					{
						Purl:    "pkg:conan/openssl.org/libp11-kit0",
						Version: "3.0.3",
						Qualifiers: []*model.PackageQualifier{
							{
								Key:   "test",
								Value: "test",
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
						Purl:    "pkg:conan/ubuntu/openssl",
						Version: "3.0.3",
						Qualifiers: []*model.PackageQualifier{
							{
								Key:   "test",
								Value: "test",
							},
						},
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
			Package:     P6,
			ExpResult:   P6Namespaces,
			ExpQueryErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result, err := UpdatePurlForNamespaces(test.Package)
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

func comparePackageNames(a, b []*model.PackageName) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
		if len(a[i].Versions) != len(b[i].Versions) {
			return false
		}
		for j := range a[i].Versions {
			if a[i].Versions[j].Purl != b[i].Versions[j].Purl {
				return false
			}
		}
	}
	return true
}