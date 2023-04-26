package depversion

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
)

func Test_VersionRangeParse(t *testing.T) {
	testCases := []struct {
		input  string
		expect VersionMatchObject
	}{
		{
			// deps.dev test set
			input: "",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=0"},
				},
			},
		},
		{
			input: "1.7.21",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=1.7.21"},
				},
			},
		},
		{
			input: "3.0.3",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=3.0.3"},
				},
			},
		},
		{
			input: "<2.0,>=0.12",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"<2.0,>=0.12"},
				},
			},
		},
		{
			input: ">=1.0.0",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.0"},
				},
			},
		},
		// not even proper semver... We will conver it to semver
		{
			input: ">=1.0.0rc8",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.0-rc8"},
				},
			},
		},
		{
			input: "[1.5.0,)",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.5.0"},
				},
			},
		},
		{
			input: "[3.0,)",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=3.0"},
				},
			},
		},
		{
			input: "^0.11",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=0.11,<1"},
				},
			},
		},
		{
			input: "^1",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1,<2"},
				},
			},
		},
		{
			input: "^1.0.25",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.25,<2"},
				},
			},
		},
		{
			input: "^3.0.0 || ^4.0.0",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=3.0.0,<4"},
					{">=4.0.0,<5"},
				},
			},
		},
		{
			input: "v0.0.0-20190603091049-60506f45cf65",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=0.0.0-20190603091049-60506f45cf65"},
				},
			},
		},

		{
			input: "v1.1.2",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=1.1.2"},
				},
			},
		},

		// NPM test set
		{
			input: "1.0.0 - 2.9999.9999",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=1.1.2"},
				},
			},
		},
		{
			input: ">=1.0.2 <2.1.2",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.2 <2.1.2"},
				},
			},
		},
		{
			input: ">1.0.2 <=2.3.4",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">1.0.2 <=2.3.4"},
				},
			},
		},
		{
			input: "2.0.1",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=2.0.1"},
				},
			},
		},
		{
			input: "<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"<1.0.0"},
					{">=2.3.1,<2.4.5"},
					{">=2.5.2,<3.0.0"},
				},
			},
		},
		{
			input: "http://asdf.com/asdf.tar.gz",
			expect: VersionMatchObject{
				Exact: ptrfrom.String("http://asdf.com/asdf.tar.gz"),
			},
		},
		{
			input: "~1.2",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.2,<1.3"},
				},
			},
		},
		{
			input: "~1.2.3",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.2.3,<2"},
				},
			},
		},
		{
			input: "2.x",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=2.0,<3"},
				},
			},
		},
		{
			input: "3.3.x",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=3.3.0,<3.4"},
				},
			},
		},
		{
			// special case latest set to no constraint
			input: "latest",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=0"},
				},
			},
		},
		{
			input: "file:../dyl",
			expect: VersionMatchObject{
				Exact: ptrfrom.String("file:../dyl"),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("parsing version range %s", tt.input), func(t *testing.T) {

			got, err := ParseVersionRange(tt.input)
			if err != nil {
				t.Errorf("got unexpected err: %v", err)
				return
			}

			if diff := cmp.Diff(got, tt.expect); len(diff) > 0 {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}
