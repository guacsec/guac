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

package common

import (
	"fmt"
	"hash/fnv"
	"slices"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

var ignore = []string{
	"AND",
	"OR",
	"WITH",
}

// Could add exceptions to ignore list, as they are not licenses:
// "389-exception",
// "Autoconf-exception-2.0",
// "Autoconf-exception-3.0",
// "Bison-exception-2.2",
// "Bootloader-exception",
// "Classpath-exception-2.0",
// "CLISP-exception-2.0",
// "DigiRule-FOSS-exception",
// "eCos-exception-2.0",
// "Fawkes-Runtime-exception",
// "FLTK-exception",
// "Font-exception-2.0",
// "freertos-exception-2.0",
// "GCC-exception-2.0",
// "GCC-exception-3.1",
// "gnu-javamail-exception",
// "GPL-3.0-linking-exception",
// "GPL-3.0-linking-source-exception",
// "GPL-CC-1.0",
// "i2p-gpl-java-exception",
// "Libtool-exception",
// "Linux-syscall-note",
// "LLVM-exception",
// "LZMA-exception",
// "mif-exception",
// "OCaml-LGPL-linking-exception",
// "OCCT-exception-1.0",
// "OpenJDK-assembly-exception-1.0",
// "openvpn-openssl-exception",
// "PS-or-PDF-font-exception-20170817",
// "Qt-GPL-exception-1.0",
// "Qt-LGPL-exception-1.1",
// "Qwt-exception-1.0",
// "Swift-exception",
// "u-boot-exception-2.0",
// "Universal-FOSS-exception-1.0",
// "WxWindows-exception-3.1",

func ParseLicenses(exp string, lv string) []generated.LicenseInputSpec {
	if exp == "" {
		return nil
	}
	var rv []generated.LicenseInputSpec
	for _, part := range strings.Split(exp, " ") {
		p := strings.Trim(part, "()+")
		if slices.Contains(ignore, p) {
			continue
		}
		rv = append(rv, generated.LicenseInputSpec{
			Name:        p,
			ListVersion: &lv,
		})
	}
	return rv
}

func HashLicense(inline string) string {
	h := fnv.New32a()
	h.Write([]byte(inline))
	s := h.Sum32()
	return fmt.Sprintf("LicenseRef-%x", s)
}
