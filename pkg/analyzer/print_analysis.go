package analyzer

import (
	"fmt"
	"os"
	"sort"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/olekukonko/tablewriter"
)


func GetNodeString(option NodeType, node interface{}) (string, error) {
	switch option {

	case Pkg:
		pkg, ok := node.(model.AllIsDependencyTreePackage)
		if !ok {
			return "", fmt.Errorf("could not case node to tree Pkg")
		}

		sort.Sort(packageNameSpaces(pkg.Namespaces))
		message := "Type:" + pkg.Type + "\n"
		for _, namespace := range pkg.Namespaces {
			message += "Namespace: " + namespace.Namespace + "\n"

			for _, name := range namespace.Names {
				message += "\t"
				message += "Name: " + name.Name
				message += "\n"

				for _, version := range name.Versions {
					message += "\t\t"
					message += "Version: " + version.Version + "\n"
					message += "\t\t"
					message += "Subpath: " + version.Subpath + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						message += "\t\t\t"
						message += outlier.Key + ": " + outlier.Value + "\n"
					}
					message += "\t\t}\n"
				}
			}
			message += "\n"
		}
		return message, nil
	case DepPkg:
		depPkg, ok := node.(model.AllIsDependencyTreeDependencyPackage)
		if !ok {
			return "", fmt.Errorf("could not case node to tree depPkg")
		}

		message := "Type:" + CheckEmpty(depPkg.Type) + "\n"
		for _, namespace := range depPkg.Namespaces {
			message += "Namespace: " + CheckEmpty(namespace.Namespace) + "\n"

			for _, name := range namespace.Names {
				message += "\t"
				message += "Name: " + CheckEmpty(name.Name)
				message += "\n"

				for _, version := range name.Versions {
					message += "\t\t"
					message += "Version: " + CheckEmpty(version.Version) + "\n"
					message += "\t\t"
					message += "Subpath: " + CheckEmpty(version.Subpath) + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						message += "\t\t\t"
						message += CheckEmpty(outlier.Key) + ": " + CheckEmpty(outlier.Value) + "\n"
					}
					message += "\t\t}\n"
				}
			}
			message += "\n"
		}
		return message, nil

	}

	return "", nil
}

func CheckEmpty(value string) string {
	if len(value) > 20 {
		return value[:20] + "..."
	}
	if value == "" {
		return "\"\""
	}
	return value
}


func PrintPathTable(header string, analysisOne, analysisTwo [][]*Node) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)

	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

	table.SetNoWhiteSpace(true)

	table.SetColumnSeparator("\t\t")
	table.SetAutoMergeCells(false)

	table.SetHeader([]string{header})

	for _, pathOne := range analysisOne {
		var row []string
		for i, nodeOne := range pathOne {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 50)
			} else {
				table.SetColMinWidth(i, 50)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}

				row = append(row, s)

			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}
		table.Append(row)

	}

	for _, pathTwo := range analysisTwo {
		var row []string
		for i, nodeOne := range pathTwo {
			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 50)
			} else {
				table.SetColMinWidth(i, 50)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)

			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}
		table.Append(row)
	}

	table.Render()
	return nil
}


func PrintDiffedPathTable(diffs []DiffedPath) error {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)

	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

	table.SetNoWhiteSpace(true)

	table.SetColumnSeparator("\t\t")
	table.SetAutoMergeCells(false)

	table.SetHeader([]string{"Path Differences"})

	for _, diff := range diffs {
		var row []string

		for i, nodeOne := range diff.PathOne {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 90)
			} else {
				table.SetColMinWidth(i, 90)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)

			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}

		table.Append(row)
		row = []string{}

		for i, nodeOne := range diff.PathTwo {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 50)
			} else {
				table.SetColMinWidth(i, 50)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}
		table.Append(row)

		table.Append([]string{"================================="})

		row  = []string{}
		for i, diff := range diff.Diffs {
			
			if len(row) != 0 {
				row = append(row, "    ")
				table.SetColMinWidth(i+1, 50)
			}else{
				table.SetColMinWidth(i, 50)
			}
			
			row = append(row, strings.Join(diff, "\n"))
		}
		table.Append(row)


		table.Append([]string{"================================="})
	}

	
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()
	return nil

}
