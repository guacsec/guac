package analyzer

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
)

const (
	colMinWidth = 50
	trimLength  = 20
)

func GetNodeString(node Node) (string, error) {
	switch node.NodeType {

	case "Package":
		pkg := node.Pkg

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
	case "DependencyPackage":
		depPkg := node.DepPkg

		message := "Type:" + CheckEmptyTrim(depPkg.Type) + "\n"
		for _, namespace := range depPkg.Namespaces {
			message += "Namespace: " + CheckEmptyTrim(namespace.Namespace) + "\n"

			for _, name := range namespace.Names {
				message += "\t"
				message += "Name: " + CheckEmptyTrim(name.Name)
				message += "\n"

				for _, version := range name.Versions {
					message += "\t\t"
					message += "Version: " + CheckEmptyTrim(version.Version) + "\n"
					message += "\t\t"
					message += "Subpath: " + CheckEmptyTrim(version.Subpath) + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						message += "\t\t\t"
						message += CheckEmptyTrim(outlier.Key) + ": " + CheckEmptyTrim(outlier.Value) + "\n"
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

func CheckEmptyTrim(value string) string {
	if len(value) > trimLength {
		return value[:trimLength] + "..."
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
				table.SetColMinWidth(i+1, colMinWidth)
			} else {
				table.SetColMinWidth(i, colMinWidth)
			}

			s, err := GetNodeString(*nodeOne)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}

			row = append(row, s)

		}
		table.Append(row)

	}

	for _, pathTwo := range analysisTwo {
		var row []string
		for i, nodeOne := range pathTwo {
			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, colMinWidth)
			} else {
				table.SetColMinWidth(i, colMinWidth)
			}

			s, err := GetNodeString(*nodeOne)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}
			row = append(row, s)

		}
		table.Append(row)
	}

	table.Render()
	return nil
}

func PrintDiffedNodeTable(diffs DiffResult) error {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)

	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

	table.SetNoWhiteSpace(true)

	table.SetColumnSeparator("\t\t")
	table.SetAutoMergeCells(false)

	table.SetHeader([]string{"Node Differences"})
	var row []string

	table.SetColMinWidth(0, colMinWidth)
	table.SetColMinWidth(2, colMinWidth)

	for _, diff := range diffs.Nodes {

		s, err := GetNodeString(*diff.NodeOne)
		if err != nil {
			return fmt.Errorf("unable to print diffs: %v", err)
		}
		row = append(row, s)

		row = append(row, "<--->")

		s, err = GetNodeString(*diff.NodeTwo)
		if err != nil {
			return fmt.Errorf("unable to print diffs: %v", err)
		}
		row = append(row, s)
		table.Append(row)

		table.Append([]string{"================================="})
		table.Append([]string{fmt.Sprintf("Node pair causing %v paths to differ", diff.Count)})
		table.Append([]string{"================================="})
	}

	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()
	return nil

}

func PrintDiffedPathTable(diffs DiffResult) error {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)

	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

	table.SetNoWhiteSpace(true)

	table.SetColumnSeparator("\t\t")
	table.SetAutoMergeCells(false)

	table.SetHeader([]string{"Path Differences"})

	for _, diff := range diffs.Paths {
		var row []string

		for i, nodeOne := range diff.PathOne {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, colMinWidth)
			} else {
				table.SetColMinWidth(i, colMinWidth)
			}

			s, err := GetNodeString(*nodeOne)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}
			row = append(row, s)

		}

		table.Append(row)
		row = []string{}

		for i, nodeOne := range diff.PathTwo {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, colMinWidth)
			} else {
				table.SetColMinWidth(i, colMinWidth)
			}

			s, err := GetNodeString(*nodeOne)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}
			row = append(row, s)

		}
		table.Append(row)

		table.Append([]string{"================================="})

		row = []string{}
		for i, diff := range diff.Diffs {

			if len(row) != 0 {
				row = append(row, "    ")
				table.SetColMinWidth(i+1, colMinWidth)
			} else {
				table.SetColMinWidth(i, colMinWidth)
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
