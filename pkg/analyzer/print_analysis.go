package analyzer

import (
	"fmt"
	"os"
	"sort"

	"github.com/olekukonko/tablewriter"
	"github.com/jedib0t/go-pretty/v6/table"
)

const (
	colMinWidth = 50
	trimLength = 150
)

func GetNodeString(node Node) (string, error) {
	switch node.NodeType {

	case "Package":
		pkg := node.Pkg
		sort.Sort(packageNameSpaces(pkg.Namespaces))
		message := "Type:" + pkg.Type + "\n"
		for _, namespace := range pkg.Namespaces {
			if namespace.Namespace == "" {
				continue
			}
			message += "Namespace: " + namespace.Namespace + "\n"

			for _, name := range namespace.Names {
				if name.Name == "" {
					continue
				}
				message += "\t"
				message += "Name: " + name.Name
				message += "\n"

				for _, version := range name.Versions {
					if version.Version == "" {
						continue
					}
					message += "\t\t"
					message += "Version: " + version.Version + "\n"
					message += "\t\t"
					message += "Subpath: " + version.Subpath + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						if outlier.Key == "" {
							continue
						}
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
		message := "Type:" + depPkg.Type + "\n"
		for _, namespace := range depPkg.Namespaces {
			if namespace.Namespace == "" {
				continue
			}
			message += "Namespace: " + namespace.Namespace + "\n"

			for _, name := range namespace.Names {
				if name.Name == "" {
					continue
				}
				message += "\t"
				message += "Name: " + name.Name
				message += "\n"

				for _, version := range name.Versions {
					if version.Version == "" {
						continue
					}
					message += "\t\t"
					message += "Version: " + version.Version + "\n"
					message += "\t\t"
					message += "Subpath: " + version.Subpath + "\n"
					message += "\t\tQualifiers: {\n"

					for _, outlier := range version.Qualifiers {
						if outlier.Key == "" {
							continue
						}
						message += "\t\t\t"
						message += outlier.Key + ": " + outlier.Value + "\n"
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
	if len(diffs.Nodes) == 0 {
		return nil
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.SetTitle("Node Differences")
	t.AppendHeader(table.Row{"Node One", "\t", "Node Two", "Difference Count"})

	for _, diff := range diffs.Nodes {
		nodeOneStr, err := GetNodeString(*diff.NodeOne)
		if err != nil {
			return fmt.Errorf("unable to print diffs: %v", err)
		}

		nodeTwoStr, err := GetNodeString(*diff.NodeTwo)
		if err != nil {
			return fmt.Errorf("unable to print diffs: %v", err)
		}

		// Create a row for the table
		row := table.Row{
			nodeOneStr,       // First node representation
			"<--->",          // Separator
			nodeTwoStr,       // Second node representation
			fmt.Sprintf("%v", diff.Count), // Difference count
		}

		t.AppendRow(row)
	}

	t.Render()
	return nil
}

func PrintDiffedPathTable(diffs DiffResult) error {
	if len(diffs.Paths) == 0 {
		return nil
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.SetTitle("Path Differences")
	
	


	for _, diff := range diffs.Paths {
		var row []string
		for _, node := range diff.NodeDiffs {
	
			nodeStr, err := GetNodeString(node)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}
			row = append(row, nodeStr)
		}
		// Convert []string to table.Row (which is []interface{})
		interfaceRow := make(table.Row, len(row))
		for i, val := range row {
			interfaceRow[i] = val
		}

		// Append the row to the table
		t.AppendRow(interfaceRow)
	}

	t.Render()
	return nil
}
