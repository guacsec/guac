package analyzer

import (
	"fmt"
	"os"
	"sort"

	"github.com/olekukonko/tablewriter"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
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
		message := "Type:" + depPkg.Type + "\n"
		for _, namespace := range depPkg.Namespaces {
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

	if err := ui.Init(); err != nil {
		return fmt.Errorf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	table := widgets.NewTable()
	table.Rows = [][]string{
		{"Node Differences"},
	}

	for _, diff := range diffs.Nodes {
		var row []string

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

		table.Rows = append(table.Rows, row)
		table.Rows = append(table.Rows, []string{fmt.Sprintf("Node pair causing %v paths to differ", diff.Count)})
	}

	table.TextStyle = ui.NewStyle(ui.ColorWhite)
	table.SetRect(0, 0, 100, 30)
	table.RowSeparator = true
	table.BorderStyle.Fg = ui.ColorCyan

	// Event handler for zoom
	uiEvents := ui.PollEvents()
	zoomFactor := 1

	for {
		ui.Render(table)
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return nil
		case "+":
			zoomFactor++
			table.SetRect(0, 0, 100*zoomFactor, 30*zoomFactor)
		case "-":
			if zoomFactor > 1 {
				zoomFactor--
				table.SetRect(0, 0, 100*zoomFactor, 30*zoomFactor)
			}
		}
	}
}

func PrintDiffedPathTable(diffs DiffResult) error {
	if len(diffs.Paths) == 0 {
		return nil
	}

	if err := ui.Init(); err != nil {
		return fmt.Errorf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	table := widgets.NewTable()
	// table.Rows = [][]string{
	// 	{"Path Differences"},
	// }

	for _, diff := range diffs.Paths {
		var row []string
		for _, node := range diff.NodeDiffs {
			if len(row) != 0 {
				row = append(row, "\t--->\t")
			}

			s, err := GetNodeString(node)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}
			row = append(row, s)
		}
		table.Rows = append(table.Rows, row)
	}

	table.TextStyle = ui.NewStyle(ui.ColorWhite) 
	table.SetRect(0, 0, 100, 30)
	table.RowSeparator = true
	table.BorderStyle.Fg = ui.ColorCyan

	// Event handler for zoom
	uiEvents := ui.PollEvents()
	zoomFactor := 1

	for {
		ui.Render(table)
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return nil
		case "+":
			zoomFactor++
			table.SetRect(0, 0, 100*zoomFactor, 30*zoomFactor)
		case "-":
			if zoomFactor > 1 {
				zoomFactor--
				table.SetRect(0, 0, 100*zoomFactor, 30*zoomFactor)
			}
		}
	}
}

// func PrintDiffedNodeTable(diffs DiffResult) error {
// 	if len(diffs.Nodes) == 0 {
// 		return nil
// 	}
// 	table := tablewriter.NewWriter(os.Stdout)
// 	table.SetAutoWrapText(false)

// 	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

// 	table.SetNoWhiteSpace(true)

// 	table.SetColumnSeparator("\t\t")
// 	table.SetAutoMergeCells(false)
// 	table.SetAutoWrapText(false)
// 	table.SetRowLine(true) 

// 	table.SetHeader([]string{"Node Differences"})
// 	var row []string

// 	table.SetColMinWidth(0, colMinWidth)
// 	table.SetColMinWidth(2, colMinWidth)

// 	for _, diff := range diffs.Nodes {

// 		s, err := GetNodeString(*diff.NodeOne)
// 		if err != nil {
// 			return fmt.Errorf("unable to print diffs: %v", err)
// 		}
// 		row = append(row, s)

// 		row = append(row, "<--->")

// 		s, err = GetNodeString(*diff.NodeTwo)
// 		if err != nil {
// 			return fmt.Errorf("unable to print diffs: %v", err)
// 		}
// 		row = append(row, s)
// 		table.Append(row)
// 		table.Append([]string{fmt.Sprintf("Node pair causing %v paths to differ", diff.Count)})
// 	}

// 	table.SetAlignment(tablewriter.ALIGN_LEFT)
// 	table.Render()
// 	return nil
// }

// func PrintDiffedPathTable(diffs DiffResult) error {
// 	if len(diffs.Paths) == 0 {
// 		return nil
// 	}

// 	table := tablewriter.NewWriter(os.Stdout)
// 	table.SetAutoWrapText(false)

// 	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

// 	table.SetNoWhiteSpace(true)
// 	table.SetRowLine(true) 


// 	table.SetAutoMergeCells(false)

// 	table.SetHeader([]string{"Path Differences"})

// 	for _, diff := range diffs.Paths {
// 		var row []string
// 		for i, node := range diff.NodeDiffs {
// 			if len(row) != 0 {
// 				row = append(row, "--->")
// 				table.SetColMinWidth(i+1, colMinWidth)
// 			} else {
// 				table.SetColMinWidth(i, colMinWidth)
// 			}

// 			s, err := GetNodeString(node)

// 			if err != nil {
// 				return fmt.Errorf("unable to print diffs: %v", err)
// 			}
// 			row = append(row, s)
// 		}
	
// 		table.Append(row)
// 	}

// 	table.SetAlignment(tablewriter.ALIGN_LEFT)
// 	table.Render()
// 	return nil

// }
