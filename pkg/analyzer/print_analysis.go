package analyzer

import (
	"fmt"
	"sort"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	colMinWidth = 50
	trimLength  = 150
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
	app := tview.NewApplication()

	// Create a scrollable Table
	table := tview.NewTable().
		SetBorders(true) // Add borders to the table for readability

	// Add Header Row
	table.SetCell(0, 0, tview.NewTableCell(header).
		SetTextColor(tcell.ColorYellow).
		SetAlign(tview.AlignCenter).
		SetSelectable(false)) // Header is not selectable

	rowIndex := 1 // Start adding rows below the header

	// Add Analysis One Paths
	for _, pathOne := range analysisOne {
		columnIndex := 0
		for _, nodeOne := range pathOne {
			s, err := GetNodeString(*nodeOne)
			if err != nil {
				return fmt.Errorf("unable to process node: %v", err)
			}

			if columnIndex > 0 {
				table.SetCell(rowIndex, columnIndex, tview.NewTableCell("--->").
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter).
					SetSelectable(false))
				columnIndex++
			}

			table.SetCell(rowIndex, columnIndex, tview.NewTableCell(s).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignLeft).
				SetSelectable(true)) // Allow selection
			columnIndex++
		}
		rowIndex++
	}

	// Add Analysis Two Paths
	for _, pathTwo := range analysisTwo {
		columnIndex := 0
		for _, nodeOne := range pathTwo {
			s, err := GetNodeString(*nodeOne)
			if err != nil {
				return fmt.Errorf("unable to process node: %v", err)
			}

			if columnIndex > 0 {
				table.SetCell(rowIndex, columnIndex, tview.NewTableCell("--->").
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter).
					SetSelectable(false))
				columnIndex++
			}

			table.SetCell(rowIndex, columnIndex, tview.NewTableCell(s).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignLeft).
				SetSelectable(true)) // Allow selection
			columnIndex++
		}
		rowIndex++
	}

	// Enable both horizontal and vertical scrolling
	table.SetFixed(1, 0).SetSelectable(true, true)

	// Handle quit events
	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlC: // Exit on Esc or Ctrl+C
			app.Stop()
		}
		return event
	})

	// Set up the application root with the table
	if err := app.SetRoot(table, true).Run(); err != nil {
		return fmt.Errorf("error running table application: %v", err)
	}

	return nil
}

func PrintAnalysis(diffs DiffResult) error {
	app := tview.NewApplication()
	table := tview.NewTable().
		SetBorders(true)

	rowIndex := 0

	// Add Node Differences if present
	if len(diffs.Nodes) > 0 {
		table.SetCell(rowIndex, 0, tview.NewTableCell("Node Analysis").
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
		rowIndex++

		// Add Node Differences Data
		for _, diff := range diffs.Nodes {
			nodeOneStr, err := GetNodeString(*diff.NodeOne)
			if err != nil {
				return fmt.Errorf("error processing node one: %v", err)
			}

			nodeTwoStr, err := GetNodeString(*diff.NodeTwo)
			if err != nil {
				return fmt.Errorf("error processing node two: %v", err)
			}

			table.SetCell(rowIndex, 0, tview.NewTableCell(nodeOneStr).SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignLeft))
			table.SetCell(rowIndex, 1, tview.NewTableCell("<-->").SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignCenter))
			table.SetCell(rowIndex, 2, tview.NewTableCell(nodeTwoStr).SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignLeft))
			table.SetCell(rowIndex, 3, tview.NewTableCell(fmt.Sprintf("%v", diff.Count)).SetTextColor(tcell.ColorWhite).SetAlign(tview.AlignCenter))
			rowIndex++
		}
	}

	// Add Path Differences if present
	if len(diffs.Paths) > 0 {
		if rowIndex > 0 {
			rowIndex++ // Add spacing between sections
		}
		table.SetCell(rowIndex, 0, tview.NewTableCell("Path Analysis").
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
		rowIndex++

		// Add Path Differences Data
		for _, diff := range diffs.Paths {
			columnIndex := 0
			for _, node := range diff.NodeDiffs {
				nodeStr, err := GetNodeString(node)
				if err != nil {
					return fmt.Errorf("error processing path node: %v", err)
				}

				table.SetCell(rowIndex, columnIndex, tview.NewTableCell(nodeStr).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignLeft).
					SetSelectable(true))
				table.SetCell(rowIndex, columnIndex+1, tview.NewTableCell("--->").
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignLeft).
					SetSelectable(false))
				columnIndex += 2
			}
			rowIndex++
		}
	}

	// Enable scrolling and quit handling
	table.SetFixed(1, 0).SetSelectable(true, true)
	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc || event.Key() == tcell.KeyCtrlC {
			app.Stop()
		}
		return event
	})

	// Run the application
	if err := app.SetRoot(table, true).Run(); err != nil {
		return fmt.Errorf("error running table application: %v", err)
	}

	return nil
}

func PrintAnalyzedPathTable(diffs DiffResult) error {
	if len(diffs.Paths) == 0 {
		return nil
	}

	app := tview.NewApplication()

	// Create a scrollable Table
	table := tview.NewTable().
		SetBorders(true) // Add borders to the table for readability

	// Add Header Row
	table.SetCell(0, 0, tview.NewTableCell("Path Nodes").
		SetTextColor(tcell.ColorYellow).
		SetAlign(tview.AlignCenter).
		SetSelectable(false)) // Header is not selectable

	// Add Path Data (Rows for each diff.NodeDiffs)
	for rowIndex, diff := range diffs.Paths {
		columnIndex := 0
		for _, node := range diff.NodeDiffs {
			nodeStr, err := GetNodeString(node)
			if err != nil {
				return fmt.Errorf("unable to print diffs: %v", err)
			}

			// Add the multi-line content directly to the table cell
			table.SetCell(rowIndex+1, columnIndex, tview.NewTableCell(nodeStr).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignLeft).
				SetSelectable(true)) // Allow selection
			columnIndex++
		}
	}

	// Enable both horizontal and vertical scrolling
	table.SetFixed(1, 0)            // Keep the header fixed during scrolling
	table.SetSelectable(true, true) // Enable row and column selection

	// Handle quit events
	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlC: // Exit on Esc or Ctrl+C
			app.Stop()
		}
		return event
	})

	// Set up the application root with the table
	if err := app.SetRoot(table, true).Run(); err != nil {
		return fmt.Errorf("error running table application: %v", err)
	}

	return nil
}
