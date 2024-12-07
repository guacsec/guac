package analyzer

import (
	"fmt"
	"sort"
	"strings"

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

	// Function to add paths to the table
	addPathsToTable := func(paths [][]*Node, startRowIndex int) (int, error) {
		rowIndex := startRowIndex

		for _, path := range paths {
			columnIndex := 0
			rowStart := rowIndex
			for i, node := range path {
				s, err := GetNodeString(*node)
				if err != nil {
					return rowIndex, fmt.Errorf("unable to process node: %v", err)
				}

				// Split the string by newline and handle tabs
				lines := strings.Split(s, "\n")
				for _, line := range lines {
					// Replace tabs with spaces for better alignment
					formattedLine := strings.ReplaceAll(line, "\t", "    ")
					table.SetCell(rowIndex, columnIndex, tview.NewTableCell(formattedLine).
						SetTextColor(tcell.ColorWhite).
						SetAlign(tview.AlignLeft).
						SetSelectable(true))
					rowIndex++
				}

				if i != len(path)-1 {
					table.SetCell(rowStart, columnIndex+1, tview.NewTableCell("--->").
						SetTextColor(tcell.ColorWhite).
						SetAlign(tview.AlignCenter).
						SetSelectable(false))
					columnIndex++
				}

				if i != len(path)-1 {
					rowIndex = rowStart
				}

				columnIndex++
			}

		}
		return rowIndex, nil
	}

	// Add Analysis One Paths
	var err error
	rowIndex, err = addPathsToTable(analysisOne, rowIndex)
	if err != nil {
		return err
	}

	// Add Analysis Two Paths
	_, err = addPathsToTable(analysisTwo, rowIndex)
	if err != nil {
		return err
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

			nodeOneLines := strings.Split(nodeOneStr, "\n")
			nodeTwoLines := strings.Split(nodeTwoStr, "\n")

			// Determine the maximum lines for alignment
			maxLines := len(nodeOneLines)
			if len(nodeTwoLines) > maxLines {
				maxLines = len(nodeTwoLines)
			}

			// Print each line, padding shorter sections with empty strings
			for i := 0; i < maxLines; i++ {
				// Get the current line or an empty string if out of bounds
				nodeOneLine := ""
				if i < len(nodeOneLines) {
					nodeOneLine = strings.ReplaceAll(nodeOneLines[i], "\t", "    ")
				}

				nodeTwoLine := ""
				if i < len(nodeTwoLines) {
					nodeTwoLine = strings.ReplaceAll(nodeTwoLines[i], "\t", "    ")
				}

				// Add cells for the row
				table.SetCell(rowIndex, 0, tview.NewTableCell(nodeOneLine).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignLeft).
					SetSelectable(false))
				if i == 0 {
					table.SetCell(rowIndex, 1, tview.NewTableCell("<-->").
						SetTextColor(tcell.ColorWhite).
						SetAlign(tview.AlignCenter).
						SetSelectable(false))
				} else {
					table.SetCell(rowIndex, 1, tview.NewTableCell("").
						SetSelectable(false)) // Empty for alignment
				}
				table.SetCell(rowIndex, 2, tview.NewTableCell(nodeTwoLine).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignLeft).
					SetSelectable(false))
				rowIndex++
			}

			// Add the count on the same row as the connector, only once
			table.SetCell(rowIndex-maxLines, 3, tview.NewTableCell(fmt.Sprintf("%v", diff.Count)).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignCenter).
				SetSelectable(false))
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
			rowStart := rowIndex

			for i, node := range diff.NodeDiffs {
				nodeStr, err := GetNodeString(node)
				if err != nil {
					return fmt.Errorf("error processing path node: %v", err)
				}

				// Split the content into lines
				lines := strings.Split(nodeStr, "\n")
				for _, line := range lines {
					// Replace tabs with spaces
					formattedLine := strings.ReplaceAll(line, "\t", "    ")
					table.SetCell(rowIndex, columnIndex, tview.NewTableCell(formattedLine).
						SetTextColor(tcell.ColorWhite).
						SetAlign(tview.AlignLeft).
						SetSelectable(true))
					rowIndex++
				}

				// Reset row index after multi-line node content
				if i != len(diff.NodeDiffs)-1 {
					table.SetCell(rowStart, columnIndex+1, tview.NewTableCell("--->").
						SetTextColor(tcell.ColorWhite).
						SetAlign(tview.AlignCenter).
						SetSelectable(false))
					columnIndex++
					rowIndex = rowStart
				}
				columnIndex++
			}

			rowIndex++ // Move to the next row after the path
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
