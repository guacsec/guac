package cyclonedx

import (
	"context"
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type cyclonedxParser struct {
	subject  assembler.ArtifactNode
	packages []assembler.PackageNode
}

func NewCycloneDXParser() *cyclonedxParser {
	return &cyclonedxParser{
		subject:  assembler.ArtifactNode{},
		packages: []assembler.PackageNode{},
	}
}

func (c *cyclonedxParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	nodes = append(nodes, c.subject)
	for _, p := range c.packages {
		nodes = append(nodes, p)
	}
	return nodes
}

// Parse breaks out the document into the graph components
func (c *cyclonedxParser) Parse(ctx context.Context, doc *processor.Document) error {
	cdxBom, err := parseCycloneDXBOM(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse cyclonedx BOM: %w", err)
	}
	c.addSubject(cdxBom)
	c.addPackages(cdxBom)

	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *cyclonedxParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}

func (c *cyclonedxParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}

	for _, p := range c.packages {
		edges = append(edges, assembler.ContainsEdge{PackageNode: p, ContainedArtifact: c.subject})
	}
	return edges
}

func (c *cyclonedxParser) addSubject(cdxBom *cdx.BOM) {
	c.subject.Name = cdxBom.Metadata.Component.Name
	c.subject.Digest = cdxBom.Metadata.Component.Version
}

func (c *cyclonedxParser) addPackages(cdxBom *cdx.BOM) {
	for _, comp := range *cdxBom.Components {
		c.packages = append(c.packages, assembler.PackageNode{
			Name:   comp.Name,
			Digest: []string{comp.Version},
			Purl:   comp.PackageURL,
			CPEs:   []string{comp.CPE},
		})
	}
}

func parseCycloneDXBOM(d []byte) (*cdx.BOM, error) {
	bom := cdx.BOM{}
	if err := json.Unmarshal(d, &bom); err != nil {
		return nil, err
	}
	return &bom, nil
}
