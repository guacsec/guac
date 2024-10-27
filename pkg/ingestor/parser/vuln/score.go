package vuln

import (
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation/vuln"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

func parseScoreBasedOnMethod(severity attestation_vuln.Severity) (float64, error) {
	score := severity.Score
	switch severity.Method {
	// TODO: match for other score types
	case string(generated.VulnerabilityScoreTypeCvssv2):
		vector, err := gocvss20.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.BaseScore(), nil
	case string(generated.VulnerabilityScoreTypeCvssv3):
		vector, err := gocvss30.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.BaseScore(), nil
	case string(generated.VulnerabilityScoreTypeCvssv31):
		vector, err := gocvss31.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.BaseScore(), nil
	case string(generated.VulnerabilityScoreTypeCvssv4):
		vector, err := gocvss40.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.Score(), nil
	}
	return strconv.ParseFloat(score, 64)
}
