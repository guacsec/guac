package vuln

import (
	"strconv"
	"strings"

	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation/vuln"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

func parseScoreBasedOnMethod(severity attestation_vuln.Severity) (float64, error) {
	score := severity.Score
	switch {
	// TODO: match for other score types
	case strings.HasPrefix(score, "CVSS:2.0"):
		vector, err := gocvss20.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.BaseScore(), nil
	case strings.HasPrefix(score, "CVSS:3.0"):
		vector, err := gocvss30.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.BaseScore(), nil
	case strings.HasPrefix(score, "CVSS:3.1"):
		vector, err := gocvss31.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.BaseScore(), nil
	case strings.HasPrefix(score, "CVSS:4.0"):
		vector, err := gocvss40.ParseVector(score)
		if err != nil {
			return 0, err
		}
		return vector.Score(), nil
	}
	return strconv.ParseFloat(score, 64)
}
