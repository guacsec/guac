package depversion

type VersionValue struct {
	SemVer        *string
	UnknownString *string
}

type VersionMatchObject struct {
	VRSet []VersionRange
	// Exact used in the case where heuristics can't determine semvers
	Exact *string
}

type VersionRange struct {
	Constraint string
}

func ParseVersionRange(s string) (VersionMatchObject, error) {
	return VersionMatchObject{}, nil
}
