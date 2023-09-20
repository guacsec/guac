//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package arangodb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) CertifyLegal(ctx context.Context, certifyLegalSpec *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {

	var aqb *arangoQueryBuilder
	if certifyLegalSpec.Subject != nil {
		var combinedCertifyLegal []*model.CertifyLegal
		if certifyLegalSpec.Subject.Package != nil {
			values := map[string]any{}
			// pkg certifyLegal
			aqb = setPkgVersionMatchValues(certifyLegalSpec.Subject.Package, values)
			aqb.forOutBound(certifyLegalPkgEdgesStr, "certifyLegal", "pVersion")
			setCertifyLegalMatchValues(aqb, certifyLegalSpec, values)

			pkgCertifyLegals, err := getPkgCertifyLegalForQuery(ctx, c, aqb, values,
				certifyLegalSpec.DeclaredLicenses, certifyLegalSpec.DiscoveredLicenses)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version certifyLegal with error: %w", err)
			}

			combinedCertifyLegal = append(combinedCertifyLegal, pkgCertifyLegals...)

		}
		if certifyLegalSpec.Subject.Source != nil {
			values := map[string]any{}
			aqb = setSrcMatchValues(certifyLegalSpec.Subject.Source, values)
			aqb.forOutBound(certifyLegalSrcEdgesStr, "certifyLegal", "sName")
			setCertifyLegalMatchValues(aqb, certifyLegalSpec, values)

			srcCertifyLegals, err := getSrcCertifyLegalForQuery(ctx, c, aqb, values,
				certifyLegalSpec.DeclaredLicenses, certifyLegalSpec.DiscoveredLicenses)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve source certifyLegal with error: %w", err)
			}

			combinedCertifyLegal = append(combinedCertifyLegal, srcCertifyLegals...)
		}
		return combinedCertifyLegal, nil
	}
	values := map[string]any{}
	var combinedCertifyLegal []*model.CertifyLegal

	// pkg certifyLegal
	aqb = newForQuery(certifyLegalsStr, "certifyLegal")
	setCertifyLegalMatchValues(aqb, certifyLegalSpec, values)
	aqb.forInBound(certifyLegalPkgEdgesStr, "pVersion", "certifyLegal")
	aqb.forInBound(pkgHasVersionStr, "pName", "pVersion")
	aqb.forInBound(pkgHasNameStr, "pNs", "pName")
	aqb.forInBound(pkgHasNamespaceStr, "pType", "pNs")

	pkgCertifyLegals, err := getPkgCertifyLegalForQuery(ctx, c, aqb, values,
		certifyLegalSpec.DeclaredLicenses, certifyLegalSpec.DiscoveredLicenses)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve package version certifyLegal  with error: %w", err)
	}
	combinedCertifyLegal = append(combinedCertifyLegal, pkgCertifyLegals...)

	// get sources
	values = map[string]any{}
	aqb = newForQuery(certifyLegalsStr, "certifyLegal")
	setCertifyLegalMatchValues(aqb, certifyLegalSpec, values)
	aqb.forInBound(certifyLegalSrcEdgesStr, "sName", "certifyLegal")
	aqb.forInBound(srcHasNameStr, "sNs", "sName")
	aqb.forInBound(srcHasNamespaceStr, "sType", "sNs")

	srcCertifyLegals, err := getSrcCertifyLegalForQuery(ctx, c, aqb, values,
		certifyLegalSpec.DeclaredLicenses, certifyLegalSpec.DiscoveredLicenses)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve source certifyLegal with error: %w", err)
	}
	combinedCertifyLegal = append(combinedCertifyLegal, srcCertifyLegals...)

	return combinedCertifyLegal, nil
}

func getSrcCertifyLegalForQuery(ctx context.Context, c *arangoClient,
	aqb *arangoQueryBuilder, values map[string]any,
	decFilter, disFilter []*model.LicenseSpec) ([]*model.CertifyLegal, error) {
	aqb.query.WriteString("\n")
	aqb.query.WriteString(`RETURN {
    'srcName': {
    'type_id': sType._id,
    'type': sType.type,
    'namespace_id': sNs._id,
    'namespace': sNs.namespace,
    'name_id': sName._id,
    'name': sName.name,
    'commit': sName.commit,
    'tag': sName.tag
  },
  'certifyLegal_id': certifyLegal._id,
  'declaredLicense': certifyLegal.declaredLicense,
  'declaredLicenses': certifyLegal.declaredLicenses,
  'discoveredLicense': certifyLegal.discoveredLicense,
  'discoveredLicenses': certifyLegal.discoveredLicenses,
  'attribution': certifyLegal.attribution,
  'justification': certifyLegal.justification,
  'timeScanned': certifyLegal.timeScanned,
  'collector': certifyLegal.collector,
  'origin': certifyLegal.origin
}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, aqb.string(), values, "CertifyLegal")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyLegal: %w", err)
	}
	defer cursor.Close()

	return c.getCertifyLegalFromCursor(ctx, cursor, decFilter, disFilter)
}

func getPkgCertifyLegalForQuery(ctx context.Context, c *arangoClient,
	aqb *arangoQueryBuilder, values map[string]any,
	decFilter, disFilter []*model.LicenseSpec) ([]*model.CertifyLegal, error) {
	aqb.query.WriteString("\n")
	aqb.query.WriteString(`RETURN {
  'pkgVersion': {
    'type_id': pType._id,
    'type': pType.type,
    'namespace_id': pNs._id,
    'namespace': pNs.namespace,
    'name_id': pName._id,
    'name': pName.name,
    'version_id': pVersion._id,
    'version': pVersion.version,
    'subpath': pVersion.subpath,
    'qualifier_list': pVersion.qualifier_list
  },
  'certifyLegal_id': certifyLegal._id,
  'declaredLicense': certifyLegal.declaredLicense,
  'declaredLicenses': certifyLegal.declaredLicenses,
  'discoveredLicense': certifyLegal.discoveredLicense,
  'discoveredLicenses': certifyLegal.discoveredLicenses,
  'attribution': certifyLegal.attribution,
  'justification': certifyLegal.justification,
  'timeScanned': certifyLegal.timeScanned,
  'collector': certifyLegal.collector,
  'origin': certifyLegal.origin
}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, aqb.string(), values, "CertifyLegal")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyLegal: %w", err)
	}
	defer cursor.Close()

	return c.getCertifyLegalFromCursor(ctx, cursor, decFilter, disFilter)
}

func setCertifyLegalMatchValues(aqb *arangoQueryBuilder, certifyLegalSpec *model.CertifyLegalSpec, queryValues map[string]any) {
	if certifyLegalSpec.ID != nil {
		aqb.filter("certifyLegal", "_id", "==", "@id")
		queryValues["id"] = *certifyLegalSpec.ID
	}
	if certifyLegalSpec.DeclaredLicense != nil {
		aqb.filter("certifyLegal", "declaredLicense", "==", "@declaredLicense")
		queryValues["declaredLicense"] = *certifyLegalSpec.DeclaredLicense
	}
	if certifyLegalSpec.DiscoveredLicense != nil {
		aqb.filter("certifyLegal", "discoveredLicense", "==", "@discoveredLicense")
		queryValues["discoveredLicense"] = *certifyLegalSpec.DiscoveredLicense
	}
	if certifyLegalSpec.Attribution != nil {
		aqb.filter("certifyLegal", "attribution", "==", "@attribution")
		queryValues["attribution"] = *certifyLegalSpec.Attribution
	}
	if certifyLegalSpec.Justification != nil {
		aqb.filter("certifyLegal", justification, "==", "@"+justification)
		queryValues[justification] = *certifyLegalSpec.Justification
	}
	if certifyLegalSpec.TimeScanned != nil {
		aqb.filter("certifyLegal", "timeScanned", "==", "@timeScanned")
		queryValues["timeScanned"] = *certifyLegalSpec.TimeScanned
	}
	if certifyLegalSpec.Origin != nil {
		aqb.filter("certifyLegal", origin, "==", "@"+origin)
		queryValues[origin] = *certifyLegalSpec.Origin
	}
	if certifyLegalSpec.Collector != nil {
		aqb.filter("certifyLegal", collector, "==", "@"+collector)
		queryValues[collector] = *certifyLegalSpec.Collector
	}
}

func getCertifyLegalQueryValues(pkg *model.PkgInputSpec, source *model.SourceInputSpec, dec []*model.License, dis []*model.License, certifyLegal *model.CertifyLegalInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		source := guacSrcId(*source)
		values["srcNameGuacKey"] = source.NameId
	}

	var decIDList []string
	// KeyLists must be empty and not nil for use in the arango query.
	decKeyList := []string{}
	for _, l := range dec {
		decIDList = append(decIDList, l.ID)
		splitID := strings.Split(l.ID, "/")
		decKeyList = append(decKeyList, splitID[1])
	}
	values["declaredLicenses"] = decIDList
	values["declaredLicensesKeyList"] = decKeyList

	var disIDList []string
	disKeyList := []string{}
	for _, l := range dis {
		disIDList = append(disIDList, l.ID)
		splitID := strings.Split(l.ID, "/")
		disKeyList = append(disKeyList, splitID[1])
	}
	values["discoveredLicenses"] = disIDList
	values["discoveredLicensesKeyList"] = disKeyList

	values["declaredLicense"] = certifyLegal.DeclaredLicense
	values["discoveredLicense"] = certifyLegal.DiscoveredLicense
	values["attribution"] = certifyLegal.Attribution
	values["justification"] = certifyLegal.Justification
	values["timeScanned"] = certifyLegal.TimeScanned
	values["origin"] = certifyLegal.Origin
	values["collector"] = certifyLegal.Collector

	return values
}

func (c *arangoClient) IngestCertifyLegal(
	ctx context.Context,
	subject model.PackageOrSourceInput,
	declaredLicenses []*model.LicenseInputSpec,
	discoveredLicenses []*model.LicenseInputSpec,
	certifyLegal *model.CertifyLegalInputSpec) (*model.CertifyLegal, error) {

	dec, err := c.getLicenses(ctx, declaredLicenses)
	if err != nil {
		return nil, fmt.Errorf("failed to get declared licenses list with error: %w", err)
	}

	dis, err := c.getLicenses(ctx, discoveredLicenses)
	if err != nil {
		return nil, fmt.Errorf("failed to get discovered licenses list with error: %w", err)
	}

	if subject.Package != nil {
		query := `
LET firstPkg = FIRST(
    FOR pVersion in pkgVersions
      FILTER pVersion.guacKey == @pkgVersionGuacKey
    FOR pName in pkgNames
      FILTER pName._id == pVersion._parent
    FOR pNs in pkgNamespaces
      FILTER pNs._id == pName._parent
    FOR pType in pkgTypes
      FILTER pType._id == pNs._parent

    RETURN {
      'typeID': pType._id,
      'type': pType.type,
      'namespace_id': pNs._id,
      'namespace': pNs.namespace,
      'name_id': pName._id,
      'name': pName.name,
      'version_id': pVersion._id,
      'version': pVersion.version,
      'subpath': pVersion.subpath,
      'qualifier_list': pVersion.qualifier_list,
      'versionDoc': pVersion
    }
)

LET certifyLegal = FIRST(
  UPSERT {
    packageID:firstPkg.version_id,
    declaredLicense:@declaredLicense,
    declaredLicenses:@declaredLicenses,
    discoveredLicense:@discoveredLicense,
    discoveredLicenses:@discoveredLicenses,
    attribution:@attribution,
    justification:@justification,
    timeScanned:@timeScanned,
    collector:@collector,
    origin:@origin
  }
  INSERT {
    packageID:firstPkg.version_id,
    declaredLicense:@declaredLicense,
    declaredLicenses:@declaredLicenses,
    discoveredLicense:@discoveredLicense,
    discoveredLicenses:@discoveredLicenses,
    attribution:@attribution,
    justification:@justification,
    timeScanned:@timeScanned,
    collector:@collector,
    origin:@origin
  }
  UPDATE {} IN certifyLegals
  RETURN NEW
)

LET edgeCollection = (
  INSERT {  _key: CONCAT("certifyLegalPkgEdges", firstPkg.versionDoc._key, certifyLegal._key), _from: firstPkg.version_id, _to: certifyLegal._id } INTO certifyLegalPkgEdges OPTIONS { overwriteMode: "ignore" }
)

LET declaredLicensesCollection = (FOR decData IN @declaredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDeclaredLicensesEdges", certifyLegal._key, decData), _from: certifyLegal._id, _to: CONCAT("licenses/", decData) } INTO certifyLegalDeclaredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

LET discoveredLicensesCollection = (FOR disData IN @discoveredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDiscoveredLicensesEdges", certifyLegal._key, disData), _from: certifyLegal._id, _to: CONCAT("licenses/", disData) } INTO certifyLegalDiscoveredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

RETURN {
  'pkgVersion': {
      'type_id': firstPkg.typeID,
      'type': firstPkg.type,
      'namespace_id': firstPkg.namespace_id,
      'namespace': firstPkg.namespace,
      'name_id': firstPkg.name_id,
      'name': firstPkg.name,
      'version_id': firstPkg.version_id,
      'version': firstPkg.version,
      'subpath': firstPkg.subpath,
      'qualifier_list': firstPkg.qualifier_list
  },
  'certifyLegal_id': certifyLegal._id,
  'declaredLicense': certifyLegal.declaredLicense,
  'declaredLicenses': certifyLegal.declaredLicenses,
  'discoveredLicense': certifyLegal.discoveredLicense,
  'discoveredLicenses': certifyLegal.discoveredLicenses,
  'attribution': certifyLegal.attribution,
  'justification': certifyLegal.justification,
  'timeScanned': certifyLegal.timeScanned,
  'collector': certifyLegal.collector,
  'origin': certifyLegal.origin
}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyLegalQueryValues(subject.Package, nil, dec, dis, certifyLegal), "IngestCertifyLegal - Pkg")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package certifyLegal: %w", err)
		}
		defer cursor.Close()

		certifyLegalList, err := c.getCertifyLegalFromCursor(ctx, cursor, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyLegals from arango cursor: %w", err)
		}

		if len(certifyLegalList) == 1 {
			return certifyLegalList[0], nil
		}
		return nil, fmt.Errorf("number of certifyLegal ingested is greater than one")
	}

	if subject.Source != nil {
		query := `
LET firstSrc = FIRST(
    FOR sName in srcNames
      FILTER sName.guacKey == @srcNameGuacKey
    FOR sNs in srcNamespaces
      FILTER sNs._id == sName._parent
    FOR sType in srcTypes
      FILTER sType._id == sNs._parent

    RETURN {
      'typeID': sType._id,
      'type': sType.type,
      'namespace_id': sNs._id,
      'namespace': sNs.namespace,
      'name_id': sName._id,
      'name': sName.name,
      'commit': sName.commit,
      'tag': sName.tag,
      'nameDoc': sName
    }
)

LET certifyLegal = FIRST(
  UPSERT {
    sourceID:firstSrc.name_id,
    declaredLicense:@declaredLicense,
    declaredLicenses:@declaredLicenses,
    discoveredLicense:@discoveredLicense,
    discoveredLicenses:@discoveredLicenses,
    attribution:@attribution,
    justification:@justification,
    timeScanned:@timeScanned,
    collector:@collector,
    origin:@origin
  }
  INSERT {
    sourceID:firstSrc.name_id,
    declaredLicense:@declaredLicense,
    declaredLicenses:@declaredLicenses,
    discoveredLicense:@discoveredLicense,
    discoveredLicenses:@discoveredLicenses,
    attribution:@attribution,
    justification:@justification,
    timeScanned:@timeScanned,
    collector:@collector,
    origin:@origin
  }
  UPDATE {} IN certifyLegals
  RETURN NEW
)

LET edgeCollection = (
  INSERT {  _key: CONCAT("certifyLegalSrcEdges", firstSrc.nameDoc._key, certifyLegal._key), _from: firstSrc.name_id, _to: certifyLegal._id } INTO certifyLegalSrcEdges OPTIONS { overwriteMode: "ignore" }
)

LET declaredLicensesCollection = (FOR decData IN @declaredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDeclaredLicensesEdges", certifyLegal._key, decData), _from: certifyLegal._id, _to: CONCAT("licenses/", decData) } INTO certifyLegalDeclaredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

LET discoveredLicensesCollection = (FOR disData IN @discoveredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDiscoveredLicensesEdges", certifyLegal._key, disData), _from: certifyLegal._id, _to: CONCAT("licenses/", disData) } INTO certifyLegalDiscoveredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

RETURN {
  'srcName': {
      'type_id': firstSrc.typeID,
      'type': firstSrc.type,
      'namespace_id': firstSrc.namespace_id,
      'namespace': firstSrc.namespace,
      'name_id': firstSrc.name_id,
      'name': firstSrc.name,
      'commit': firstSrc.commit,
      'tag': firstSrc.tag
  },
  'certifyLegal_id': certifyLegal._id,
  'declaredLicense': certifyLegal.declaredLicense,
  'declaredLicenses': certifyLegal.declaredLicenses,
  'discoveredLicense': certifyLegal.discoveredLicense,
  'discoveredLicenses': certifyLegal.discoveredLicenses,
  'attribution': certifyLegal.attribution,
  'justification': certifyLegal.justification,
  'timeScanned': certifyLegal.timeScanned,
  'collector': certifyLegal.collector,
  'origin': certifyLegal.origin
}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyLegalQueryValues(nil, subject.Source, dec, dis, certifyLegal), "IngestCertifyLegal - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source certifyLegal: %w", err)
		}
		defer cursor.Close()

		certifyLegalList, err := c.getCertifyLegalFromCursor(ctx, cursor, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyLegals from arango cursor: %w", err)
		}

		if len(certifyLegalList) == 1 {
			return certifyLegalList[0], nil
		}
		return nil, fmt.Errorf("number of certifyLegal ingested is greater than one")
	}
	return nil, fmt.Errorf("package or source is not specified for IngestCertifyLegal")
}

func (c *arangoClient) IngestCertifyLegals(
	ctx context.Context,
	subjects model.PackageOrSourceInputs,
	declaredLicensesList [][]*model.LicenseInputSpec,
	discoveredLicensesList [][]*model.LicenseInputSpec,
	certifyLegals []*model.CertifyLegalInputSpec) ([]*model.CertifyLegal, error) {

	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			dec, err := c.getLicenses(ctx, declaredLicensesList[i])
			if err != nil {
				return nil, fmt.Errorf("failed to get declared licenses list with error: %w", err)
			}

			dis, err := c.getLicenses(ctx, discoveredLicensesList[i])
			if err != nil {
				return nil, fmt.Errorf("failed to get discovered licenses list with error: %w", err)
			}

			listOfValues = append(listOfValues, getCertifyLegalQueryValues(subjects.Packages[i], nil, dec, dis, certifyLegals[i]))
		}

		var documents []string
		for _, val := range listOfValues {
			bs, _ := json.Marshal(val)
			documents = append(documents, string(bs))
		}

		queryValues := map[string]any{}
		queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

		var sb strings.Builder

		sb.WriteString("for doc in [")
		for i, val := range listOfValues {
			bs, _ := json.Marshal(val)
			if i == len(listOfValues)-1 {
				sb.WriteString(string(bs))
			} else {
				sb.WriteString(string(bs) + ",")
			}
		}
		sb.WriteString("]")

		query := `
LET firstPkg = FIRST(
  FOR pVersion in pkgVersions
    FILTER pVersion.guacKey == doc.pkgVersionGuacKey
  FOR pName in pkgNames
    FILTER pName._id == pVersion._parent
  FOR pNs in pkgNamespaces
    FILTER pNs._id == pName._parent
  FOR pType in pkgTypes
    FILTER pType._id == pNs._parent

  RETURN {
    'typeID': pType._id,
    'type': pType.type,
    'namespace_id': pNs._id,
    'namespace': pNs.namespace,
    'name_id': pName._id,
    'name': pName.name,
    'version_id': pVersion._id,
    'version': pVersion.version,
    'subpath': pVersion.subpath,
    'qualifier_list': pVersion.qualifier_list,
    'versionDoc': pVersion
  }
)

LET certifyLegal = FIRST(
  UPSERT {
    packageID:firstPkg.version_id,
    declaredLicense:doc.declaredLicense,
    declaredLicenses:doc.declaredLicenses,
    discoveredLicense:doc.discoveredLicense,
    discoveredLicenses:doc.discoveredLicenses,
    attribution:doc.attribution,
    justification:doc.justification,
    timeScanned:doc.timeScanned,
    collector:doc.collector,
    origin:doc.origin
  }
  INSERT {
    packageID:firstPkg.version_id,
    declaredLicense:doc.declaredLicense,
    declaredLicenses:doc.declaredLicenses,
    discoveredLicense:doc.discoveredLicense,
    discoveredLicenses:doc.discoveredLicenses,
    attribution:doc.attribution,
    justification:doc.justification,
    timeScanned:doc.timeScanned,
    collector:doc.collector,
    origin:doc.origin
  }
  UPDATE {} IN certifyLegals
  RETURN NEW
)

LET edgeCollection = (
  INSERT {  _key: CONCAT("certifyLegalPkgEdges", firstPkg.versionDoc._key, certifyLegal._key), _from: firstPkg.version_id, _to: certifyLegal._id } INTO certifyLegalPkgEdges OPTIONS { overwriteMode: "ignore" }
)

LET declaredLicensesCollection = (FOR decData IN doc.declaredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDeclaredLicensesEdges", certifyLegal._key, decData), _from: certifyLegal._id, _to: CONCAT("licenses/", decData) } INTO certifyLegalDeclaredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

LET discoveredLicensesCollection = (FOR disData IN doc.discoveredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDiscoveredLicensesEdges", certifyLegal._key, disData), _from: certifyLegal._id, _to: CONCAT("licenses/", disData) } INTO certifyLegalDiscoveredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

RETURN {
  'pkgVersion': {
      'type_id': firstPkg.typeID,
      'type': firstPkg.type,
      'namespace_id': firstPkg.namespace_id,
      'namespace': firstPkg.namespace,
      'name_id': firstPkg.name_id,
      'name': firstPkg.name,
      'version_id': firstPkg.version_id,
      'version': firstPkg.version,
      'subpath': firstPkg.subpath,
      'qualifier_list': firstPkg.qualifier_list
  },
  'certifyLegal_id': certifyLegal._id,
  'declaredLicense': certifyLegal.declaredLicense,
  'declaredLicenses': certifyLegal.declaredLicenses,
  'discoveredLicense': certifyLegal.discoveredLicense,
  'discoveredLicenses': certifyLegal.discoveredLicenses,
  'attribution': certifyLegal.attribution,
  'justification': certifyLegal.justification,
  'timeScanned': certifyLegal.timeScanned,
  'collector': certifyLegal.collector,
  'origin': certifyLegal.origin
}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyLegals - Pkg")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package certifyLegals: %w", err)
		}
		defer cursor.Close()

		certifyLegalList, err := c.getCertifyLegalFromCursor(ctx, cursor, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyLegals from arango cursor: %w", err)
		}

		return certifyLegalList, nil
	}
	if len(subjects.Sources) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Sources {
			dec, err := c.getLicenses(ctx, declaredLicensesList[i])
			if err != nil {
				return nil, fmt.Errorf("failed to get declared licenses list with error: %w", err)
			}

			dis, err := c.getLicenses(ctx, discoveredLicensesList[i])
			if err != nil {
				return nil, fmt.Errorf("failed to get discovered licenses list with error: %w", err)
			}

			listOfValues = append(listOfValues, getCertifyLegalQueryValues(nil, subjects.Sources[i], dec, dis, certifyLegals[i]))
		}

		var documents []string
		for _, val := range listOfValues {
			bs, _ := json.Marshal(val)
			documents = append(documents, string(bs))
		}

		queryValues := map[string]any{}
		queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

		var sb strings.Builder

		sb.WriteString("for doc in [")
		for i, val := range listOfValues {
			bs, _ := json.Marshal(val)
			if i == len(listOfValues)-1 {
				sb.WriteString(string(bs))
			} else {
				sb.WriteString(string(bs) + ",")
			}
		}
		sb.WriteString("]")

		query := `
LET firstSrc = FIRST(
  FOR sName in srcNames
    FILTER sName.guacKey == doc.srcNameGuacKey
  FOR sNs in srcNamespaces
    FILTER sNs._id == sName._parent
  FOR sType in srcTypes
    FILTER sType._id == sNs._parent

  RETURN {
    'typeID': sType._id,
    'type': sType.type,
    'namespace_id': sNs._id,
    'namespace': sNs.namespace,
    'name_id': sName._id,
    'name': sName.name,
    'commit': sName.commit,
    'tag': sName.tag,
    'nameDoc': sName
  }
)

LET certifyLegal = FIRST(
  UPSERT {
    sourceID:firstSrc.name_id,
    declaredLicense:doc.declaredLicense,
    declaredLicenses:doc.declaredLicenses,
    discoveredLicense:doc.discoveredLicense,
    discoveredLicenses:doc.discoveredLicenses,
    attribution:doc.attribution,
    justification:doc.justification,
    timeScanned:doc.timeScanned,
    collector:doc.collector,
    origin:doc.origin
  }
  INSERT {
    sourceID:firstSrc.name_id,
    declaredLicense:doc.declaredLicense,
    declaredLicenses:doc.declaredLicenses,
    discoveredLicense:doc.discoveredLicense,
    discoveredLicenses:doc.discoveredLicenses,
    attribution:doc.attribution,
    justification:doc.justification,
    timeScanned:doc.timeScanned,
    collector:doc.collector,
    origin:doc.origin
  }
  UPDATE {} IN certifyLegals
  RETURN NEW
)

LET edgeCollection = (
  INSERT {  _key: CONCAT("certifyLegalSrcEdges", firstSrc.nameDoc._key, certifyLegal._key), _from: firstSrc.name_id, _to: certifyLegal._id } INTO certifyLegalSrcEdges OPTIONS { overwriteMode: "ignore" }
)

LET declaredLicensesCollection = (FOR decData IN doc.declaredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDeclaredLicensesEdges", certifyLegal._key, decData), _from: certifyLegal._id, _to: CONCAT("licenses/", decData) } INTO certifyLegalDeclaredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

LET discoveredLicensesCollection = (FOR disData IN doc.discoveredLicensesKeyList
  INSERT { _key: CONCAT("certifyLegalDiscoveredLicensesEdges", certifyLegal._key, disData), _from: certifyLegal._id, _to: CONCAT("licenses/", disData) } INTO certifyLegalDiscoveredLicensesEdges OPTIONS { overwriteMode: "ignore" }
)

RETURN {
  'srcName': {
      'type_id': firstSrc.typeID,
      'type': firstSrc.type,
      'namespace_id': firstSrc.namespace_id,
      'namespace': firstSrc.namespace,
      'name_id': firstSrc.name_id,
      'name': firstSrc.name,
      'commit': firstSrc.commit,
      'tag': firstSrc.tag
  },
  'certifyLegal_id': certifyLegal._id,
  'declaredLicense': certifyLegal.declaredLicense,
  'declaredLicenses': certifyLegal.declaredLicenses,
  'discoveredLicense': certifyLegal.discoveredLicense,
  'discoveredLicenses': certifyLegal.discoveredLicenses,
  'attribution': certifyLegal.attribution,
  'justification': certifyLegal.justification,
  'timeScanned': certifyLegal.timeScanned,
  'collector': certifyLegal.collector,
  'origin': certifyLegal.origin
}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyLegals - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source certifyLegal: %w", err)
		}
		defer cursor.Close()
		certifyLegalList, err := c.getCertifyLegalFromCursor(ctx, cursor, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyLegals from arango cursor: %w", err)
		}

		return certifyLegalList, nil

	}
	return nil, fmt.Errorf("packages or sources not specified for IngestCertifyLegals")
}

func (c *arangoClient) getCertifyLegalFromCursor(ctx context.Context,
	cursor driver.Cursor, decFilter, disFilter []*model.LicenseSpec) (
	[]*model.CertifyLegal, error) {
	type collectedData struct {
		Pkg                *dbPkgVersion `json:"pkgVersion"`
		SrcName            *dbSrcName    `json:"srcName"`
		CertifyLegalID     string        `json:"certifyLegal_id"`
		DeclaredLicense    string        `json:"declaredLicense"`
		DeclaredLicenses   []string      `json:"declaredLicenses"`
		DiscoveredLicense  string        `json:"discoveredLicense"`
		DiscoveredLicenses []string      `json:"discoveredLicenses"`
		Attribution        string        `json:"attribution"`
		Justification      string        `json:"justification"`
		TimeScanned        time.Time     `json:"timeScanned"`
		Collector          string        `json:"collector"`
		Origin             string        `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to certifyLegal from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var certifyLegalList []*model.CertifyLegal
	for _, createdValue := range createdValues {
		var pkg *model.Package = nil
		var src *model.Source = nil
		if createdValue.Pkg != nil {
			pkg = generateModelPackage(
				createdValue.Pkg.TypeID,
				createdValue.Pkg.PkgType,
				createdValue.Pkg.NamespaceID,
				createdValue.Pkg.Namespace,
				createdValue.Pkg.NameID,
				createdValue.Pkg.Name,
				createdValue.Pkg.VersionID,
				createdValue.Pkg.Version,
				createdValue.Pkg.Subpath,
				createdValue.Pkg.QualifierList)
		} else if createdValue.SrcName != nil {
			src = generateModelSource(
				createdValue.SrcName.TypeID,
				createdValue.SrcName.SrcType,
				createdValue.SrcName.NamespaceID,
				createdValue.SrcName.Namespace,
				createdValue.SrcName.NameID,
				createdValue.SrcName.Name,
				createdValue.SrcName.Commit,
				createdValue.SrcName.Tag)
		}

		certifyLegal := &model.CertifyLegal{
			ID:                createdValue.CertifyLegalID,
			DeclaredLicense:   createdValue.DeclaredLicense,
			DiscoveredLicense: createdValue.DiscoveredLicense,
			Attribution:       createdValue.Attribution,
			Justification:     createdValue.Justification,
			TimeScanned:       createdValue.TimeScanned,
			Origin:            createdValue.Origin,
			Collector:         createdValue.Collector,
		}

		dec, err := c.getLicensesByID(ctx, createdValue.DeclaredLicenses)
		if err != nil {
			return nil, fmt.Errorf("failed to convert Declared License IDs into nodes: %w", err)
		}
		certifyLegal.DeclaredLicenses = dec

		dis, err := c.getLicensesByID(ctx, createdValue.DiscoveredLicenses)
		if err != nil {
			return nil, fmt.Errorf("failed to convert Discovered License IDs into nodes: %w", err)
		}
		certifyLegal.DiscoveredLicenses = dis

		// NOTE: Matching the filter list to the license list on queries is done
		// here, not in the Arango query.
		if !licenseMatch(decFilter, dec) || !licenseMatch(disFilter, dis) {
			continue
		}

		if pkg != nil {
			certifyLegal.Subject = pkg
		} else if src != nil {
			certifyLegal.Subject = src
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for certifyLegal")
		}
		certifyLegalList = append(certifyLegalList, certifyLegal)
	}
	return certifyLegalList, nil
}
