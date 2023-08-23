package backend

// var c1 = &model.CVEInputSpec{
// 	Year:  2019,
// 	CveID: "CVE-2019-13110",
// }
// var c1out = &model.Cve{
// 	Year:  2019,
// 	CveID: "cve-2019-13110",
// }

// var c2 = &model.CVEInputSpec{
// 	Year:  2014,
// 	CveID: "CVE-2014-8139",
// }
// var c2out = &model.Cve{
// 	Year:  2014,
// 	CveID: "cve-2014-8139",
// }

// var c3 = &model.CVEInputSpec{
// 	Year:  2014,
// 	CveID: "cVe-2014-8140",
// }
// var c3out = &model.Cve{
// 	Year:  2014,
// 	CveID: "cve-2014-8140",
// }

// func lessCve(a, b *model.Cve) bool {
// 	return a.CveID < b.CveID
// }

// func (s *Suite) TestCVE() {
// 	tests := []struct {
// 		Name         string
// 		Ingests      []*model.CVEInputSpec
// 		ExpIngestErr bool
// 		Query        *model.CVESpec
// 		Exp          []*model.Cve
// 		ExpQueryErr  bool
// 	}{
// 		{
// 			Name:    "HappyPath",
// 			Ingests: []*model.CVEInputSpec{c1},
// 			Query:   &model.CVESpec{},
// 			Exp:     []*model.Cve{c1out},
// 		},
// 		{
// 			Name:    "Multiple",
// 			Ingests: []*model.CVEInputSpec{c1, c2},
// 			Query:   &model.CVESpec{},
// 			Exp:     []*model.Cve{c2out, c1out},
// 		},
// 		{
// 			Name:    "Duplicates",
// 			Ingests: []*model.CVEInputSpec{c1, c1, c1},
// 			Query:   &model.CVESpec{},
// 			Exp:     []*model.Cve{c1out},
// 		},
// 		{
// 			Name:    "Query by year",
// 			Ingests: []*model.CVEInputSpec{c1, c2, c3},
// 			Query: &model.CVESpec{
// 				Year: ptrfrom.Int(2014),
// 			},
// 			Exp: []*model.Cve{c2out, c3out},
// 		},
// 		{
// 			Name:    "Query by CveID",
// 			Ingests: []*model.CVEInputSpec{c1, c2, c3},
// 			Query: &model.CVESpec{
// 				CveID: ptrfrom.String("CVE-2014-8140"),
// 			},
// 			Exp: []*model.Cve{c3out},
// 		},
// 		{
// 			Name:    "Query by ID",
// 			Ingests: []*model.CVEInputSpec{c1},
// 			Query: &model.CVESpec{
// 				ID: ptrfrom.String("0"),
// 			},
// 			Exp: []*model.Cve{c1out},
// 		},
// 		{
// 			Name:    "Query none",
// 			Ingests: []*model.CVEInputSpec{c1, c2, c3},
// 			Query: &model.CVESpec{
// 				Year: ptrfrom.Int(2099),
// 			},
// 			Exp: nil,
// 		},
// 		{
// 			Name:    "Query none ID",
// 			Ingests: []*model.CVEInputSpec{c1, c2, c3},
// 			Query: &model.CVESpec{
// 				ID: ptrfrom.String("12345"),
// 			},
// 			Exp: nil,
// 		},
// 		{
// 			Name:    "Query invalid ID",
// 			Ingests: []*model.CVEInputSpec{c1, c2, c3},
// 			Query: &model.CVESpec{
// 				ID: ptrfrom.String("asdf"),
// 			},
// 			ExpQueryErr: true,
// 		},
// 	}

// 	ctx := s.Ctx
// 	for _, test := range tests {
// 		s.Run(test.Name, func() {
// 			b, err := GetBackend(s.Client)
// 			if err != nil {
// 				s.T().Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			ids := make([]string, len(test.Ingests))
// 			for i, v := range test.Ingests {
// 				record, err := b.IngestCve(ctx, v)
// 				if (err != nil) != test.ExpIngestErr {
// 					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
// 				}
// 				if err != nil {
// 					return
// 				}
// 				ids[i] = record.ID
// 			}
// 			if test.Query.ID != nil {
// 				idIndex, err := strconv.Atoi(*test.Query.ID)
// 				if err == nil && idIndex < len(ids) {
// 					test.Query.ID = ptrfrom.String(ids[idIndex])
// 				}
// 			}

// 			got, err := b.Cve(ctx, test.Query)
// 			if (err != nil) != test.ExpQueryErr {
// 				s.T().Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
// 			}
// 			if err != nil {
// 				return
// 			}
// 			slices.SortFunc(got, lessCve)
// 			if diff := cmp.Diff(test.Exp, got, ignoreID); diff != "" {
// 				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }
