package helpers

import (
	"encoding/json"
	"net/http"
)

// PrettyJSONResponse is a custom response type that implements GetPackageInfoResponseObject
type PrettyJSONResponse struct {
	Data interface{}
}

func (r *PrettyJSONResponse) VisitGetPackageInfoResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r.Data)
}
