package cmd

import (
	"github.com/guacsec/guac/pkg/version"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_versionHandler(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(versionHandler))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	assert.NoError(t, err)

	actualData, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	err = res.Body.Close()
	assert.NoError(t, err)

	actualStr := string(actualData)
	assert.Equal(t, version.Version, actualStr)
}
