package panel

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PoriyaVali/V2bX/conf"
)

// Only the panel's own "server is not exist" marks a node as deleted; a bare
// 404 can be a wrong ApiHost or a maintenance page.
func TestNodeNotFoundNeedsThePanelsAnswer(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		deleted bool
	}{
		{http.StatusInternalServerError, `{"message":"server is not exist"}`, true},
		{http.StatusBadRequest, `{"message":"Server is not exist"}`, true},
		{http.StatusNotFound, `<html>not found</html>`, false},
		{http.StatusInternalServerError, `{"message":"token is error"}`, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		client, err := New(&conf.ApiConfig{APIHost: srv.URL, Key: "k", NodeID: 7, NodeType: "sudoku", Timeout: 2})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetNodeInfo()
		srv.Close()
		if err == nil || errors.Is(err, ErrNodeNotFound) != tc.deleted {
			t.Errorf("HTTP %d %s: deleted=%v, err %v", tc.status, tc.body, errors.Is(err, ErrNodeNotFound), err)
		}
	}
}
