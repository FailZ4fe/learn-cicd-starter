package auth

import (
	"errors"
	"net/http"
  "testing"
)

func TestGetAPIKey(t *testing.T) {
  type testCase struct {
    name      string
    header    http.Header
    expected  string
    err       error
  }
  tests := []testCase{
    {
      name:     "valid header",
      header:   http.Header{"Authorization": []string{"ApiKey apikey123"}},
      expected: "apikey123",
      err:      nil,
    },
    {
      name:     "no Authorization header",
      header:   http.Header{},
      expected: "",
      err:      ErrNoAuthHeaderIncluded,
    },
    {
      name:     "malformed header",
      header:   http.Header{"Authorization": []string{"Bearer token123"}},
      expected: "",
      err:      errors.New("malformed authorization header"),
    },
    {
      name:     "empty ApiKey value",
      header:   http.Header{"Authorization": []string{"ApiKey "}},
      expected: "",
      err:      errors.New("malformed authorization header"),
    },
    {
      name:     "missing ApiKey keyword",
      header:   http.Header{"Authorization": []string{"apikey testkey"}},
      expected: "",
      err:      errors.New("malformed authorization header"),
    },
  }

  for _, tc := range tests {
    t.Run(tc.name, func(t *testing.T){
      gotKey, gotErr := GetAPIKey(tc.header)

      if gotKey != tc.expected{
        t.Errorf("%q: expected key %q, got %q",tc.name, tc.expected, gotKey)
      }

      if (gotErr == nil) != (tc.err == nil) || (gotErr != nil && gotErr.Error() != tc.err.Error()) {
        t.Errorf("%q: expected error %v, got %v",tc.name, tc.err, gotErr)
      }
    })
  }
}
