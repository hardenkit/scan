// Package httpx holds the shared HTTP client used for every data source.
package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// UserAgent identifies the scanner to upstream data sources.
var UserAgent = "hardenkit-scan/dev (+https://hardenkit.com)"

var client = &http.Client{Timeout: 60 * time.Second}

// Do sends req and decodes a JSON response into out.
func Do(req *http.Request, out any) error {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := resp.Header.Get("message")
		if msg == "" {
			msg = string(body)
		}
		return fmt.Errorf("%s %s: HTTP %d: %s", req.Method, req.URL.Host, resp.StatusCode, msg)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// GetJSON fetches url and decodes the JSON body into out.
func GetJSON(ctx context.Context, url string, header http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return Do(req, out)
}
