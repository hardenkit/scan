// Package httpx holds the shared HTTP client used for every data source.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// PostJSON sends body as JSON to rawURL and accepts any 2xx response.
// Webhook URLs are secrets, so errors name only the host: never the path,
// the query or the response body, which can repeat the path.
func PostJSON(ctx context.Context, rawURL string, body any) error {
	return PostJSONWith(ctx, rawURL, nil, body)
}

// PostJSONWith is PostJSON with extra request headers.
func PostJSONWith(ctx context.Context, rawURL string, header http.Header, body any) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("POST: not an http or https URL")
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("POST %s: invalid request", u.Host)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // url.Error prints the whole URL
		}
		return fmt.Errorf("POST %s: %v", u.Host, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("POST %s: HTTP %d", u.Host, resp.StatusCode)
	}
	return nil
}
