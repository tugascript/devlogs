// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	cimdMaxDocumentBytes = 5 * 1024
	cimdFetchTimeout     = 5 * time.Second
	cimdDefaultCacheTTL  = 5 * time.Minute
	cimdMaxCacheTTL      = time.Hour
)

var errInvalidCIMD = errors.New("invalid client ID metadata document")

type CIMDClientMetadata = dtos.CIMDClientMetadata

// ResolveCIMDClient resolves a CIMD client ID, using the shared cache for
// successful documents only. Callers must first give registered client IDs
// precedence, since CIMD is the fallback registration mechanism.
func (s *Services) ResolveCIMDClient(ctx context.Context, clientID string) (CIMDClientMetadata, *exceptions.ServiceError) {
	if _, err := parseCIMDURL(clientID); err != nil {
		return CIMDClientMetadata{}, exceptions.NewValidationError("Invalid CIMD client_id")
	}
	metadata, err := s.cache.GetCIMDMetadata(ctx, clientID)
	if err != nil {
		return CIMDClientMetadata{}, exceptions.NewInternalServerError()
	}
	if metadata != nil {
		if err := validateCIMDMetadata(clientID, *metadata); err != nil {
			return CIMDClientMetadata{}, exceptions.NewValidationError("Invalid client metadata")
		}
		return *metadata, nil
	}

	result, err := fetchCIMDClientMetadata(ctx, clientID, newCIMDHTTPClient())
	if err != nil {
		return CIMDClientMetadata{}, exceptions.NewValidationError("Unable to resolve client metadata")
	}
	if err := s.cache.SetCIMDMetadata(ctx, clientID, result.Metadata, result.CacheTTL); err != nil {
		return CIMDClientMetadata{}, exceptions.NewInternalServerError()
	}
	return result.Metadata, nil
}

type cimdFetchResult struct {
	Metadata CIMDClientMetadata
	CacheTTL time.Duration
}

// FetchCIMDClientMetadata fetches and validates a Client ID Metadata Document.
// The HTTP client is private to this function so callers cannot accidentally
// enable redirects, proxies, or an unsafe dial path.
func FetchCIMDClientMetadata(ctx context.Context, clientID string) (CIMDClientMetadata, time.Duration, error) {
	result, err := fetchCIMDClientMetadata(ctx, clientID, newCIMDHTTPClient())
	if err != nil {
		return CIMDClientMetadata{}, 0, err
	}
	return result.Metadata, result.CacheTTL, nil
}

func fetchCIMDClientMetadata(ctx context.Context, clientID string, client *http.Client) (cimdFetchResult, error) {
	u, err := parseCIMDURL(clientID)
	if err != nil {
		return cimdFetchResult{}, err
	}

	requestCtx, cancel := context.WithTimeout(ctx, cimdFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return cimdFetchResult{}, fmt.Errorf("%w: create request", errInvalidCIMD)
	}
	req.Header.Set("Accept", "application/json, application/*+json")
	resp, err := client.Do(req)
	if err != nil {
		return cimdFetchResult{}, fmt.Errorf("%w: fetch failed", errInvalidCIMD)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cimdFetchResult{}, fmt.Errorf("%w: metadata endpoint returned %d", errInvalidCIMD, resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))) {
		return cimdFetchResult{}, fmt.Errorf("%w: response is not JSON", errInvalidCIMD)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxDocumentBytes+1))
	if err != nil || len(body) > cimdMaxDocumentBytes {
		return cimdFetchResult{}, fmt.Errorf("%w: document exceeds size limit or could not be read", errInvalidCIMD)
	}
	var metadata CIMDClientMetadata
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&metadata); err != nil {
		return cimdFetchResult{}, fmt.Errorf("%w: malformed JSON", errInvalidCIMD)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return cimdFetchResult{}, fmt.Errorf("%w: expected one JSON object", errInvalidCIMD)
	}
	if err := validateCIMDMetadata(clientID, metadata); err != nil {
		return cimdFetchResult{}, err
	}
	cacheTTL := cimdCacheTTL(resp.Header)
	if metadata.JWKSURI != "" {
		if len(metadata.JWKS) != 0 {
			return cimdFetchResult{}, fmt.Errorf("%w: jwks and jwks_uri are mutually exclusive", errInvalidCIMD)
		}
		jwks, jwksTTL, err := fetchCIMDJWKS(requestCtx, metadata.JWKSURI, client)
		if err != nil {
			return cimdFetchResult{}, err
		}
		metadata.JWKS = jwks
		if jwksTTL < cacheTTL {
			cacheTTL = jwksTTL
		}
	}
	return cimdFetchResult{Metadata: metadata, CacheTTL: cacheTTL}, nil
}

func fetchCIMDJWKS(ctx context.Context, jwksURI string, client *http.Client) (json.RawMessage, time.Duration, error) {
	u, err := parseCIMDURL(jwksURI)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid jwks_uri", errInvalidCIMD)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: create JWKS request", errInvalidCIMD)
	}
	req.Header.Set("Accept", "application/json, application/*+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: fetch JWKS failed", errInvalidCIMD)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: JWKS endpoint returned %d", errInvalidCIMD, resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))) {
		return nil, 0, fmt.Errorf("%w: JWKS response is not JSON", errInvalidCIMD)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxDocumentBytes+1))
	if err != nil || len(body) > cimdMaxDocumentBytes || !json.Valid(body) || !validPublicJWKS(body) {
		return nil, 0, fmt.Errorf("%w: invalid or oversized public JWKS", errInvalidCIMD)
	}
	return json.RawMessage(body), cimdCacheTTL(resp.Header), nil
}

func parseCIMDURL(clientID string) (*url.URL, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Path == "" {
		return nil, fmt.Errorf("%w: client_id must be an HTTPS URL with a host and path", errInvalidCIMD)
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		if strings.TrimSpace(u.Hostname()) == "" || strings.ContainsAny(u.Hostname(), " \t\r\n") {
			return nil, fmt.Errorf("%w: invalid host", errInvalidCIMD)
		}
	}
	return u, nil
}

func validateCIMDMetadata(clientID string, metadata CIMDClientMetadata) error {
	if metadata.ClientID != clientID || metadata.ClientName == "" {
		return fmt.Errorf("%w: client_id must match exactly and client_name is required", errInvalidCIMD)
	}
	if len(metadata.ClientName) > 255 {
		return fmt.Errorf("%w: client_name is too long", errInvalidCIMD)
	}
	for _, redirectURI := range metadata.RedirectURIs {
		parsed, err := url.Parse(redirectURI)
		if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%w: invalid redirect_uri", errInvalidCIMD)
		}
	}
	if hasCIMDGrant(metadata.GrantTypes, "authorization_code") && len(metadata.RedirectURIs) == 0 {
		return fmt.Errorf("%w: redirect_uris required for authorization_code", errInvalidCIMD)
	}
	method := metadata.TokenEndpointAuthMethod
	if method == "" {
		return fmt.Errorf("%w: token_endpoint_auth_method is required", errInvalidCIMD)
	}
	switch method {
	case "none":
	case "private_key_jwt":
		if len(metadata.JWKS) == 0 && metadata.JWKSURI == "" {
			return fmt.Errorf("%w: private_key_jwt requires jwks or jwks_uri", errInvalidCIMD)
		}
		if len(metadata.JWKS) != 0 && metadata.JWKSURI != "" {
			return fmt.Errorf("%w: jwks and jwks_uri are mutually exclusive", errInvalidCIMD)
		}
		if metadata.JWKSURI != "" {
			if _, err := parseCIMDURL(metadata.JWKSURI); err != nil {
				return fmt.Errorf("%w: jwks_uri must be a safe HTTPS URL", errInvalidCIMD)
			}
		}
	default:
		return fmt.Errorf("%w: shared-secret or unsupported token endpoint authentication method", errInvalidCIMD)
	}
	if len(metadata.JWKS) != 0 && !validPublicJWKS(metadata.JWKS) {
		return fmt.Errorf("%w: jwks contains invalid or private key material", errInvalidCIMD)
	}
	if metadata.ClientURI != "" && !validHTTPSURL(metadata.ClientURI) {
		return fmt.Errorf("%w: client_uri must be HTTPS", errInvalidCIMD)
	}
	if metadata.LogoURI != "" && !validHTTPSURL(metadata.LogoURI) {
		return fmt.Errorf("%w: logo_uri must be HTTPS", errInvalidCIMD)
	}
	return nil
}

func validPublicJWKS(raw json.RawMessage) bool {
	var set utils.JWKSet
	if json.Unmarshal(raw, &set) != nil || len(set.Keys) == 0 || set.Validate() != nil {
		return false
	}
	for _, key := range set.Keys {
		if _, err := key.ToPrivateKey(); err == nil {
			return false
		}
	}
	return true
}

func hasCIMDGrant(grants []string, grant string) bool {
	for _, item := range grants {
		if item == grant {
			return true
		}
	}
	return false
}

func validHTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func cimdCacheTTL(header http.Header) time.Duration {
	maxAge := -1
	for _, directive := range strings.Split(header.Get("Cache-Control"), ",") {
		key, value, found := strings.Cut(strings.TrimSpace(directive), "=")
		if strings.EqualFold(key, "no-store") || strings.EqualFold(key, "no-cache") {
			return 0
		}
		if strings.EqualFold(key, "max-age") && found {
			if parsed, err := strconv.Atoi(strings.Trim(value, " \"")); err == nil && parsed >= 0 {
				maxAge = parsed
			}
		}
	}
	if maxAge < 0 {
		return cimdDefaultCacheTTL
	}
	if maxAge > int(cimdMaxCacheTTL/time.Second) {
		return cimdMaxCacheTTL
	}
	ttl := time.Duration(maxAge) * time.Second
	if ttl > cimdMaxCacheTTL {
		return cimdMaxCacheTTL
	}
	return ttl
}

func newCIMDHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 16 * 1024,
		DialContext:            cimdSafeDialContext,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cimdFetchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func cimdSafeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var candidates []netip.Addr
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		candidates = []netip.Addr{ip.Unmap()}
	} else {
		answers, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if lookupErr != nil || len(answers) == 0 {
			return nil, fmt.Errorf("CIMD host lookup failed")
		}
		for _, answer := range answers {
			candidates = append(candidates, answer.Unmap())
		}
	}
	for _, ip := range candidates {
		if !isPublicCIMDAddress(ip) {
			return nil, fmt.Errorf("CIMD host resolves to a non-public address")
		}
	}
	var lastErr error
	dialer := &net.Dialer{Timeout: cimdFetchTimeout, KeepAlive: 30 * time.Second}
	for _, ip := range candidates {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func isPublicCIMDAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	blocked := []netip.Prefix{}
	if ip.Is4() {
		for _, cidr := range []string{
			"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24",
			"192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24", "198.18.0.0/15",
			"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		} {
			blocked = append(blocked, netip.MustParsePrefix(cidr))
		}
	} else {
		if !netip.MustParsePrefix("2000::/3").Contains(ip) {
			return false
		}
		for _, cidr := range []string{"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
			blocked = append(blocked, netip.MustParsePrefix(cidr))
		}
	}
	for _, prefix := range blocked {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
