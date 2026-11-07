// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"
	"testing"
)

func TestOAuthAuthorizationServerMetadataAdvertisesCIMD(t *testing.T) {
	metadata := MapOIDCConfigDTOToWellKnownOAuthAuthorizationServerDTO(&OIDCConfigDTO{}, "id.example.test", "tenant")
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if document["client_id_metadata_document_supported"] != true {
		t.Fatalf("CIMD support not advertised: %s", encoded)
	}
	methods, ok := document["token_endpoint_auth_methods_supported"].([]any)
	if !ok || len(methods) == 0 || methods[0] != "none" {
		t.Fatalf("public-client authentication method missing: %s", encoded)
	}
	if document["issuer"] != "https://tenant.id.example.test" || document["authorization_endpoint"] == nil || document["token_endpoint"] == nil || document["registration_endpoint"] == nil {
		t.Fatalf("existing authorization metadata missing: %s", encoded)
	}
}

func TestOIDCDiscoveryDoesNotChangeForCIMD(t *testing.T) {
	metadata := MapOIDCConfigDTOToWellKnownOIDCConfigurationDTO(&OIDCConfigDTO{}, "id.example.test", "tenant")
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if _, found := document["client_id_metadata_document_supported"]; found {
		t.Fatalf("OIDC discovery was changed unexpectedly: %s", encoded)
	}
}
