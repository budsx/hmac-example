package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestGenerateHMAC(t *testing.T) {
	payload := `{"transaction_datetime":"2024-08-15T14:00:00Z","customer_name":"John Doe","request_id":"123456789"}`
	secret := "rahasia"

	expected := generateHMAC(payload, secret)
	h := hmac.New(sha512.New, []byte(secret))
	h.Write([]byte(payload))
	expectedRaw := hex.EncodeToString(h.Sum(nil))
	expectedBase64 := base64.StdEncoding.EncodeToString([]byte(expectedRaw))

	if expected != expectedBase64 {
		t.Errorf(" TestGenerateHMAC : Expected %s but got %s", expectedBase64, expected)
		return
	}
}

func TestHandlerWithValidSignature(t *testing.T) {
	os.Setenv("SECRET_SIGNATURE", "rahasia")
	defer os.Unsetenv("SECRET_SIGNATURE")

	payload := `{"transaction_datetime":"2024-08-15T14:00:00Z","customer_name":"John Doe","request_id":"123456789"}`
	signature := generateHMAC(payload, os.Getenv("SECRET_SIGNATURE"))

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-signature", signature)

	rr := httptest.NewRecorder()
	handler := signatureChecker(http.HandlerFunc(handler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		return
	}

	expected := "Valid!"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
		return
	}
}

func TestHandlerWithInvalidSignature(t *testing.T) {
	os.Setenv("SECRET_SIGNATURE", "rahasia")
	defer os.Unsetenv("SECRET_SIGNATURE")

	payload := `{"transaction_datetime":"2024-08-15T14:00:00Z","customer_name":"John Doe","request_id":"123456789"}`
	invalidSignature := "invalid_signature"

	req := httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-signature", invalidSignature)

	rr := httptest.NewRecorder()
	handler := signatureChecker(http.HandlerFunc(handler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
		return
	}

	expected := "FlZjUzNDY3OGRhZmVhYWY3YTdkZGMwNDYyYTViOTk3ZTY2NmFlZTgxOWU3M2E5MTZmZjJiNTBmZDdmMWNlMGQxMGU1NDJhODE0YTkwNWQzMDAzOTEyYWExM2Y4NTI0ZWMzODFhOGQ0MGUzYWUzYzg5N2Y5M2NmMTVlZmI0NWQ="
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
		return
	}
}

func TestHandlerWithoutSignature(t *testing.T) {
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := signatureChecker(http.HandlerFunc(handler))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
		return
	}

	expected := "Invalid Signature\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
		return
	}
}
