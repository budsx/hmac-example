package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type RequestPayload struct {
	TransactionDatetime string `json:"transaction_datetime"`
	CustomerName        string `json:"customer_name"`
	RequestID           string `json:"request_id"`
}

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", signatureChecker(http.HandlerFunc(handler)))

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe("localhost:8080", mux); err != nil {
		log.Fatal(err)
	}
}

func generateHMAC(payload, key string) string {
	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(payload))
	msg := hex.EncodeToString(h.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(msg))
}

func signatureChecker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("x-signature")
		if signature == "" {
			http.Error(w, "Invalid Signature", http.StatusForbidden)
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		log.Println(os.Getenv("SECRET_SIGNATURE"))

		expectedSignature := generateHMAC(string(body), os.Getenv("SECRET_SIGNATURE"))
		log.Println("Expected", expectedSignature)
		log.Println("From Request", signature)
		if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
			http.Error(w, "Invalid Signature", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Valid!")
}