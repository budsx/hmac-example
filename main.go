package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func generateHMAC(payload, key string) string {
	b := marshaler(payload)
	str := strBuilder(b)

	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(str))
	msg := hex.EncodeToString(h.Sum(nil))
	generatedSignature := base64.StdEncoding.EncodeToString([]byte(msg))

	return generatedSignature
}

type RequestPayload struct {
	TransactionDatetime string `json:"transaction_datetime"`
	CustomerName        string `json:"customer_name"`
	RequestID           string `json:"request_id"`
}

func marshaler(req string) RequestPayload {
	result := RequestPayload{}
	json.Unmarshal([]byte(req), &result)
	return result
}

func strBuilder(req RequestPayload) string {
	formattedString := fmt.Sprintf(
		"%s:%s:%s",
		req.RequestID,
		req.CustomerName,
		req.TransactionDatetime,
	)
	log.Println(formattedString)
	return formattedString
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

		expectedSignature := generateHMAC(string(body), os.Getenv("SECRET_SIGNATURE"))
		fmt.Println("Expected", expectedSignature)
		fmt.Println("From Request", signature)
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

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", signatureChecker(http.HandlerFunc(handler)))

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe("localhost:8080", mux); err != nil {
		log.Fatal(err)
	}
}
