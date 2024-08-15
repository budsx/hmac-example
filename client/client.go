package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	payload := RequestPayload{
		TransactionDatetime: "2024-08-15T14:00:00Z",
		CustomerName:        "John Doe",
		RequestID:           "123456789",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	secretKey := os.Getenv("SECRET_SIGNATURE")
	signature := generateHMAC(string(payloadBytes), secretKey)

	req, err := http.NewRequest("POST", "http://localhost:8080/", bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-signature", signature)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Response: %s", respBody)
}

func generateHMAC(payload, key string) string {
	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(payload))
	msg := hex.EncodeToString(h.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(msg))
}
