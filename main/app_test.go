package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func runTestServer() *httptest.Server {
	db = initDB()

	r := setupRoutes(db)

	return httptest.NewServer(r)
}

func TestLogin(t *testing.T) {
	ts := runTestServer()
	defer ts.Close()

	// Создаем тело запроса
	body := map[string]string{
		"email":         "karataev020902@gmail.com",
		"password_hash": "password",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Could not encode body: %v", err)
	}

	// Создаем новый запрос
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/login", ts.URL), bytes.NewBuffer(bodyBytes))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Отправляем запрос
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Could not send request: %v", err)
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK; got %v", resp.StatusCode)
	}
}
