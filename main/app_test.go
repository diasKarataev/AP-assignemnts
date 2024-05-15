package main

import (
	"assignment1/internal/data"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func runTestServer() (*httptest.Server, func()) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=UTC", host, user, password, "testDB", port)
	db = initDB(dsn)
	db.AutoMigrate(&data.ModuleInfo{})
	db.AutoMigrate(&data.UserInfo{})

	r := setupRoutes(db)

	ts := httptest.NewServer(r)

	// Return the server and a cleanup function
	return ts, func() {
		ts.Close()
		db.Migrator().DropTable(&data.ModuleInfo{})
		db.Migrator().DropTable(&data.UserInfo{})
	}
}

func TestLogin(t *testing.T) {
	ts, cleanup := runTestServer()
	defer cleanup()

	registerBody := map[string]string{
		"email":         "testuser@example.com",
		"fname":         "Test User",
		"password_hash": "password",
	}
	registerBodyBytes, err := json.Marshal(registerBody)
	if err != nil {
		t.Fatalf("Could not encode body: %v", err)
	}

	_, err = http.Post(ts.URL+"/register", "application/json", bytes.NewBuffer(registerBodyBytes))
	if err != nil {
		t.Fatalf("Could not register user: %v", err)
	}

	loginBody := map[string]string{
		"email":         "testuser@example.com",
		"password_hash": "password",
	}
	loginBodyBytes, err := json.Marshal(loginBody)
	if err != nil {
		t.Fatalf("Could not encode body: %v", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/login", ts.URL), bytes.NewBuffer(loginBodyBytes))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Could not send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK; got %v", resp.StatusCode)
	}
}

func TestRegister(t *testing.T) {
	ts, cleanup := runTestServer()
	defer ts.Close()

	body := map[string]string{
		"email":         "karataev020902@gmail.com",
		"fname":         "dkcreator",
		"password_hash": "password",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Could not encode body: %v", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/register", ts.URL), bytes.NewBuffer(bodyBytes))
	if err != nil {
		t.Fatalf("Could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Could not send request: %v", err)
	}
	defer resp.Body.Close()

	//if resp.StatusCode != http.StatusCreated {
	//	t.Fatalf("Expected status Created; got %v", resp.StatusCode)
	//}

	var user data.UserInfo
	if err := db.Where("email = ?", "karataev020902@gmail.com").First(&user).Error; err != nil {
		t.Fatalf("Could not find user in database: %v", err)
	}
	cleanup()
}

func TestCreateModuleInfo(t *testing.T) {
	ts, cleanup := runTestServer()
	defer ts.Close()

	testModuleInfo := &data.ModuleInfo{
		ModuleName:     "Test Module",
		ModuleDuration: 10,
		ExamType:       "Test Exam",
		Version:        "1.0",
	}

	bodyBytes, _ := json.Marshal(testModuleInfo)
	resp, _ := http.Post(ts.URL+"/moduleinfo", "application/json", bytes.NewBuffer(bodyBytes))

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status code 201, got %v", resp.StatusCode)
	}
	cleanup()
}

func TestGetModuleInfo(t *testing.T) {
	ts, cleanup := runTestServer()
	defer ts.Close()

	testModuleInfo := &data.ModuleInfo{
		ModuleName:     "Test Module",
		ModuleDuration: 10,
		ExamType:       "Test Exam",
		Version:        "1.0",
	}
	db.Create(testModuleInfo)

	resp, _ := http.Get(ts.URL + "/moduleinfo/1")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %v", resp.StatusCode)
	}
	cleanup()
}

func TestUpdateModuleInfo(t *testing.T) {

	ts, cleanup := runTestServer()
	defer ts.Close()

	testModuleInfo := &data.ModuleInfo{
		ModuleName:     "Test Module",
		ModuleDuration: 10,
		ExamType:       "Test Exam",
		Version:        "1.0",
	}
	db.Create(testModuleInfo)

	updatedModuleInfo := &data.ModuleInfo{
		ModuleName:     "Updated Module",
		ModuleDuration: 20,
		ExamType:       "Updated Exam",
		Version:        "2.0",
	}

	client := &http.Client{}
	bodyBytes, _ := json.Marshal(updatedModuleInfo)
	req, _ := http.NewRequest("PUT", ts.URL+"/moduleinfo/1", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %v", resp.StatusCode)
	}
	cleanup()
}

func TestDeleteModuleInfo(t *testing.T) {
	ts, cleanup := runTestServer()
	defer ts.Close()

	testModuleInfo := &data.ModuleInfo{
		ModuleName:     "Test Module",
		ModuleDuration: 10,
		ExamType:       "Test Exam",
		Version:        "1.0",
	}
	db.Create(testModuleInfo)

	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", ts.URL+"/moduleinfo/1", nil)
	resp, _ := client.Do(req)

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status code 204, got %v", resp.StatusCode)
	}
	cleanup()
}
