package main

import (
	"assignment1/internal/data"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/pressly/goose"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"net/http"
	"time"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "Infinitive"
	dbname   = "d.karataevDB"
)

var (
	db *gorm.DB
)

func main() {
	// DB connection
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=UTC", host, user, password, dbname, port)
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("Ошибка подключения к базе данных: %v", err)
	}

	// Applying migrations
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Ошибка при получении объекта базы данных: %v", err)
	}
	err = goose.Up(sqlDB, "./migrations")
	if err != nil {
		log.Fatalf("Ошибка при применении миграций: %v", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/moduleinfo", createModuleInfo).Methods("POST")
	r.HandleFunc("/moduleinfo/{id}", getModuleInfo).Methods("GET")
	r.HandleFunc("/moduleinfo/{id}", updateModuleInfo).Methods("PUT")
	r.HandleFunc("/moduleinfo/{id}", deleteModuleInfo).Methods("DELETE")

	log.Println("Сервер запущен на :8080")
	http.ListenAndServe(":8080", r)
}

func createModuleInfo(w http.ResponseWriter, r *http.Request) {
	var module data.ModuleInfo
	err := json.NewDecoder(r.Body).Decode(&module)
	if err != nil {
		http.Error(w, "Ошибка при чтении запроса", http.StatusBadRequest)
		return
	}

	module.CreatedAt = time.Now()
	module.UpdatedAt = time.Now()

	result := db.Create(&module)
	if result.Error != nil {
		http.Error(w, "Ошибка при создании записи", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(module)
}

func getModuleInfo(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var module data.ModuleInfo
	result := db.First(&module, id)
	if result.Error != nil {
		http.Error(w, "Запись не найдена", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(module)
}

func updateModuleInfo(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var module data.ModuleInfo
	result := db.First(&module, id)
	if result.Error != nil {
		http.Error(w, "Запись не найдена", http.StatusNotFound)
		return
	}

	var updatedModule data.ModuleInfo
	err := json.NewDecoder(r.Body).Decode(&updatedModule)
	if err != nil {
		http.Error(w, "Ошибка при чтении запроса", http.StatusBadRequest)
		return
	}

	module.ModuleName = updatedModule.ModuleName
	module.ModuleDuration = updatedModule.ModuleDuration
	module.ExamType = updatedModule.ExamType
	module.Version = updatedModule.Version
	module.UpdatedAt = time.Now()

	db.Save(&module)

	json.NewEncoder(w).Encode(module)
}

func deleteModuleInfo(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var module data.ModuleInfo
	result := db.First(&module, id)
	if result.Error != nil {
		http.Error(w, "Запись не найдена", http.StatusNotFound)
		return
	}

	db.Delete(&module)

	w.WriteHeader(http.StatusNoContent)
}
