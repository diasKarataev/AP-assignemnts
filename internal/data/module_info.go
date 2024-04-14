package data

import (
	"time"
)

type ModuleInfo struct {
	ID             uint      `json:"id" gorm:"primaryKey"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ModuleName     string    `json:"module_name"`
	ModuleDuration int       `json:"module_duration"`
	ExamType       string    `json:"exam_type"`
	Version        string    `json:"version"`
}
