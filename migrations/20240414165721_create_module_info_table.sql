-- +goose Up
CREATE TABLE IF NOT EXISTS module_infos (
    id SERIAL PRIMARY KEY,
    module_name VARCHAR(255) NOT NULL,
    module_duration INT NOT NULL,
    exam_type VARCHAR(255) NOT NULL,
    version VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down