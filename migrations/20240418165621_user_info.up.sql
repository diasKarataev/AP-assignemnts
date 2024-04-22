-- +goose Up
CREATE TABLE user_infos
(
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    f_name         VARCHAR(255),
    s_name         VARCHAR(255),
    email         citext UNIQUE               NOT NULL,
    password_hash bytea                       NOT NULL,
    user_role     VARCHAR(50),
    activated     bool                        NOT NULL,
    version       INTEGER                     NOT NULL DEFAULT 1,
    activation_link VARCHAR(255)
);


-- +goose Down
DROP TABLE IF EXISTS user_infos;