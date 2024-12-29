CREATE TABLE IF NOT EXISTS roles
(
    id   SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

INSERT INTO roles (id, name)
VALUES (1, 'SUPER_ADMIN'),
       (2, 'ADMIN'),
       (3, 'PARAMEDIC'),
       (4, 'SUBSCRIBED_USER'),
       (5, 'NON_SUBSCRIBED_USER');