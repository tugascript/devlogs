# Simple Makefile for a Go project

# Build the application
all: build test

create-migration-file:
	@echo "Creating migration..."
	migrate create -ext sql -dir internal/database/migrations

create-db-schema:
	@echo "Creating initial schema..."
	dbml2sql initial_schema.dbml --postgres -o internal/providers/database/migrations/20241213231542_create_initial_schema.up.sql

sqlc:
	@echo "Generating SQLC bindings..."
	sqlc generate

build:
	@echo "Building..."
	
	
	@go build -o main cmd/api/main.go

# Run the application
run:
	@go run cmd/api/main.go
	
# Create DB container
docker-run:
	@if docker compose up --build 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose up --build; \
	fi

# Shutdown DB container
docker-down:
	@if docker compose down 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose down; \
	fi

# Clean the binary
clean:
	@echo "Cleaning..."
	@rm -f main

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

migrate-test-up:
	migrate -path ./internal/providers/database/migrations -database "postgres://postgres:postgres@localhost:5432/idp_test?sslmode=disable" -verbose up

keygen:
	@echo "Generating keys..."
	DEBUG=true go run ../keygen/main.go

test-verbose:
	@echo "Testing..."
	@go test -v ./tests

test:
	go test ./tests

.PHONY: all build run test clean watch docker-run docker-down itest
