# Stage 1: Build Frontend (Angular)
FROM node:20 AS frontend-builder
WORKDIR /app

# Copy dependency definitions
COPY ticket-frontend/package.json ticket-frontend/package-lock.json ./ticket-frontend/
WORKDIR /app/ticket-frontend
RUN npm ci

# Copy all frontend source files
COPY ticket-frontend/ .
RUN npm run build -- --configuration production

# Stage 2: Build Backend (Go)
FROM golang:1.24-alpine AS backend-builder
WORKDIR /app

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
# -o server specifies the output binary name
RUN go build -o server main.go models.go

# Stage 3: Final Image (Alpine Linux)
FROM alpine:latest
WORKDIR /root/

# Install CA certificates for HTTPS connections (needed for TiDB Cloud)
RUN apk --no-cache add ca-certificates

# Copy the binary from the backend builder
COPY --from=backend-builder /app/server .

# Copy the frontend build artifacts
# Make sure the path matches where Angular outputs the build (usually dist/project-name/browser)
COPY --from=frontend-builder /app/ticket-frontend/dist/ticket-frontend/browser ./ticket-frontend/dist/ticket-frontend/browser

# Create uploads directory
RUN mkdir -p uploads

# Expose port 8080 (Render uses 8080 by default)
EXPOSE 8080

# Run the server
CMD ["./server"]
