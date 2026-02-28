# Stage 1: Build Backend (Go)
FROM golang:1.24-alpine AS backend-builder
WORKDIR /app

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
RUN go build -o server main.go models.go

# Stage 2: Final Image (Alpine Linux)
FROM alpine:latest
WORKDIR /root/

# Install CA certificates for HTTPS connections (needed for TiDB Cloud)
RUN apk --no-cache add ca-certificates

# Copy the binary from the backend builder
COPY --from=backend-builder /app/server .

# Copy the frontend build artifacts from LOCAL machine
COPY ticket-frontend/dist/ticket-frontend/browser ./ticket-frontend/dist/ticket-frontend/browser

# Create uploads directory
RUN mkdir -p uploads

# Expose port 8080
EXPOSE 8080

# Run the server
CMD ["./server"]