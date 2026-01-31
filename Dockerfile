# Stage 1: Build
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod ./
# COPY go.sum ./ # Uncomment if go.sum exists
# RUN go mod download 
# (We don't have external deps yet, but good practice)

COPY . .

# Build static binary (no CGO)
RUN CGO_ENABLED=0 GOOS=linux go build -o pii-shield cmd/cleaner/main.go

# Stage 2: Run (Scratch - empty image)
FROM scratch

WORKDIR /

# Copy binary from builder
COPY --from=builder /app/pii-shield /pii-shield

# Sidecar works as a pipe
ENTRYPOINT ["/pii-shield"]
