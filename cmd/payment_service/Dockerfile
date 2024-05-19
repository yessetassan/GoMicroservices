# Build stage
FROM golang:1.21.6 AS builder
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -v -o rest_payment_server ./cmd/payment_service/rest_payment_server.go

# Run stage
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/rest_payment_server .
RUN apk --no-cache add ca-certificates

# Command to run
CMD ["./rest_payment_server"]
