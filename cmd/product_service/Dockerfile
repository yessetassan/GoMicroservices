# Use the official Golang image to create a build artifact.
FROM golang:1.21.6 as builder

# Start from the official Golang base image
# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Go Module files
COPY go.mod .
COPY go.sum .

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files do not change
RUN go mod download

# Copy the entire project (ensure the context of docker build includes the project root)
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -v -o rest_server ./cmd/product_service/rest_server.go

# Start a new stage from scratch
FROM alpine:latest
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/rest_server .

# Add ca-certificates in case you need HTTPS
RUN apk --no-cache add ca-certificates

# Expose port 8081 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./rest_server"]
