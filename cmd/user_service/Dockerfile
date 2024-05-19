# Start from the official Golang base image
FROM golang:1.18 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files do not change
RUN go mod download

# Copy the source code into the container
COPY cmd/user_service cmd/user_service
COPY pkg pkg

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /rest_user_server cmd/user_service/rest_user_server.go

# Start a new stage from scratch
FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /rest_user_server .

# Add ca-certificates in case you need HTTPS
RUN apk --no-cache add ca-certificates

# Expose port 8081 to the outside world
EXPOSE 8081

# Command to run the executable
CMD ["./rest_user_server"]
