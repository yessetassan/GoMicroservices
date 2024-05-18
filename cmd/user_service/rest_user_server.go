package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	pb "MarketShop/cmd/user"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

const userGrpcAddress = "localhost:50052"

var userGrpcClient pb.UserServiceClient

func main() {
	// Set up a connection to the gRPC server
	conn, err := grpc.Dial(userGrpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	userGrpcClient = pb.NewUserServiceClient(conn)

	// Set up the HTTP server
	router := mux.NewRouter()

	router.HandleFunc("/users", createUserHandler).Methods("POST")
	router.HandleFunc("/users/{id}", withAuth(getUserHandler)).Methods("GET")
	router.HandleFunc("/users/{id}", withAuth(updateUserHandler)).Methods("PUT")
	router.HandleFunc("/users/{id}", withAuth(deleteUserHandler)).Methods("DELETE")
	router.HandleFunc("/users", withAuth(listUsersHandler)).Methods("GET")
	router.HandleFunc("/login", loginUserHandler).Methods("POST")

	log.Println("User REST server listening on port 8081...")
	log.Fatal(http.ListenAndServe(":8081", router))
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user pb.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := userGrpcClient.CreateUser(context.Background(), &pb.CreateUserRequest{User: &user})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.User)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract token from context
	tokenString, err := extractTokenFromContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Add token to gRPC context metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := userGrpcClient.GetUser(ctx, &pb.GetUserRequest{Id: userID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.User)
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user pb.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vars := mux.Vars(r)
	userID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.Id = userID

	// Extract token from context
	tokenString, err := extractTokenFromContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Add token to gRPC context metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := userGrpcClient.UpdateUser(ctx, &pb.UpdateUserRequest{User: &user})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.User)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract token from context
	tokenString, err := extractTokenFromContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Add token to gRPC context metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	_, err = userGrpcClient.DeleteUser(ctx, &pb.DeleteUserRequest{Id: userID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token from context
	tokenString, err := extractTokenFromContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Add token to gRPC context metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := userGrpcClient.ListUsers(ctx, &pb.ListUsersRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Users)
}

func loginUserHandler(w http.ResponseWriter, r *http.Request) {
	var creds pb.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := userGrpcClient.Login(context.Background(), &creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": resp.Token,
	})
}

// Middleware for authentication
func withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate JWT
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		handler(w, r.WithContext(ctx))
	}
}

func extractTokenFromContext(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	return tokenString, nil
}
