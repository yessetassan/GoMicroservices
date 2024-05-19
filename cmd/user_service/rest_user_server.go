package main

import (
	"context"
	"encoding/json"
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

const userGrpcAddress = "localhost:50052"

var userGrpcClient pb.UserServiceClient

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	// Set up a connection to the gRPC server
	userConn, err := grpc.Dial(userGrpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer userConn.Close()

	userGrpcClient = pb.NewUserServiceClient(userConn)

	// Set up the HTTP server
	router := mux.NewRouter()

	router.HandleFunc("/users", createUserHandler).Methods("POST")
	router.HandleFunc("/users/{id}", withAuth(getUserHandler)).Methods("GET")
	router.HandleFunc("/users/update", withAuth(updateUserHandler)).Methods("PUT")
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
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	resp, err := userGrpcClient.CreateUser(context.Background(), &pb.CreateUserRequest{User: &user})
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.User)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	resp, err := userGrpcClient.GetUser(context.Background(), &pb.GetUserRequest{Id: userID})
	if err != nil {
		http.Error(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.User)
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user pb.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate user attributes
	if user.FirstName == "" {
		http.Error(w, "first_name is required", http.StatusBadRequest)
		return
	}
	if user.LastName == "" {
		http.Error(w, "last_name is required", http.StatusBadRequest)
		return
	}
	if user.MiddleName == "" {
		http.Error(w, "middle_name is required", http.StatusBadRequest)
		return
	}
	if user.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	// Extract token from request header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate JWT and extract username
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Set the username (login) from the token
	user.Login = claims.Username

	// Create gRPC context with metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call the gRPC UpdateUser method
	resp, err := userGrpcClient.UpdateUser(ctx, &pb.UpdateUserRequest{User: &user})
	if err != nil {
		http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.User)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	_, err = userGrpcClient.DeleteUser(ctx, &pb.DeleteUserRequest{Id: userID})
	if err != nil {
		http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	resp, err := userGrpcClient.ListUsers(ctx, &pb.ListUsersRequest{})
	if err != nil {
		http.Error(w, "Failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Users)
}

func loginUserHandler(w http.ResponseWriter, r *http.Request) {
	var creds pb.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	resp, err := userGrpcClient.Login(context.Background(), &creds)
	if err != nil {
		http.Error(w, "Invalid credentials: "+err.Error(), http.StatusUnauthorized)
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
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate JWT
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		handler(w, r.WithContext(ctx))
	}
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(authHeader, "Bearer ")
}
