package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	pb "MarketShop/cmd/product"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const productGrpcAddress = "localhost:50051"

var productGrpcClient pb.ProductServiceClient

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	// Set up a connection to the gRPC server
	productConn, err := grpc.Dial(productGrpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer productConn.Close()

	productGrpcClient = pb.NewProductServiceClient(productConn)

	// Set up the HTTP server
	router := mux.NewRouter()

	//
	router.HandleFunc("/products", withAuth(createProductHandler)).Methods("POST")
	router.HandleFunc("/products/{id}", withAuth(getProductHandler)).Methods("GET")
	router.HandleFunc("/products/{id}", withAuth(updateProductHandler)).Methods("PUT")
	router.HandleFunc("/products/{id}", withAuth(deleteProductHandler)).Methods("DELETE")
	router.HandleFunc("/products", withAuth(listProductsHandler)).Methods("GET")

	log.Println("Product REST server listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func createProductHandler(w http.ResponseWriter, r *http.Request) {
	var product pb.Product
	err := json.NewDecoder(r.Body).Decode(&product)
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

	resp, err := productGrpcClient.CreateProduct(ctx, &pb.CreateProductRequest{Product: &product})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Product)
}

func getProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID, err := strconv.ParseInt(vars["id"], 10, 64)
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

	resp, err := productGrpcClient.GetProduct(ctx, &pb.GetProductRequest{Id: productID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Product)
}

func updateProductHandler(w http.ResponseWriter, r *http.Request) {
	var product pb.Product
	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vars := mux.Vars(r)
	productID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	product.Id = productID

	// Extract token from context
	tokenString, err := extractTokenFromContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Add token to gRPC context metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := productGrpcClient.UpdateProduct(ctx, &pb.UpdateProductRequest{Product: &product})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Product)
}

func deleteProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID, err := strconv.ParseInt(vars["id"], 10, 64)
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

	_, err = productGrpcClient.DeleteProduct(ctx, &pb.DeleteProductRequest{Id: productID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listProductsHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token from context
	tokenString, err := extractTokenFromContext(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Add token to gRPC context metadata
	md := metadata.New(map[string]string{"authorization": tokenString})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := productGrpcClient.ListProducts(ctx, &pb.ListProductsRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Products)
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
