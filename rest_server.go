package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	pb "MarketShop/cmd/product"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	router.HandleFunc("/products", withAuthProduct(createProductHandler)).Methods("POST")
	router.HandleFunc("/products/{id}", withAuthProduct(getProductHandler)).Methods("GET")
	router.HandleFunc("/products/{id}", withAuthProduct(updateProductHandler)).Methods("PUT")
	router.HandleFunc("/products/{id}", withAuthProduct(deleteProductHandler)).Methods("DELETE")
	router.HandleFunc("/products", withAuthProduct(listProductsHandler)).Methods("GET")

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

	resp, err := productGrpcClient.CreateProduct(context.Background(), &pb.CreateProductRequest{Product: &product})
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

	resp, err := productGrpcClient.GetProduct(context.Background(), &pb.GetProductRequest{Id: productID})
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

	resp, err := productGrpcClient.UpdateProduct(context.Background(), &pb.UpdateProductRequest{Product: &product})
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

	_, err = productGrpcClient.DeleteProduct(context.Background(), &pb.DeleteProductRequest{Id: productID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listProductsHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := productGrpcClient.ListProducts(context.Background(), &pb.ListProductsRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Products)
}

// Middleware for authentication
func withAuthProduct(handler http.HandlerFunc) http.HandlerFunc {
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
