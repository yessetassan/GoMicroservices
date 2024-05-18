package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	pb "MarketShop/cmd/order"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const orderGrpcAddress = "localhost:50053"

var orderGrpcClient pb.OrderServiceClient

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	// Set up a connection to the gRPC server
	orderConn, err := grpc.Dial(orderGrpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer orderConn.Close()

	orderGrpcClient = pb.NewOrderServiceClient(orderConn)

	// Set up the HTTP server
	router := mux.NewRouter()

	router.HandleFunc("/orders", withAuthOrder(createOrderHandler)).Methods("POST")
	router.HandleFunc("/orders/{id}", withAuthOrder(getOrderHandler)).Methods("GET")
	router.HandleFunc("/orders/{id}", withAuthOrder(updateOrderHandler)).Methods("PUT")
	router.HandleFunc("/orders/{id}", withAuthOrder(cancelOrderHandler)).Methods("DELETE")
	router.HandleFunc("/orders", withAuthOrder(listOrdersHandler)).Methods("GET")

	log.Println("Order REST server listening on port 8082...")
	log.Fatal(http.ListenAndServe(":8082", router))
}

func createOrderHandler(w http.ResponseWriter, r *http.Request) {
	var order pb.Order
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	resp, err := orderGrpcClient.CreateOrder(ctx, &pb.CreateOrderRequest{Order: &order})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Order)
}

func getOrderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	resp, err := orderGrpcClient.GetOrder(ctx, &pb.GetOrderRequest{Id: orderID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Order)
}

func updateOrderHandler(w http.ResponseWriter, r *http.Request) {
	var order pb.Order
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	vars := mux.Vars(r)
	orderID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	order.Id = orderID

	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	resp, err := orderGrpcClient.UpdateOrder(ctx, &pb.UpdateOrderRequest{Order: &order})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Order)
}

func cancelOrderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	_, err = orderGrpcClient.CancelOrder(ctx, &pb.CancelOrderRequest{Id: orderID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listOrdersHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	resp, err := orderGrpcClient.ListOrders(ctx, &pb.EmptyRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Orders)
}

func withAuthOrder(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", claims.Username)
		handler(w, r.WithContext(ctx))
	}
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(authHeader, "Bearer ")
}
