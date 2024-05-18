package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	pb "MarketShop/cmd/payment"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const paymentGrpcAddress = "localhost:50054"

var paymentGrpcClient pb.PaymentServiceClient

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	UserID   int64  `json:"user_id"`
	jwt.StandardClaims
}

func main() {
	// Set up a connection to the gRPC server
	paymentConn, err := grpc.Dial(paymentGrpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer paymentConn.Close()

	paymentGrpcClient = pb.NewPaymentServiceClient(paymentConn)

	// Set up the HTTP server
	router := mux.NewRouter()

	router.HandleFunc("/api/payments", withAuthPayment(listPaymentDetailsHandler)).Methods("GET")

	log.Println("Payment REST server listening on port 8083...")
	log.Fatal(http.ListenAndServe(":8083", router))
}

func listPaymentDetailsHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := extractToken(r)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", tokenString))

	resp, err := paymentGrpcClient.ListPaymentDetails(ctx, &pb.EmptyRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.PaymentDetails)
}

func withAuthPayment(handler http.HandlerFunc) http.HandlerFunc {
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

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		handler(w, r.WithContext(ctx))
	}
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(authHeader, "Bearer ")
}
