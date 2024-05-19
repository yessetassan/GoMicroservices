package main

import (
	pb "MarketShop/cmd/payment"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const paymentGrpcAddress = "localhost:50054"

var paymentGrpcClient pb.PaymentServiceClient

func main() {
	conn, err := grpc.Dial(paymentGrpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	paymentGrpcClient = pb.NewPaymentServiceClient(conn)
	router := mux.NewRouter()
	router.HandleFunc("/api/payments", handleListPaymentDetails).Methods("GET")

	log.Println("Payment REST server listening on port 8083...")
	log.Fatal(http.ListenAndServe(":8083", router))
}

func handleListPaymentDetails(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	md := metadata.New(map[string]string{"authorization": "Bearer " + token})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := paymentGrpcClient.ListPaymentDetails(ctx, &pb.EmptyRequest{})
	if err != nil {
		http.Error(w, "Failed to list payment details: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.PaymentDetails)
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(authHeader, "Bearer ")
}
