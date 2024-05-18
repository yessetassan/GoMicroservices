package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	pb "MarketShop/cmd/order"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
)

const orderGrpcAddress = "localhost:50053"

var orderGrpcClient pb.OrderServiceClient

func main() {
	// Set up a connection to the gRPC server
	orderConn, err := grpc.Dial(orderGrpcAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer orderConn.Close()

	orderGrpcClient = pb.NewOrderServiceClient(orderConn)

	// Set up the HTTP server
	router := mux.NewRouter()

	router.HandleFunc("/orders", createOrderHandler).Methods("POST")
	router.HandleFunc("/orders/{id}", getOrderHandler).Methods("GET")
	router.HandleFunc("/orders/{id}", updateOrderHandler).Methods("PUT")
	router.HandleFunc("/orders/{id}", cancelOrderHandler).Methods("DELETE")
	router.HandleFunc("/orders", listOrdersHandler).Methods("GET")

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

	resp, err := orderGrpcClient.CreateOrder(context.Background(), &pb.CreateOrderRequest{Order: &order})
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

	resp, err := orderGrpcClient.GetOrder(context.Background(), &pb.GetOrderRequest{Id: orderID})
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

	resp, err := orderGrpcClient.UpdateOrder(context.Background(), &pb.UpdateOrderRequest{Order: &order})
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

	_, err = orderGrpcClient.CancelOrder(context.Background(), &pb.CancelOrderRequest{Id: orderID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func listOrdersHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := orderGrpcClient.ListOrders(context.Background(), &pb.EmptyRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp.Orders)
}
