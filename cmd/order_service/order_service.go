package main

import (
	"context"
	"log"
	"net"

	pb "MarketShop/cmd/order"
	"MarketShop/pkg/db"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedOrderServiceServer
}

func (s *server) CreateOrder(ctx context.Context, req *pb.CreateOrderRequest) (*pb.OrderResponse, error) {
	order := req.GetOrder()
	dbPool := db.GetDB()

	query := `INSERT INTO _order (user_id, product_id, quantity, total_price) VALUES ($1, $2, $3, $4) RETURNING id`
	err := dbPool.QueryRow(context.Background(), query, order.UserId, order.ProductId, order.Quantity, order.TotalPrice).Scan(&order.Id)
	if err != nil {
		log.Printf("CreateOrder failed: %v", err)
		return nil, err
	}

	log.Printf("Order created: %v", order)
	return &pb.OrderResponse{Order: order}, nil
}

func (s *server) GetOrder(ctx context.Context, req *pb.GetOrderRequest) (*pb.OrderResponse, error) {
	dbPool := db.GetDB()
	order := &pb.Order{}

	query := `SELECT id, user_id, product_id, quantity, total_price FROM _order WHERE id=$1`
	err := dbPool.QueryRow(context.Background(), query, req.GetId()).Scan(&order.Id, &order.UserId, &order.ProductId, &order.Quantity, &order.TotalPrice)
	if err != nil {
		log.Printf("GetOrder failed: %v", err)
		return nil, err
	}

	log.Printf("Order retrieved: %v", order)
	return &pb.OrderResponse{Order: order}, nil
}

func (s *server) UpdateOrder(ctx context.Context, req *pb.UpdateOrderRequest) (*pb.OrderResponse, error) {
	order := req.GetOrder()
	dbPool := db.GetDB()

	query := `UPDATE _order SET user_id=$1, product_id=$2, quantity=$3, total_price=$4 WHERE id=$5`
	_, err := dbPool.Exec(context.Background(), query, order.UserId, order.ProductId, order.Quantity, order.TotalPrice, order.Id)
	if err != nil {
		log.Printf("UpdateOrder failed: %v", err)
		return nil, err
	}

	log.Printf("Order updated: %v", order)
	return &pb.OrderResponse{Order: order}, nil
}

func (s *server) CancelOrder(ctx context.Context, req *pb.CancelOrderRequest) (*pb.EmptyResponse, error) {
	dbPool := db.GetDB()

	query := `DELETE FROM _order WHERE id=$1`
	_, err := dbPool.Exec(context.Background(), query, req.GetId())
	if err != nil {
		log.Printf("CancelOrder failed: %v", err)
		return nil, err
	}

	log.Printf("Order canceled: %d", req.GetId())
	return &pb.EmptyResponse{}, nil
}

func (s *server) ListOrders(ctx context.Context, req *pb.EmptyRequest) (*pb.ListOrdersResponse, error) {
	dbPool := db.GetDB()
	rows, err := dbPool.Query(context.Background(), "SELECT id, user_id, product_id, quantity, total_price FROM _order")
	if err != nil {
		log.Printf("ListOrders failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var orders []*pb.Order
	for rows.Next() {
		var order pb.Order
		err := rows.Scan(&order.Id, &order.UserId, &order.ProductId, &order.Quantity, &order.TotalPrice)
		if err != nil {
			log.Printf("ListOrders row scan failed: %v", err)
			return nil, err
		}
		orders = append(orders, &order)
	}

	return &pb.ListOrdersResponse{Orders: orders}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterOrderServiceServer(s, &server{})

	db.InitDB() // Initialize the database connection

	log.Printf("Order server is running on port 50053...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
