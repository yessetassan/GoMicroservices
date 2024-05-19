package main

import (
	pb "MarketShop/cmd/order"
	"MarketShop/pkg/db"
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"math/rand"
	"net"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type server struct {
	pb.UnimplementedOrderServiceServer
}

// Authenticate is a middleware for JWT authentication.
func Authenticate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	tokens, ok := md["authorization"]
	if !ok || len(tokens) < 1 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}
	tokenString := tokens[0]

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	ctx = context.WithValue(ctx, "username", claims.Username)
	return handler(ctx, req)
}

func (s *server) CreateOrder(ctx context.Context, req *pb.CreateOrderRequest) (*pb.OrderResponse, error) {
	username := ctx.Value("username").(string)
	userId, err := fetchUserIdByUsername(username)
	if err != nil {
		log.Printf("Failed to fetch user ID: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to fetch user ID: %v", err)
	}

	order := req.GetOrder()
	order.UserId = userId // Set user ID from the JWT token

	// Validate quantity
	if order.Quantity <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "quantity must be greater than zero")
	}

	// Calculate totalPrice by multiplying quantity with product's price
	productPrice, err := fetchProductPriceById(order.ProductId)
	if err != nil {
		log.Printf("Failed to fetch product price: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to fetch product price: %v", err)
	}
	order.TotalPrice = float64(order.Quantity) * productPrice

	dbPool := db.GetDB()
	query := `INSERT INTO _order (user_id, product_id, quantity, total_price) VALUES ($1, $2, $3, $4) RETURNING id`
	err = dbPool.QueryRow(context.Background(), query, order.UserId, order.ProductId, order.Quantity, order.TotalPrice).Scan(&order.Id)
	if err != nil {
		log.Printf("CreateOrder failed: %v", err)
		return nil, err
	}

	// After creating the order, create an entry in payment_details
	paymentId, err := fetchPaymentIdForUser(order.UserId)
	if err != nil {
		log.Printf("Failed to fetch payment ID: %v", err)
	}

	statusId := rand.Int63n(4) // Random status from 0 to 3
	paymentDetailsQuery := `INSERT INTO payment_details (order_id, payment_id, status_id) VALUES ($1, $2, $3)`
	_, err = dbPool.Exec(context.Background(), paymentDetailsQuery, order.Id, paymentId, statusId)
	if err != nil {
		log.Printf("Failed to insert payment details: %v", err)
	}

	log.Printf("Order created with ID: %v, and payment details inserted", order.Id)
	return &pb.OrderResponse{Order: order}, nil
}

func (s *server) GetOrder(ctx context.Context, req *pb.GetOrderRequest) (*pb.OrderResponse, error) {
	username := ctx.Value("username").(string)
	userId, err := fetchUserIdByUsername(username)
	if err != nil {
		log.Printf("Failed to fetch user ID: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to fetch user ID: %v", err)
	}

	dbPool := db.GetDB()
	order := &pb.Order{}

	query := `SELECT id, user_id, product_id, quantity, total_price FROM _order WHERE id=$1 AND user_id=$2`
	err = dbPool.QueryRow(context.Background(), query, req.GetId(), userId).Scan(&order.Id, &order.UserId, &order.ProductId, &order.Quantity, &order.TotalPrice)
	if err != nil {
		log.Printf("GetOrder failed: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to retrieve order: %v", err)
	}

	log.Printf("Order retrieved: %v", order)
	return &pb.OrderResponse{Order: order}, nil
}

func (s *server) UpdateOrder(ctx context.Context, req *pb.UpdateOrderRequest) (*pb.OrderResponse, error) {
	dbPool := db.GetDB()
	order := req.GetOrder()

	query := `UPDATE _order SET product_id=$1, quantity=$2, total_price=$3 WHERE id=$4 AND user_id=$5`
	_, err := dbPool.Exec(context.Background(), query, order.ProductId, order.Quantity, order.TotalPrice, order.Id, order.UserId)
	if err != nil {
		log.Printf("UpdateOrder failed: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to update order: %v", err)
	}

	log.Printf("Order updated: %v", order)
	return &pb.OrderResponse{Order: order}, nil
}

func (s *server) CancelOrder(ctx context.Context, req *pb.CancelOrderRequest) (*pb.EmptyResponse, error) {
	username := ctx.Value("username").(string)
	userId, err := fetchUserIdByUsername(username)
	if err != nil {
		log.Printf("Failed to fetch user ID: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to fetch user ID: %v", err)
	}

	dbPool := db.GetDB()

	query := `DELETE FROM _order WHERE id=$1 AND user_id=$2`
	_, err = dbPool.Exec(context.Background(), query, req.GetId(), userId)
	if err != nil {
		log.Printf("CancelOrder failed: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to cancel order: %v", err)
	}

	log.Printf("Order canceled: %d", req.GetId())
	return &pb.EmptyResponse{}, nil
}

func (s *server) ListOrders(ctx context.Context, req *pb.EmptyRequest) (*pb.ListOrdersResponse, error) {
	username := ctx.Value("username").(string)
	userId, err := fetchUserIdByUsername(username)
	if err != nil {
		log.Printf("Failed to fetch user ID: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to fetch user ID: %v", err)
	}

	dbPool := db.GetDB()
	rows, err := dbPool.Query(context.Background(), "SELECT id, user_id, product_id, quantity, total_price FROM _order WHERE user_id=$1", userId)
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

func fetchPaymentIdForUser(userId int64) (int64, error) {
	dbPool := db.GetDB()
	var paymentId int64

	query := `SELECT id FROM user_payment WHERE user_id = $1`
	err := dbPool.QueryRow(context.Background(), query, userId).Scan(&paymentId)
	if err != nil {
		log.Printf("Failed to fetch payment ID for user %d: %v", userId, err)
		return 0, err
	}

	return paymentId, nil
}

func fetchUserIdByUsername(username string) (int64, error) {
	dbPool := db.GetDB()
	var userId int64

	query := `SELECT id FROM _user WHERE login = $1`
	err := dbPool.QueryRow(context.Background(), query, username).Scan(&userId)
	if err != nil {
		log.Printf("Failed to fetch user ID for username %s: %v", username, err)
		return 0, err
	}

	return userId, nil
}

func fetchProductPriceById(productId int64) (float64, error) {
	dbPool := db.GetDB()
	var price float64

	query := `SELECT price FROM product WHERE id = $1`
	err := dbPool.QueryRow(context.Background(), query, productId).Scan(&price)
	if err != nil {
		log.Printf("Failed to fetch price for product %d: %v", productId, err)
		return 0, err
	}

	return price, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			Authenticate,
		)),
	)
	pb.RegisterOrderServiceServer(s, &server{})

	db.InitDB() // Initialize the database connection

	log.Printf("Order server is running on port 50053...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
