package main

import (
	pb "MarketShop/cmd/payment"
	"MarketShop/pkg/db"
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"net"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	UserID   int64  `json:"user_id"`
	jwt.StandardClaims
}

type server struct {
	pb.UnimplementedPaymentServiceServer
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

	ctx = context.WithValue(ctx, "userID", claims.UserID)
	return handler(ctx, req)
}

func (s *server) ListPaymentDetails(ctx context.Context, req *pb.EmptyRequest) (*pb.ListPaymentDetailsResponse, error) {
	userID, ok := ctx.Value("userID").(int64)
	if !ok {
		return nil, status.Errorf(codes.Internal, "userID not found in context")
	}

	dbPool := db.GetDB()
	rows, err := dbPool.Query(context.Background(), "SELECT id, order_id, payment_id, status_id FROM payment_details WHERE payment_id IN (SELECT id FROM user_payment WHERE user_id = $1)", userID)
	if err != nil {
		log.Printf("ListPaymentDetails failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var paymentDetails []*pb.PaymentDetail
	for rows.Next() {
		var paymentDetail pb.PaymentDetail
		err := rows.Scan(&paymentDetail.Id, &paymentDetail.OrderId, &paymentDetail.PaymentId, &paymentDetail.StatusId)
		if err != nil {
			log.Printf("ListPaymentDetails row scan failed: %v", err)
			return nil, err
		}
		paymentDetails = append(paymentDetails, &paymentDetail)
	}

	return &pb.ListPaymentDetailsResponse{PaymentDetails: paymentDetails}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50054")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			Authenticate,
		)),
	)
	pb.RegisterPaymentServiceServer(s, &server{})

	db.InitDB() // Initialize the database connection

	log.Printf("Payment server is running on port 50054...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
