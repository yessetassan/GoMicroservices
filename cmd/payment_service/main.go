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
	"strings"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type server struct {
	pb.UnimplementedPaymentServiceServer
}

func Authenticate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	tokens, ok := md["authorization"]
	if !ok || len(tokens) < 1 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}
	tokenString := strings.TrimPrefix(tokens[0], "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	ctx = context.WithValue(ctx, "username", claims.Username)
	return handler(ctx, req)
}

func (s *server) ListPaymentDetails(ctx context.Context, req *pb.EmptyRequest) (*pb.ListPaymentDetailsResponse, error) {
	username := ctx.Value("username").(string)
	dbPool := db.GetDB()
	var details []*pb.PaymentDetail

	query := `SELECT pd.id, pd.order_id, pd.payment_id, pd.status_id, ps.name AS status_name
              FROM payment_details pd
              JOIN user_payment up ON pd.payment_id = up.id
              JOIN _user u ON up.user_id = u.id
              JOIN payment_status ps ON pd.status_id = ps.id
              WHERE u.login = $1`
	rows, err := dbPool.Query(ctx, query, username)
	if err != nil {
		log.Printf("Failed to retrieve payment details: %v", err)
		return nil, status.Errorf(codes.Internal, "database error: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var detail pb.PaymentDetail
		if err := rows.Scan(&detail.Id, &detail.OrderId, &detail.PaymentId, &detail.StatusId, &detail.StatusName); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read payment details: %v", err)
		}
		details = append(details, &detail)
	}

	return &pb.ListPaymentDetailsResponse{PaymentDetails: details}, nil
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
