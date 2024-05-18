package main

import (
	pb "MarketShop/cmd/product"
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
	jwt.StandardClaims
}

type server struct {
	pb.UnimplementedProductServiceServer
}

// JWT Authentication Middleware
func Authenticate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info.FullMethod == "/product.ProductService/CreateProduct" ||
		info.FullMethod == "/product.ProductService/UpdateProduct" ||
		info.FullMethod == "/product.ProductService/DeleteProduct" ||
		info.FullMethod == "/product.ProductService/ListProducts" ||
		info.FullMethod == "/product.ProductService/GetProduct" {
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
	}

	return handler(ctx, req)
}

func (s *server) CreateProduct(ctx context.Context, req *pb.CreateProductRequest) (*pb.ProductResponse, error) {
	product := req.GetProduct()
	dbPool := db.GetDB()

	query := `INSERT INTO product (product_name, description, price, category_id, inventory_id) VALUES ($1, $2, $3, $4, $5) RETURNING id`
	err := dbPool.QueryRow(context.Background(), query, product.ProductName, product.Description, product.Price, product.CategoryId, product.InventoryId).Scan(&product.Id)
	if err != nil {
		log.Printf("CreateProduct failed: %v", err)
		return nil, err
	}

	log.Printf("Product created: %v", product)
	return &pb.ProductResponse{Product: product}, nil
}

func (s *server) GetProduct(ctx context.Context, req *pb.GetProductRequest) (*pb.ProductResponse, error) {
	dbPool := db.GetDB()
	product := &pb.Product{}

	query := `SELECT id, product_name, description, price, category_id, inventory_id FROM product WHERE id=$1`
	err := dbPool.QueryRow(context.Background(), query, req.GetId()).Scan(&product.Id, &product.ProductName, &product.Description, &product.Price, &product.CategoryId, &product.InventoryId)
	if err != nil {
		log.Printf("GetProduct failed: %v", err)
		return nil, err
	}

	log.Printf("Product retrieved: %v", product)
	return &pb.ProductResponse{Product: product}, nil
}

func (s *server) UpdateProduct(ctx context.Context, req *pb.UpdateProductRequest) (*pb.ProductResponse, error) {
	product := req.GetProduct()
	dbPool := db.GetDB()

	query := `UPDATE product SET product_name=$1, description=$2, price=$3, category_id=$4, inventory_id=$5 WHERE id=$6`
	_, err := dbPool.Exec(context.Background(), query, product.ProductName, product.Description, product.Price, product.CategoryId, product.InventoryId, product.Id)
	if err != nil {
		log.Printf("UpdateProduct failed: %v", err)
		return nil, err
	}

	log.Printf("Product updated: %v", product)
	return &pb.ProductResponse{Product: product}, nil
}

func (s *server) DeleteProduct(ctx context.Context, req *pb.DeleteProductRequest) (*pb.EmptyResponse, error) {
	dbPool := db.GetDB()

	query := `DELETE FROM product WHERE id=$1`
	_, err := dbPool.Exec(context.Background(), query, req.GetId())
	if err != nil {
		log.Printf("DeleteProduct failed: %v", err)
		return nil, err
	}

	log.Printf("Product deleted: %d", req.GetId())
	return &pb.EmptyResponse{}, nil
}

func (s *server) ListProducts(ctx context.Context, req *pb.ListProductsRequest) (*pb.ListProductsResponse, error) {
	dbPool := db.GetDB()
	rows, err := dbPool.Query(context.Background(), "SELECT id, product_name, description, price, category_id, inventory_id FROM product")
	if err != nil {
		log.Printf("ListProducts failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var products []*pb.Product
	for rows.Next() {
		var product pb.Product
		err := rows.Scan(&product.Id, &product.ProductName, &product.Description, &product.Price, &product.CategoryId, &product.InventoryId)
		if err != nil {
			log.Printf("ListProducts row scan failed: %v", err)
			return nil, err
		}
		products = append(products, &product)
	}

	return &pb.ListProductsResponse{Products: products}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			Authenticate,
		)),
	)
	pb.RegisterProductServiceServer(s, &server{})

	db.InitDB() // Initialize the database connection

	log.Printf("Product server is running on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
