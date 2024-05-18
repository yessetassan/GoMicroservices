package main

import (
	"context"
	"log"
	"net"
	"time"

	pb "MarketShop/cmd/user"
	"MarketShop/pkg/db"
	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type server struct {
	pb.UnimplementedUserServiceServer
}

func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.UserResponse, error) {
	user := req.GetUser()
	dbPool := db.GetDB()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password")
	}
	user.Password = string(hashedPassword)

	query := `INSERT INTO _user (first_name, last_name, middle_name, login, email, password_hash, role_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err = dbPool.QueryRow(context.Background(), query, user.FirstName, user.LastName, user.MiddleName, user.Login, user.Email, user.Password, user.RoleId).Scan(&user.Id)
	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{User: user}, nil
}

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	dbPool := db.GetDB()
	user := &pb.User{}

	query := `SELECT id, first_name, last_name, middle_name, login, email, password_hash, role_id FROM _user WHERE id=$1`
	err := dbPool.QueryRow(context.Background(), query, req.GetId()).Scan(&user.Id, &user.FirstName, &user.LastName, &user.MiddleName, &user.Login, &user.Email, &user.Password, &user.RoleId)
	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{User: user}, nil
}

func (s *server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserResponse, error) {
	user := req.GetUser()
	dbPool := db.GetDB()

	query := `UPDATE _user SET first_name=$1, last_name=$2, middle_name=$3, login=$4, email=$5, role_id=$6 WHERE id=$7`
	_, err := dbPool.Exec(context.Background(), query, user.FirstName, user.LastName, user.MiddleName, user.Login, user.Email, user.RoleId, user.Id)
	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{User: user}, nil
}

func (s *server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.EmptyResponse, error) {
	dbPool := db.GetDB()

	query := `DELETE FROM _user WHERE id=$1`
	_, err := dbPool.Exec(context.Background(), query, req.GetId())
	if err != nil {
		return nil, err
	}

	return &pb.EmptyResponse{}, nil
}

func (s *server) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	dbPool := db.GetDB()
	rows, err := dbPool.Query(context.Background(), "SELECT id, first_name, last_name, middle_name, login, email, password_hash, role_id FROM _user")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*pb.User
	for rows.Next() {
		var user pb.User
		err := rows.Scan(&user.Id, &user.FirstName, &user.LastName, &user.MiddleName, &user.Login, &user.Email, &user.Password, &user.RoleId)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}

	return &pb.ListUsersResponse{Users: users}, nil
}

func (s *server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	dbPool := db.GetDB()
	var hashedPassword string
	var userID int64

	err := dbPool.QueryRow(context.Background(), "SELECT id, password_hash FROM _user WHERE login = $1", req.Username).Scan(&userID, &hashedPassword)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "username or password is incorrect")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "username or password is incorrect")
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: req.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate token")
	}

	return &pb.LoginResponse{Token: tokenString}, nil
}

func Authenticate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info.FullMethod == "/user.UserService/CreateUser" || info.FullMethod == "/user.UserService/Login" {
		// Skip authentication for CreateUser and Login methods
		return handler(ctx, req)
	}

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

func main() {
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			Authenticate,
		)),
	)
	pb.RegisterUserServiceServer(s, &server{})

	db.InitDB() // Initialize the database connection

	log.Printf("User server is running on port 50052...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
