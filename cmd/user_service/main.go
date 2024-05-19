package main

import (
	"context"
	"log"
	"net"
	"strings"
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

type contextKey int

const (
	userContextKey contextKey = iota
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

	// Validate user attributes
	if user.FirstName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "first_name is required")
	}
	if user.LastName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "last_name is required")
	}
	if user.MiddleName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "middle_name is required")
	}
	if user.Login == "" {
		return nil, status.Errorf(codes.InvalidArgument, "login is required")
	}
	if user.Email == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	if user.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "password is required")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)
	}
	user.Password = string(hashedPassword)

	// Insert the user into the database
	query := `INSERT INTO _user (first_name, last_name, middle_name, login, email, password_hash, role_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err = dbPool.QueryRow(context.Background(), query, user.FirstName, user.LastName, user.MiddleName, user.Login, user.Email, user.Password, 1).Scan(&user.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	// Generate a fake user_payment entry for the new user
	fakePaymentType := "Credit Card"
	fakeProvider := "Visa"
	fakeAccountNo := "1234567890123456"
	fakeExpiry := time.Now().AddDate(2, 0, 0).Format("2006-01-02") // 2 years from now

	paymentQuery := `INSERT INTO user_payment (user_id, payment_type, provider, account_no, expiry, deleted) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err = dbPool.Exec(context.Background(), paymentQuery, user.Id, fakePaymentType, fakeProvider, fakeAccountNo, fakeExpiry, false)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user payment: %v", err)
	}

	return &pb.UserResponse{User: user}, nil
}

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	dbPool := db.GetDB()
	user := &pb.User{}

	query := `SELECT id, first_name, last_name, middle_name, login, email, password_hash, role_id FROM _user WHERE id=$1`
	err := dbPool.QueryRow(context.Background(), query, req.GetId()).Scan(&user.Id, &user.FirstName, &user.LastName, &user.MiddleName, &user.Login, &user.Email, &user.Password, &user.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	return &pb.UserResponse{User: user}, nil
}

func (s *server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UserResponse, error) {
	user := req.GetUser()
	dbPool := db.GetDB()

	// Validate user attributes
	if user.FirstName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "first_name is required")
	}
	if user.LastName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "last_name is required")
	}
	if user.MiddleName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "middle_name is required")
	}
	if user.Email == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}

	// Safely get login from JWT token stored in context
	rawUsername := ctx.Value(userContextKey)
	username, ok := rawUsername.(string)
	if !ok || username == "" {
		return nil, status.Errorf(codes.Unauthenticated, "invalid session or user not authenticated")
	}

	// Update user details using the username from the token
	query := `UPDATE _user SET first_name=$1, last_name=$2, middle_name=$3, email=$4 WHERE login=$5`
	if _, err := dbPool.Exec(context.Background(), query, user.FirstName, user.LastName, user.MiddleName, user.Email, username); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	// Fetch updated user details to return
	if err := dbPool.QueryRow(context.Background(), `SELECT id, first_name, last_name, middle_name, login, email, role_id FROM _user WHERE login=$1`, username).Scan(&user.Id, &user.FirstName, &user.LastName, &user.MiddleName, &user.Login, &user.Email, &user.RoleId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve updated user: %v", err)
	}

	return &pb.UserResponse{User: user}, nil
}

func (s *server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.EmptyResponse, error) {
	dbPool := db.GetDB()

	// First, delete dependent records
	_, err := dbPool.Exec(context.Background(), "DELETE FROM user_payment WHERE user_id=$1", req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user payments: %v", err)
	}

	// Now, delete the user
	_, err = dbPool.Exec(context.Background(), "DELETE FROM _user WHERE id=$1", req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user: %v", err)
	}

	return &pb.EmptyResponse{}, nil
}

func (s *server) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	dbPool := db.GetDB()
	rows, err := dbPool.Query(context.Background(), "SELECT id, first_name, last_name, middle_name, login, email, password_hash, role_id FROM _user")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}
	defer rows.Close()

	var users []*pb.User
	for rows.Next() {
		var user pb.User
		err := rows.Scan(&user.Id, &user.FirstName, &user.LastName, &user.MiddleName, &user.Login, &user.Email, &user.Password, &user.RoleId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to scan user: %v", err)
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
		return nil, status.Errorf(codes.Unauthenticated, "username or password is incorrect: %v", err)
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
		return nil, status.Errorf(codes.Internal, "cannot generate token: %v", err)
	}

	return &pb.LoginResponse{Token: tokenString}, nil
}

func Authenticate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Skip authentication for certain methods
	if info.FullMethod == "/user.UserService/CreateUser" || info.FullMethod == "/user.UserService/Login" {
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
	tokenString := strings.TrimPrefix(tokens[0], "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	// Check if username is present and set it in the context
	if claims.Username != "" {
		ctx = context.WithValue(ctx, userContextKey, claims.Username)
	} else {
		return nil, status.Errorf(codes.Unauthenticated, "username not present in token")
	}

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
