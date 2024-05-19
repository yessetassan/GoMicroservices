package main

import (
	"context"
	"log"
	"net"
	"testing"

	pb "MarketShop/cmd/user"
	"MarketShop/pkg/db"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			Authenticate,
		)),
	)
	pb.RegisterUserServiceServer(s, &server{})

	db.InitDB() // Initialize the database connection

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func getToken(client pb.UserServiceClient, t *testing.T) string {
	ctx := context.Background()
	loginReq := &pb.LoginRequest{
		Username: "tauke",
		Password: "tauke",
	}
	loginResp, err := client.Login(ctx, loginReq)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	return loginResp.Token
}

func TestCreateUser(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewUserServiceClient(conn)

	req := &pb.CreateUserRequest{
		User: &pb.User{
			FirstName:  "TestJohn",
			LastName:   "TestDoe",
			MiddleName: "T",
			Login:      "testjohndoe",
			Email:      "test.john.doe@example.com",
			Password:   "password123",
		},
	}

	resp, err := client.CreateUser(ctx, req)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if resp.User.Login != "testjohndoe" {
		t.Errorf("expected login to be 'testjohndoe', got %v", resp.User.Login)
	}
}

func TestGetUser(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewUserServiceClient(conn)

	// First, create a user to get
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createReq := &pb.CreateUserRequest{
		User: &pb.User{
			FirstName:  "TestJane",
			LastName:   "TestDoe",
			MiddleName: "T",
			Login:      "testjanedoe",
			Email:      "test.jane.doe@example.com",
			Password:   string(hashedPassword),
		},
	}
	createResp, err := client.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Get token for authentication
	token := getToken(client, t)

	// Now test get user with token
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
	getReq := &pb.GetUserRequest{Id: createResp.User.Id}
	getResp, err := client.GetUser(ctx, getReq)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if getResp.User.Login != "testjanedoe" {
		t.Errorf("expected login to be 'testjanedoe', got %v", getResp.User.Login)
	}
}

func TestUpdateUser(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewUserServiceClient(conn)

	// First, create a user to update
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createReq := &pb.CreateUserRequest{
		User: &pb.User{
			FirstName:  "TestAlice",
			LastName:   "TestSmith",
			MiddleName: "T",
			Login:      "testalicesmith",
			Email:      "test.alice.smith@example.com",
			Password:   string(hashedPassword),
		},
	}
	createResp, err := client.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Get token for authentication
	token := getToken(client, t)

	// Now test update user with token
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
	updateReq := &pb.UpdateUserRequest{
		User: &pb.User{
			Id:         createResp.User.Id,
			FirstName:  "TestAliceUpdated",
			LastName:   "TestSmithUpdated",
			MiddleName: "TUpdated",
			Email:      "test.alice.updated@example.com",
		},
	}
	updateResp, err := client.UpdateUser(ctx, updateReq)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if updateResp.User.FirstName != "TestAliceUpdated" {
		t.Errorf("expected first name to be 'TestAliceUpdated', got %v", updateResp.User.FirstName)
	}
}

func TestDeleteUser(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewUserServiceClient(conn)

	// First, create a user to delete
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createReq := &pb.CreateUserRequest{
		User: &pb.User{
			FirstName:  "TestBob",
			LastName:   "TestJohnson",
			MiddleName: "T",
			Login:      "testbobjohnson",
			Email:      "test.bob.johnson@example.com",
			Password:   string(hashedPassword),
		},
	}
	createResp, err := client.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Get token for authentication
	token := getToken(client, t)

	// Now test delete user with token
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
	deleteReq := &pb.DeleteUserRequest{Id: createResp.User.Id}
	_, err = client.DeleteUser(ctx, deleteReq)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user is deleted
	getReq := &pb.GetUserRequest{Id: createResp.User.Id}
	_, err = client.GetUser(ctx, getReq)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound error, got %v", err)
	}
}

func TestLogin(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewUserServiceClient(conn)

	// First, create a user to login with
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createReq := &pb.CreateUserRequest{
		User: &pb.User{
			FirstName:  "TestCharlie",
			LastName:   "TestBrown",
			MiddleName: "T",
			Login:      "testcharliebrown",
			Email:      "test.charlie.brown@example.com",
			Password:   string(hashedPassword),
		},
	}
	_, err = client.CreateUser(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Now test login
	loginReq := &pb.LoginRequest{
		Username: "assan",
		Password: "assan",
	}
	loginResp, err := client.Login(ctx, loginReq)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if loginResp.Token == "" {
		t.Errorf("expected a token, got empty string")
	}
}
