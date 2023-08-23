package main

import (
	"context"
	"fmt"
	"os"
	pb "svarog_tests/proto/gen"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var err error
	var conn *grpc.ClientConn
	var stub pb.SvarogServerClient
	var ctx context.Context
	var cancel context.CancelFunc

	{ // ceremony of grpc initialization
		conn, err = grpc.Dial(
			"localhost:9000",
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		stub = pb.NewSvarogServerClient(conn)
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}

	var resp *pb.NewSessionResponse
	{ // call grpc function
		req := &pb.KeygenSessionCompleteParams{
			Groups: []*pb.Group{
				{
					MemberNames: []string{"a", "b", "c"},
					SubQuorum:   2,
				}, {
					MemberNames: []string{"d", "e", "f", "g", "h"},
					SubQuorum:   3,
				}, {
					MemberNames: []string{"i", "j", "k", "l", "m"},
					SubQuorum:   3,
				},
			},
			Quorum: 8,
		}
		resp, err = stub.BizNewKeygenSession(ctx, req)
		if err != nil {
			panic(err)
		}
		fmt.Println(resp)
	}

	{ // write to /dev/shm/session
		file, err := os.OpenFile(
			"/dev/shm/svarog_session",
			os.O_RDWR|os.O_CREATE|os.O_TRUNC,
			0666)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		_, err = file.Write([]byte(resp.SessionId))
		if err != nil {
			panic(err)
		}
	}
}
