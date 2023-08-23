package main

import (
	"context"
	"fmt"
	"os"
	pb "svarog_tests/proto/gen"
	"time"

	"github.com/akamensky/argparse"
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

	var member_name *string
	{ // parse command line arguments
		parser := argparse.NewParser("testMpcAttendKeygen", "Test mpc_attend_keygen")
		member_name = parser.String("n", "name", &argparse.Options{Required: true, Help: "Member name"})
		err = parser.Parse(os.Args)
		parser.Parse(os.Args)
		if err != nil {
			fmt.Println(parser.Usage(err))
			panic(nil)
		}
	}

	var session_id string
	{ // load session id from /dev/shm/session
		file, err := os.OpenFile(
			"/dev/shm/svarog_session",
			os.O_RDONLY,
			0666)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		buf := make([]byte, 1024)
		n, err := file.Read(buf)
		if err != nil {
			panic(err)
		}
		session_id = string(buf[:n])
	}

	{ // call grpc function
		req := &pb.MemberAttendance{
			SessionId:  session_id,
			MemberName: *member_name,
		}
		resp, err := stub.MpcAttendKeygen(ctx, req)
		if err != nil {
			panic(err)
		}
		fmt.Println(resp)
	}
}
