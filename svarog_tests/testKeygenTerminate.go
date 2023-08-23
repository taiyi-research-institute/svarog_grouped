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

	var member_id *int
	{ // parse command line arguments
		parser := argparse.NewParser("testMpcTerminateKeygen", "Test mpc_attend_keygen")
		member_id = parser.Int("i", "id", &argparse.Options{Required: true, Help: "Member ID"})
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
		xpub1 := "xpub661MyMwAqRbcEYbPGwcGB77U1P26KFRq1Mgh1Up7oW4ZYWU6qMKwurmTkNz4jTJEJShNojdKA2whoDtCThmsejJZk1ZvZmrz46oX5KxdTKB"
		// xpub2 := "xpub661MyMwAqRbcFVbz6WtQjfYxk9hrEL3BP99wzYw6TFTb3FnJQ6LdQj8VZbSWc46ntmem5ArnUMxbsgsNCaF3DQTBmYXd845hSbhE9GMoKGY"
		req := &pb.KeygenTermination{
			SessionId: session_id,
			MemberId:  int64(*member_id),
			RootXpub:  xpub1,
		}

		_, err := stub.MpcTerminateKeygen(ctx, req)
		if err != nil {
			panic(err)
		}
	}
}
