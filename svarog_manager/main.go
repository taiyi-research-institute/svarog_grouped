package main

import (
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
	"google.golang.org/grpc"

	biz "svarog_manager/bizlogic"
	pb "svarog_manager/proto/gen"
)

var conf = struct {
	Peer struct {
		GrpcHost   string
		GrpcPort   uint16
		SqlitePath string
	}
	Sesman struct {
		GrpcHost   string
		GrpcPort   uint16
		SqlitePath string
	}
	Logging struct {
		Level string
		Dir   string
	}
}{}

func main() {
	if _, err := os.Stat("mpc_service_config.toml"); os.IsNotExist(err) {
		panic("`mpc_service_config.toml` not found.\n" +
			"Originally, this file accompanies the executable.\n")
	}
	_, err := toml.DecodeFile("mpc_service_config.toml", &conf)
	if err != nil {
		panic("Cannot decode `mpc_service_config.toml`. DO NOT rename or remove any field.\n" + err.Error())
	}
	grpc_hostport := fmt.Sprintf(
		"%s:%d",
		conf.Sesman.GrpcHost,
		conf.Sesman.GrpcPort,
	)
	sock, err := net.Listen("tcp", grpc_hostport)
	if err != nil {
		panic(err)
	}

	bizCore := &biz.SessionManager{}
	bizCore.InitLogger(conf.Logging.Level, conf.Logging.Dir)
	bizCore.InitDB()
	bizCore.InitSessionRecycler()

	var opt []grpc.ServerOption
	grpcServer := grpc.NewServer(opt...)
	pb.RegisterMpcSessionManagerServer(grpcServer, bizCore)

	fmt.Println("Mpc Session Manager will listen at", grpc_hostport, "...")
	err = grpcServer.Serve(sock) // hopefully, forever run
	if err != nil {
		panic("Mpc Session Manager is down. Reason:\n" + err.Error())
	}
}
