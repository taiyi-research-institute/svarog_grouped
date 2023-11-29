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

type Config struct {
	Grpc struct {
		Port uint16
	}
	Logging struct {
		Level string
		Dir   string
	}
}

func NewDefaultConfig() *Config {
	conf := new(Config)
	conf.Grpc.Port = 9000
	conf.Logging.Level = "debug"
	conf.Logging.Dir = "./"
	return conf
}

func main() {
	conf := NewDefaultConfig()
	// create config file if not exist, avoid panic
	if _, err := os.Stat("svarog.toml"); os.IsNotExist(err) {
		_, err := os.Create("svarog.toml")
		if err != nil {
			panic(err)
		}
	}
	_, err := toml.DecodeFile("svarog.toml", &conf)
	if err != nil {
		panic(err)
	}
	grpc_hostport := fmt.Sprintf("localhost:%d", conf.Grpc.Port)
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

	fmt.Println("Svarog GRPC server is running at ", grpc_hostport, " ...")
	grpcServer.Serve(sock) // hopefully, forever run
}
