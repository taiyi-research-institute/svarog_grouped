package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	xw "mpctest/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func keygen() {
	fmt.Println("MANAGER KEYGEN function called，启动一个 keygen 会话")
	// 拨号连接 GRPC 服务器
	var serverAddr = "127.0.0.1:9000"
	var conn, err = grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect to %s: %v\n", serverAddr, err)
		return
	}
	// 创建 MPC Session Manager Client
	var client = xw.NewMpcSessionManagerClient(conn)
	// keygen 请求
	request := &xw.SessionConfig{
		SessionType: "keygen",
		KeyQuorum:   2, // 签名时需提供分片数的最小值
		Groups: []*xw.Group{{ // 张三
			GroupName:   "zhangsan",
			GroupQuorum: 1, // 该组签名时需提供的分片数的最小值
			Members: []*xw.Member{{
				MemberName:  "zhangsanfeng",
				IsAttending: true, // keygen时所有成员都需参与
			}},
		}, { // 李四
			GroupName:   "lisi",
			GroupQuorum: 1,
			Members: []*xw.Member{{
				MemberName:  "lisiguang",
				IsAttending: true,
			}},
		}},
	}
	// 创建 keygen session
	sessConf, err := client.NewSession(context.Background(), request)
	if err != nil {
		log.Printf("Failed to create session: %v\n", err)
		return
	}
	log.Println("Session created")
	resp, err := json.MarshalIndent(sessConf, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal session config: %v\n", err)
		return
	}
	fmt.Printf("%+v\n", string(resp))
}

func sign(hash []byte) {
	fmt.Println("Sign function called，启动一个 sign 会话")
	// 拨号连接 GRPC 服务器
	var serverAddr = "127.0.0.1:9000"
	var conn, err = grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect to %s: %v\n", serverAddr, err)
		return
	}
	// 创建 MPC Session Manager Client
	var client = xw.NewMpcSessionManagerClient(conn)
	// sign 请求
	request := &xw.SessionConfig{
		SessionType: "sign",
		KeyQuorum:   2, // 签名时需提供分片数的最小值
		Groups: []*xw.Group{{ // 张三
			GroupName:   "zhangsan",
			GroupQuorum: 1, // 该组签名时需提供的分片数的最小值
			Members: []*xw.Member{{
				MemberName:  "zhangsanfeng",
				IsAttending: true,
			}},
		}, { // 李四
			GroupName:   "lisi",
			GroupQuorum: 1,
			Members: []*xw.Member{{
				MemberName:  "lisiguang",
				IsAttending: true,
			}},
		}},
		ToSign: &xw.ToSign{
			TxHashes: []*xw.TxHash{{
				TxHash:     hash,
				DerivePath: "m/44/60/0/0/0",
			}},
		},
	}
	// 创建 sign session
	sessConf, err := client.NewSession(context.Background(), request)
	if err != nil {
		log.Printf("Failed to create session: %v\n", err)
		return
	}
	log.Println("Session created")
	resp, err := json.MarshalIndent(sessConf, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal session config: %v\n", err)
		return
	}
	fmt.Printf("%+v\n", string(resp))
}

func main() {
	keygenPtr := flag.Bool("keygen", false, "Generate key")
	signPtr := flag.Bool("sign", false, "Sign the document")
	hashPtr := flag.String("hash", "", "Hash of the document")

	flag.Parse()

	hash, err := hex.DecodeString(*hashPtr)
	if err != nil {
		log.Printf("Failed to decode hash: %v\n", err)
		return
	}

	if *keygenPtr {
		keygen()
	} else if *signPtr {
		sign(hash)
	}
}
