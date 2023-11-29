package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	xw "mpctest/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func keygen(sessionID string, memberName string) {
	fmt.Println("PEER KEYGEN function called，加入 keygen 会话")
	var serverAddr = "127.0.0.1:9001"
	var conn, err = grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	if err != nil {
		log.Printf("Failed to connect to %s: %v\n", serverAddr, err)
		return
	}
	// 创建 MPC Client
	var client = xw.NewMpcPeerClient(conn)
	// 加入 keygen session
	_, err = client.JoinSession(context.Background(), &xw.JoinSessionRequest{
		SessionId:  sessionID,
		MemberName: memberName,
	})
	if err != nil {
		log.Printf("Failed to join session: %v\n", err)
		return
	}
	log.Println("Session joined，接下来是轮询 session 状态")
	for {
		sessFruit, err := client.GetSessionFruit(context.Background(), &xw.SessionId{
			SessionId: sessionID,
		})
		if err != nil {
			log.Printf("Failed to get session fruit: %v\n", err)
			return
		}
		if sessFruit.Value == nil {
			log.Println("Session fruit not ready, waiting...")
			time.Sleep(1 * time.Second)
			continue
		}
		log.Println("Session fruit ready")
		resp, err := json.MarshalIndent(sessFruit, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal session fruit: %v\n", err)
			return
		}
		fmt.Printf("%+v\n", string(resp))
		break
	}
}

func sign(sessionID string, memberName string, keyName string) {
	fmt.Println("Sign function called，加入 sign 会话")
	var serverAddr = "127.0.0.1:9001"
	var conn, err = grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect to %s: %v\n", serverAddr, err)
		return
	}
	// 创建 MPC Client
	var client = xw.NewMpcPeerClient(conn)
	// 加入 keygen session
	_, err = client.JoinSession(context.Background(), &xw.JoinSessionRequest{
		SessionId:  sessionID,
		MemberName: memberName,
		KeyName:    keyName,
	})
	if err != nil {
		log.Printf("Failed to join session: %v\n", err)
		return
	}
	log.Println("Session joined，接下来是轮询 session 状态")
	for {
		sessFruit, err := client.GetSessionFruit(context.Background(), &xw.SessionId{
			SessionId: sessionID,
		})
		if err != nil {
			log.Printf("Failed to get session fruit: %v\n", err)
			return
		}
		if sessFruit.Value == nil {
			log.Println("Session fruit not ready, waiting...")
			time.Sleep(1 * time.Second)
			continue
		}
		log.Println("Session fruit ready")
		resp, err := json.MarshalIndent(sessFruit, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal session fruit: %v\n", err)
			return
		}
		fmt.Printf("%+v\n", string(resp))
		break
	}
}

func main() {
	keygenPtr := flag.Bool("keygen", false, "Generate key")
	signPtr := flag.Bool("sign", false, "Sign the document")
	sessionID := flag.String("session", "", "Session ID")
	memberName := flag.String("member", "", "Member name")
	keyName := flag.String("key", "", "Key name")

	flag.Parse()

	if *keygenPtr {
		keygen(*sessionID, *memberName)
	} else if *signPtr {
		sign(*sessionID, *memberName, *keyName)
	}
}
