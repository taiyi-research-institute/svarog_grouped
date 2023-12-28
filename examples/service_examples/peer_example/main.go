package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	pb "service_examples/proto/gen"

	"github.com/akamensky/argparse"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	err := ArgParse()
	if err != nil {
		panic(err)
	}

	switch *args.ses_type {
	case "keygen":
		xpub, err := PeerKeygen(*args.peer_url, *args.ses_id, *args.member_name)
		if err != nil {
			panic(err)
		}
		fmt.Println(xpub)
	case "sign":
		sigs, err := PeerSign(*args.peer_url, *args.ses_id, *args.member_name, *args.key_id)
		if err != nil {
			panic(err)
		}
		sigs_beautiful_bytes, err := json.MarshalIndent(sigs, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(sigs_beautiful_bytes))
	case "reshare":
		xpub, err := PeerReshare(*args.peer_url, *args.ses_id, *args.member_name, *args.key_id)
		if err != nil {
			panic(err)
		}
		fmt.Println(xpub)
	default:
		panic("Invalid or unimplemented session type")
	}
}

var args struct {
	peer_url    *string
	ses_type    *string
	ses_id      *string
	member_name *string
	key_id      *string
}

func ArgParse() error {
	parser := argparse.NewParser("peer_example", "Examples of mpc peer (xuanwu)")
	args.peer_url = parser.String(
		"s",
		"peer_hostport",
		&argparse.Options{
			Required: false,
			Help:     "MPC peer's host:port",
			Default:  "127.0.0.1:9001",
		},
	)
	args.ses_type = parser.String(
		"t",
		"ses_type",
		&argparse.Options{
			Required: true,
			Help:     "Session type. Currently only `keygen` and `sign` are supported",
		},
	)

	args.ses_id = parser.String(
		"i",
		"id",
		&argparse.Options{
			Required: true,
			Help:     "SessionID. Typically a UUID-v4 in lowercases and without hyphens",
		},
	)
	args.member_name = parser.String(
		"m",
		"member_name",
		&argparse.Options{
			Required: true,
			Help:     "Member name",
		},
	)
	args.key_id = parser.String(
		"k",
		"key_id",
		&argparse.Options{
			Required: false,
			Help:     "KeyID. Typically the SessionID of a successful keygen session",
		},
	)

	err := parser.Parse(os.Args)
	if err != nil {
		return err
	}

	{ // validate args.ses_type
		valid_ses_types := []string{"keygen", "sign", "reshare"}
		found := false
		for _, validvalid_ses_types := range valid_ses_types {
			if validvalid_ses_types == *args.ses_type {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Invalid ses_type %s. Valid ses_types are: %v\n", *args.ses_type, valid_ses_types)
		}
	}

	if *args.ses_type != "keygen" {
		if *args.key_id == "" {
			return fmt.Errorf("key_id is required for ses_type %s\n", *args.ses_type)
		}
	}

	return nil
}

func PeerKeygen(
	sesman_hostport string,
	ses_id string,
	member_name string,
) (xpub string, err error) {
	conn, err := grpc.Dial(sesman_hostport, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	if err != nil {
		return "", fmt.Errorf("Failed to connect to %s: %v\n", sesman_hostport, err)
	}
	peer := pb.NewMpcPeerClient(conn)
	fmt.Println("Joining keygen session", ses_id, "as", member_name)

	_, err = peer.JoinSession(context.Background(), &pb.JoinSessionRequest{
		SessionId:  ses_id,
		MemberName: member_name,
	})
	if err != nil {
		return "", fmt.Errorf("Failed to join session: %v\n", err)
	}

	for { // poll session fruit
		ses_fruit, err := peer.GetSessionFruit(context.Background(), &pb.GetSessionFruitRequest{
			SessionId:  ses_id,
			MemberName: member_name,
		})
		if err != nil {
			return "", fmt.Errorf("Failed to get session fruit: %v\n", err)
		}
		xpub = ses_fruit.GetRootXpub()
		if xpub == "" {
			fmt.Println("Waiting for keygen session fruit...")
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	// The trick of using /dev/shm/keygen_session_id is only to automate the example.
	// In real world, the key_id should be provided by the upstream biz.
	err = os.WriteFile("/dev/shm/keygen_session_id", []byte(ses_id), 0644)
	if err != nil {
		return "", fmt.Errorf("Failed to write keygen_session_id: %v\n", err)
	}

	return xpub, nil
}

func PeerSign(
	sesman_hostport string,
	ses_id string,
	member_name string,
	key_id string,
) (sigs []*pb.Signature, err error) {
	conn, err := grpc.Dial(sesman_hostport, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to %s: %v\n", sesman_hostport, err)
	}
	peer := pb.NewMpcPeerClient(conn)
	fmt.Println("Joining sign session", ses_id, "as", member_name, "using key", key_id)

	_, err = peer.JoinSession(context.Background(), &pb.JoinSessionRequest{
		SessionId:  ses_id,
		MemberName: member_name,
		KeyName:    key_id,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to join session: %v\n", err)
	}

	for { // poll session fruit
		ses_fruit, err := peer.GetSessionFruit(context.Background(), &pb.GetSessionFruitRequest{
			SessionId:  ses_id,
			MemberName: member_name,
		})
		if err != nil {
			return nil, fmt.Errorf("Failed to get session fruit: %v\n", err)
		}
		sigs_ := ses_fruit.GetSignatures()
		if sigs_ == nil {
			fmt.Println("Waiting for sign session fruit...")
			time.Sleep(1 * time.Second)
			continue
		} else {
			for _, sig := range sigs_.Signatures {
				sigs = append(sigs, sig)
			}
			break
		}
	}

	return sigs, nil
}

func PeerReshare(
	sesman_hostport string,
	ses_id string,
	member_name string,
	key_id string,
) (xpub string, err error) {
	conn, err := grpc.Dial(sesman_hostport, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	if err != nil {
		return "", fmt.Errorf("Failed to connect to %s: %v\n", sesman_hostport, err)
	}
	peer := pb.NewMpcPeerClient(conn)
	fmt.Println("Joining reshare session", ses_id, "as", member_name, "using key", key_id)

	_, err = peer.JoinSession(context.Background(), &pb.JoinSessionRequest{
		SessionId:  ses_id,
		MemberName: member_name,
		KeyName:    key_id,
	})
	if err != nil {
		return "", fmt.Errorf("Failed to join session: %v\n", err)
	}

	for { // poll session fruit
		ses_fruit, err := peer.GetSessionFruit(context.Background(), &pb.GetSessionFruitRequest{
			SessionId:  ses_id,
			MemberName: member_name,
		})
		if err != nil {
			return "", fmt.Errorf("Failed to get session fruit: %v\n", err)
		}
		xpub = ses_fruit.GetRootXpub()
		if xpub == "" {
			fmt.Println("Waiting for reshare session fruit...")
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	return xpub, nil
}
