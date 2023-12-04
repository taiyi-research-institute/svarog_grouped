package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"golang.org/x/crypto/blake2b"

	pb "service_examples/proto/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	sesman_hostport, ses_type := ArgParse()
	var conf *pb.SessionConfig
	var err error
	switch ses_type {
	case "keygen":
		conf, err = NewKeygenSession(sesman_hostport)
	case "sign":
		derive_paths := []string{
			"m/44/1/2/3/4",
		}
		tx_hash := blake2b.Sum256([]byte(
			"Je ne veux pas travailler. Je ne veux pas dejeuner. Je veux seulement l'oublier, et puis je fume.",
		))
		if err != nil {
			panic(err)
		}
		tx_hashes := append([][32]byte{}, tx_hash)
		conf, err = NewSignSession(sesman_hostport, derive_paths, tx_hashes)
		if err != nil {
			panic(err)
		}
	default:
		panic("Unknown or unimplemented session type: " + ses_type)
	}

	conf_beautiful_bytes, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		panic("Failed to marshal session config: " + err.Error())
	}
	fmt.Println(string(conf_beautiful_bytes))
}

func ArgParse() (string, string) {
	parser := argparse.NewParser("manager_example", "Examples of mpc session manager (svarog, luban)")
	sesman_hostport := parser.String(
		"s",
		"sesman_hostport",
		&argparse.Options{
			Required: false,
			Help:     "Session manager's host:port",
			Default:  "127.0.0.1:9000",
		},
	)
	ses_type := parser.Selector(
		"t",
		"type",
		[]string{"keygen", "sign"},
		&argparse.Options{
			Required: true,
			Help:     "Session type. Currently supported: keygen, sign",
		},
	)
	err := parser.Parse(os.Args)
	if err != nil {
		panic(parser.Usage(err))
	}
	return *sesman_hostport, *ses_type
}

func NewKeygenSession(
	sesman_hostport string,
) (resp *pb.SessionConfig, err error) {
	conn, err := grpc.Dial(
		sesman_hostport,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	defer conn.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to %s: %v\n", sesman_hostport, err)
	}
	var client = pb.NewMpcSessionManagerClient(conn)

	req := &pb.SessionConfig{
		SessionType: "keygen",
		KeyQuorum:   4, // minimum count of shards to sign
		Groups: []*pb.Group{{
			GroupName:   "halogen",
			GroupQuorum: 2, // minimum count of shards to sign
			Members: []*pb.Member{{
				MemberName:  "fluorine",
				IsAttending: true,
			}, {
				MemberName:  "chlorine",
				IsAttending: true,
			}, {
				MemberName:  "bromine",
				IsAttending: true,
			}},
		}, {
			GroupName:   "noble_gas",
			GroupQuorum: 1, // minimum count of shards to sign
			Members: []*pb.Member{{
				MemberName:  "helium",
				IsAttending: true,
			}, {
				MemberName:  "neon",
				IsAttending: true,
			}, {
				MemberName:  "argon",
				IsAttending: true,
			}},
		}},
	}

	conf, err := client.NewSession(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %v\n", err)
	}
	return conf, nil
}

func NewSignSession(
	sesman_hostport string,
	derive_paths []string,
	tx_hashes [][32]byte,
) (resp *pb.SessionConfig, err error) {
	if len(tx_hashes) == 0 {
		return nil, errors.New("No hashes provided.")
	}
	if len(tx_hashes) > 1 {
		return nil, errors.New("Batch sign currently not yet ready.")
	}
	if len(derive_paths) != len(tx_hashes) {
		return nil, errors.New("Count of derivation paths should equal to count of Tx hashes.")
	}

	conn, err := grpc.Dial(
		sesman_hostport,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	defer conn.Close()
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to %s: %v\n", sesman_hostport, err)
	}
	var client = pb.NewMpcSessionManagerClient(conn)

	req := &pb.SessionConfig{
		SessionType: "sign",
		KeyQuorum:   2, // minimum count of shards to sign
		Groups: []*pb.Group{{
			GroupName:   "halogen",
			GroupQuorum: 2, // minimum count of shards to sign
			Members: []*pb.Member{{
				MemberName:  "fluorine",
				IsAttending: false,
			}, {
				MemberName:  "chlorine",
				IsAttending: true,
			}, {
				MemberName:  "bromine",
				IsAttending: true,
			}},
		}, { // BEGIN group "noble_gas"
			GroupName:   "noble_gas",
			GroupQuorum: 1, // minimum count of shards to sign
			Members: []*pb.Member{{
				MemberName:  "helium",
				IsAttending: true,
			}, {
				MemberName:  "neon",
				IsAttending: true,
			}, {
				MemberName:  "argon",
				IsAttending: false,
			}},
		}},
		ToSign: &pb.ToSign{},
	}
	for idx, tx_hash := range tx_hashes {
		req.ToSign.TxHashes = append(req.ToSign.TxHashes, &pb.TxHash{
			DerivePath: derive_paths[idx],
			TxHash:     tx_hash[:],
		})
	}
	resp, err = client.NewSession(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("Failed to create sign session: %v\n", err)
	}

	return resp, nil
}
