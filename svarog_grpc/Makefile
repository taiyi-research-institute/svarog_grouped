.PHONY: all

all: rust go

rust:
	@cargo build --release --manifest-path=protoc_rust/Cargo.toml
	@rsync -a protoc_rust/target/release/protoc_rust ./protoc_rust.run
	@`which echo` -e '\033[1;35m[protoc rs]\033[0m' \
		`readlink -f protoc_rust.run`
	@./protoc_rust.run -r ./src/protogen
	@`which echo` -e '\033[1;35m[protoc rs]\033[0m' \
		`readlink -f proto/` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f ./`"/{src,Cargo.toml}"

go:
	@protoc --go_out=$(SVAROG_GO_PROTOGEN) --go-grpc_out=$(SVAROG_GO_PROTOGEN) --proto_path=proto proto/*.proto
	@`which echo` -e '\033[1;35m[protoc go]\033[0m' \
		`readlink -f proto` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f $(SVAROG_GO_PROTOGEN)/proto/gen`

clean:
	@rm -rf protoc_rust.run
	@`which echo` -e '\033[1;35m[DELETE]\033[0m' `readlink -f protoc_rust.run`

# java:
# 	rm -rf src_java
# 	mkdir src_java
# 	protoc --java_out=src_java --grpc-java_out=src_java --proto_path=proto proto/*.proto