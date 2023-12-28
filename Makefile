# Makefile of the whole "Svarog" project

.PHONY: all clean

all: proto build

build: kill_tmux
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_peer

deploy:
	cd $(shell pwd)/out && ./deploy.sh

pack: build
	mkdir -p $(shell pwd)/package
	cp $(shell pwd)/out/svarog_manager.run $(shell pwd)/package
	cp $(shell pwd)/out/svarog_peer.run $(shell pwd)/package
	cp $(shell pwd)/out/deploy.sh $(shell pwd)/package
	cp $(shell pwd)/out/mpc_service_config.toml $(shell pwd)/package

# aliases of target `proto`
protobuf: proto
grpc: proto

proto:
	@SVAROG_RUST_PROTOGEN="$(shell pwd)/svarog_peer/src/protogen" \
	 SVAROG_GO_PROTOGEN="$(shell pwd)/svarog_manager" \
	 SVAROG_GO_EXAMPLE_PROTOGEN="$(shell pwd)/examples/service_examples" \
		make -C ./svarog_grpc

clean:
	@make -C ./svarog_manager clean
	@make -C ./svarog_peer clean

kill_tmux:
	@tmux kill-session -t svarog || true

include examples/sdk_examples.mk
include examples/service_examples.mk