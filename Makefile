# Makefile of the whole "Svarog" project

.PHONY: all clean

all: proto build deploy

build:
	@tmux kill-session -t svarog || true
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_peer

deploy:
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n peer -d ";"
	@sleep 1
	@tmux send-keys -t svarog:man "cd $(shell pwd)/out && ./svarog_manager.run" C-m
	@tmux send-keys -t svarog:peer "cd $(shell pwd)/out && ./svarog_peer.run" C-m

# aliases of target `proto`
protobuf: proto
grpc: proto

proto:
	@SVAROG_RUST_PROTOGEN="$(shell pwd)/svarog_peer/src/protogen" \
	 SVAROG_GO_PROTOGEN="$(shell pwd)/svarog_manager" \
		make -C ./svarog_grpc

clean:
	@make -C ./svarog_manager clean
	@make -C ./svarog_peer clean

