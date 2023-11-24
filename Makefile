# Makefile of the whole "Svarog" project

.PHONY: all clean

all: proto build deploy

build:
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_peer

deploy:
	@tmux kill-session -t svarog || true
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

example_keygen: proto 
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="keygen" make -C ./svarog_mpc_sdk
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@tmux kill-session -t svarog || true
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n ses -d ";" new-window \
		-n peer1 -d ";"
	@sleep 1
	@tmux send-keys -t svarog:man "cd $(shell pwd)/out && ./svarog_manager.run" C-m
	@sleep 1
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./new_session.run keygen" C-m
	@sleep 1
	@tmux send-keys -t svarog:peer1 "cd $(shell pwd)/out && ./keygen_main.run -m Rivest" C-m

clean:
	@make -C ./svarog_manager clean
	@make -C ./svarog_peer clean
