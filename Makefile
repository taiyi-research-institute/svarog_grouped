# Makefile of the whole "Svarog" project

.PHONY: all clean

all: proto main

main:
	@tmux kill-session -t Sv || true
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager

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

test: all
	@tmux new-session -s Sv \
		-n svgmon -d ";"
	@sleep 1
	@tmux send-keys -t Sv:svgmon "cd $(shell pwd)/out && ./svarog_manager.run" C-m
