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
	@tmux send-keys -t svarog:peer "cd $(shell pwd)/out && ./svarog_peer.run --log debug" C-m

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

kill_tmux:
	@tmux kill-session -t svarog || true

example_keygen: kill_tmux 
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="keygen" make -C ./svarog_mpc_sdk
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n ses -d ";" new-window \
		-n pF  -d ";" new-window \
		-n pCl -d ";" new-window \
		-n pBr -d ";" new-window \
		-n _pI -d ";" new-window \
		-n pHe -d ";" new-window \
		-n pNe -d ";" new-window \
		-n pAr -d ";"
	@sleep 1
	@tmux send-keys -t svarog:man "cd $(shell pwd)/out && ./svarog_manager.run" C-m
	@sleep 3
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./new_session.run keygen" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./keygen_main.run -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./keygen_main.run -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./keygen_main.run -m bromine" C-m
	@tmux send-keys -t svarog:_pI "cd $(shell pwd)/out && ./keygen_main.run -m iodine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./keygen_main.run -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./keygen_main.run -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./keygen_main.run -m argon" C-m

example_keygen_mnem: kill_tmux 
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="keygen_mnem" make -C ./svarog_mpc_sdk
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n ses -d ";" new-window \
		-n pF  -d ";" new-window \
		-n pCl -d ";" new-window \
		-n pBr -d ";" new-window \
		-n pNu -d ";" new-window \
		-n pHe -d ";" new-window \
		-n pNe -d ";" new-window \
		-n pAr -d ";"
	@sleep 1
	@tmux send-keys -t svarog:man "cd $(shell pwd)/out && ./svarog_manager.run" C-m
	@sleep 3
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./new_session.run keygen" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./keygen_mnem_main.run -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./keygen_mnem_main.run -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./keygen_mnem_main.run -m bromine" C-m
	@tmux send-keys -t svarog:pNu "cd $(shell pwd)/out && ./keygen_mnem_main.run -p" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./keygen_mnem_main.run -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./keygen_mnem_main.run -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./keygen_mnem_main.run -m argon" C-m

example_sign: kill_tmux 
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="sign" make -C ./svarog_mpc_sdk
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n ses -d ";" new-window \
		-n pF  -d ";" new-window \
		-n pCl -d ";" new-window \
		-n pBr -d ";" new-window \
		-n pHe -d ";" new-window \
		-n pNe -d ";" new-window \
		-n pAr -d ";"
	@sleep 1
	@tmux send-keys -t svarog:man "cd $(shell pwd)/out && ./svarog_manager.run" C-m
	@sleep 3
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./new_session.run sign" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./sign_main.run -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./sign_main.run -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./sign_main.run -m bromine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./sign_main.run -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./sign_main.run -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./sign_main.run -m argon" C-m