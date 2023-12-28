example_service_keygen: kill_tmux
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_peer
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./examples/service_examples
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n peer -d ";" new-window \
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
	@sleep 1
	@tmux send-keys -t svarog:peer "cd $(shell pwd)/out && ./svarog_peer.run" C-m
	@sleep 2
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./manager_example.run -t keygen" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m bromine" C-m
	@tmux send-keys -t svarog:_pI "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m iodine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./peer_example.run -t keygen -i a6b65314fb234a2da6b29e8036b59be6 -m argon" C-m

example_service_sign: kill_tmux
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_peer
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./examples/service_examples
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n peer -d ";" new-window \
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
	@sleep 1
	@tmux send-keys -t svarog:peer "cd $(shell pwd)/out && ./svarog_peer.run" C-m
	@sleep 2
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./manager_example.run -t sign" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m bromine" C-m
	@tmux send-keys -t svarog:_pI "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m iodine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./peer_example.run -t sign -k a6b65314fb234a2da6b29e8036b59be6 -i ba2e15797ffa4e62859155fc7fc50556 -m argon" C-m

example_service_reshare: kill_tmux
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_peer
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./examples/service_examples
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n peer -d ";" new-window \
		-n ses -d ";" new-window \
		-n pF  -d ";" new-window \
		-n pCl -d ";" new-window \
		-n pBr -d ";" new-window \
		-n _pI -d ";" new-window \
		-n pHe -d ";" new-window \
		-n pNe -d ";" new-window \
		-n pAr -d ";" new-window \
		-n pLi -d ";" new-window \
		-n pNa -d ";" new-window \
		-n pK  -d ";" new-window \
		-n pRb -d ";" new-window \
		-n pCs -d ";"
	@sleep 1
	@tmux send-keys -t svarog:man "cd $(shell pwd)/out && ./svarog_manager.run" C-m
	@sleep 1
	@tmux send-keys -t svarog:peer "cd $(shell pwd)/out && ./svarog_peer.run" C-m
	@sleep 2
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./manager_example.run -t reshare" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m bromine" C-m
	@tmux send-keys -t svarog:_pI "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m iodine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m argon" C-m
	@tmux send-keys -t svarog:pLi "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m lithium" C-m
	@tmux send-keys -t svarog:pNa "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m sodium" C-m
	@tmux send-keys -t svarog:pK  "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m potassium" C-m
	@tmux send-keys -t svarog:pRb "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m rubidium" C-m
	@tmux send-keys -t svarog:pCs "cd $(shell pwd)/out && ./peer_example.run -t reshare -k a6b65314fb234a2da6b29e8036b59be6 -i c24f01d0af1f4cb4acb77fb1a8f1839b -m cesium" C-m
