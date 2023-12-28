example_sdk_keygen: kill_tmux
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="keygen" make -C ./examples/sdk_examples
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

example_sdk_keygen_mnem: kill_tmux 
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="keygen_mnem" make -C ./examples/sdk_examples
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
	@tmux send-keys -t svarog:pNu "cd $(shell pwd)/out && ./keygen_mnem_main.run -p" C-m
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./keygen_mnem_main.run -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./keygen_mnem_main.run -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./keygen_mnem_main.run -m bromine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./keygen_mnem_main.run -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./keygen_mnem_main.run -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./keygen_mnem_main.run -m argon" C-m

example_sdk_sign: kill_tmux 
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="sign" make -C ./examples/sdk_examples
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


example_sdk_reshare: kill_tmux 
	@BUILD_OUT_DIR="$(shell pwd)/out" make -C ./svarog_manager
	@BUILD_OUT_DIR="$(shell pwd)/out" EXAMPLE_NAME="reshare" make -C ./examples/sdk_examples
	@tmux new-session -s svarog \
		-n man -d ";" new-window \
		-n ses -d ";" new-window \
		-n pF  -d ";" new-window \
		-n pCl -d ";" new-window \
		-n pBr -d ";" new-window \
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
	@sleep 3
	@tmux send-keys -t svarog:ses "cd $(shell pwd)/out && ./new_session.run reshare" C-m
	@sleep 1
	@tmux send-keys -t svarog:pF  "cd $(shell pwd)/out && ./reshare_main.run -m fluorine" C-m
	@tmux send-keys -t svarog:pCl "cd $(shell pwd)/out && ./reshare_main.run -m chlorine" C-m
	@tmux send-keys -t svarog:pBr "cd $(shell pwd)/out && ./reshare_main.run -m bromine" C-m
	@tmux send-keys -t svarog:pHe "cd $(shell pwd)/out && ./reshare_main.run -m helium" C-m
	@tmux send-keys -t svarog:pNe "cd $(shell pwd)/out && ./reshare_main.run -m neon" C-m
	@tmux send-keys -t svarog:pAr "cd $(shell pwd)/out && ./reshare_main.run -m argon" C-m
	@tmux send-keys -t svarog:pLi "cd $(shell pwd)/out && ./reshare_main.run -r -m lithium" C-m
	@tmux send-keys -t svarog:pNa "cd $(shell pwd)/out && ./reshare_main.run -r -m sodium" C-m
	@tmux send-keys -t svarog:pK  "cd $(shell pwd)/out && ./reshare_main.run -r -m potassium" C-m
	@tmux send-keys -t svarog:pRb "cd $(shell pwd)/out && ./reshare_main.run -r -m rubidium" C-m
	@tmux send-keys -t svarog:pCs "cd $(shell pwd)/out && ./reshare_main.run -r -m cesium" C-m