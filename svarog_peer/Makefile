.PHONY: all clean

all:
	@cargo fmt
	@`which echo` -e '\033[1;35m[cargo fmt]\033[0m' \
		`readlink -f .`
	@cargo build --release
	@cp ./target/release/svarog_peer $(BUILD_OUT_DIR)/svarog_peer.run
	@`which echo` -e '\033[1;35m[cargo build]\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/svarog_peer.run`
