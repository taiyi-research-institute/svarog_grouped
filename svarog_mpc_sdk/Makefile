.PHONY: all clean

all:
	@cargo fmt
	@`which echo` -e '\033[1;35m[cargo fmt]\033[0m' \
		`readlink -f .`
	@cargo build --release --bin new_session --bin $(EXAMPLE_NAME)_main

	@cp ./target/release/new_session $(BUILD_OUT_DIR)/new_session.run
	@`which echo` -e '\033[1;35m[cargo build]\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/new_session.run`

	@cp ./target/release/$(EXAMPLE_NAME)_main $(BUILD_OUT_DIR)/$(EXAMPLE_NAME)_main.run
	@`which echo` -e '\033[1;35m[cargo build]\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/$(EXAMPLE_NAME)_main.run`
