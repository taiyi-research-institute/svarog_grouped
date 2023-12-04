.PHONY: all clean

all: sdk_examples

sdk_examples:
	@cargo fmt
	@`which echo` -e '\033[1;35m[cargo fmt]\033[0m' \
		`readlink -f .`
	@cargo build --release --bin $(EXAMPLE_NAME)_main --bin new_session
	@cp target/release/$(EXAMPLE_NAME)_main $(BUILD_OUT_DIR)/$(EXAMPLE_NAME)_main.run
	@cp target/release/new_session $(BUILD_OUT_DIR)/new_session.run
	@`which echo` -e '\033[1;35m[cargo build]\033[0m' \
		`readlink -f $(EXAMPLE_NAME)_main.rs` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/$(EXAMPLE_NAME)_main.run`
	@`which echo` -e '\033[1;35m[cargo build]\033[0m' \
		`readlink -f new_session.rs` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/new_session.run`
