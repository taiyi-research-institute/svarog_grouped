.PHONY: all clean

all: svarog_manager 

svarog_manager:
	@gofmt -s -w .
	@`which echo` -e '\033[1;35m[gofmt]\033[0m' \
		`readlink -f .`
	@go build -o $(BUILD_OUT_DIR)/svarog_manager.run main.go
	@`which echo` -e '\033[1;35m[go build]\033[0m' \
		`readlink -f main.go` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/svarog_manager.run`
