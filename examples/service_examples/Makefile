.PHONY: all clean

all: manager_example peer_example

fmt:
	@go mod tidy
	@gofmt -s -w .
	@`which echo` -e '\033[1;35m[gofmt]\033[0m' \
		`readlink -f .`

manager_example: fmt
	@go build -o $(BUILD_OUT_DIR)/manager_example.run manager_example/main.go
	@`which echo` -e '\033[1;35m[go build]\033[0m' \
		`readlink -f manager_example/main.go` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/manager_example.run`

peer_example: fmt
	@go build -o $(BUILD_OUT_DIR)/peer_example.run peer_example/main.go
	@`which echo` -e '\033[1;35m[go build]\033[0m' \
		`readlink -f peer_example/main.go` \
		'\n\t\033[1;35m->\033[0m' \
		`readlink -f $(BUILD_OUT_DIR)/peer_example.run`
