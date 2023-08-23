.PHONY: all

all: keygen

keygen:
	@gofmt -s -w .
	@go run testBizNewKeygenSession.go
	@for name in a b c d e f g h i j k l m; do \
		go run testMpcAttendKeygen.go -n $$name; \
	done
	@tmux kill-session -t SvTest || true
	@tmux new-session -s SvTest \
		-n poll -d ";"
	@sleep 1
	@tmux send-keys \
		-t SvTest:poll \
		"watch -n 1 go run testBizPollProgress.go" \
		C-m
	@for id in 6 10 2 11 13 9 12 3 7 8 4 5 1; do \
		go run testMpcTerminateKeygen.go -i $$id; \
	done

sign:
	@gofmt -s -w .
	@go run testBizNewSignSession.go
	