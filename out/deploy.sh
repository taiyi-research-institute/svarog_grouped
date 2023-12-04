#!/bin/bash

tmux kill-session -t svarog || true
tmux new-session -s svarog \
    -n man -d ";" new-window \
    -n peer -d ";"
sleep 1
tmux send-keys -t svarog:man "./svarog_manager.run" C-m
tmux send-keys -t svarog:peer "./svarog_peer.run" C-m