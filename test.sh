#!/bin/sh

cargo clean && cargo update && cargo build && cargo test
