.PHONY: test build run demo bpf tidy

VERSION ?= 0.1.0

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/kardia ./cmd/kardia

run: build
	./bin/kardia -mode=all -scenario=demo -listen=:8080

demo: run

tidy:
	go mod tidy

# Compile CO-RE objects on a Linux builder with clang, libbpf headers, and BTF.
# Objects land in bpf/out and are loaded by the node agent.
bpf:
	mkdir -p bpf/out
	@for src in bpf/*.bpf.c; do \
		obj=bpf/out/$$(basename $$src .c).o; \
		echo "clang $$src"; \
		clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
			-I/usr/include -I/usr/include/bpf -Ibpf \
			-c $$src -o $$obj || exit 1; \
	done

image:
	docker build -t kardia:$(VERSION) .
