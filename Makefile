all: build-ebpf build-webapp build-rootkit build-client build-pause

rootkit: build-ebpf build-rootkit

rootkit-aws: build-ebpf-aws build-rootkit

compile = clang -target bpf \
		-D__TARGET_ARCH_x86 \
		-D__KERNEL__ \
		$(3) \
		-DUSE_SYSCALL_WRAPPER=1 \
		-DKBUILD_MODNAME=\"kubedagger\" \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wall \
		-I ebpf/include \
		-I ebpf \
		-g -O2 \
		-c $(1) -o $(2)

generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/include/vmlinux.h

build-ebpf: generate-vmlinux
	mkdir -p pkg/assets/bin
	$(call compile,ebpf/bootstrap.c,pkg/assets/bin/bootstrap.o,)
	$(call compile,ebpf/main.c,pkg/assets/bin/main.o,)

build-ebpf-aws:
	mkdir -p pkg/assets/bin
	$(call compile,ebpf/main.c,pkg/assets/bin/main.o,-DHTTP_REQ_PATTERN=89)

build-webapp:
	mkdir -p bin/
	go build -o bin/ ./cmd/demo/webapp

build-rootkit:
	mkdir -p bin/
	go build -o bin/ ./cmd/kubedagger

build-client:
	mkdir -p bin/
	go build -o bin/ ./cmd/kubedagger-client

build-pause:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w' -o bin/ ./cmd/demo/pause/./...

static:
	mkdir -p bin/
	go build -tags osusergo,netgo -ldflags="-extldflags '-static'" -o bin/ ./cmd/./...

run:
	sudo ./bin/kubedagger

test:
	go test ./...

lint:
	golangci-lint run ./...

install_client:
	sudo cp ./bin/kubedagger-client /usr/bin/
