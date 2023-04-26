

GOVERSION=$(shell go version)
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)


clean:
	cd ./pkg/ebpf/;rm *.tmp *.o.*;cd -


build:
	go mod tidy
	go generate ./...
	$(MAKE) clean


# install:
# 	$(MAKE) build
# 	sudo cp cmd/srv6_tracing_agent/main /usr/local/bin/srv6_ebpfagent
# 	sudo chmod +x /usr/local/bin/srv6_ebpfagent

