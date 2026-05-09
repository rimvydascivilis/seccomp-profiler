BINARY      := bin/seccomp-profiler
HOOK_BINARY := bin/seccomp-profiler-hook
BPF_SRC     := bpf/syscall_tracker.c

HOOK_INSTALL    := /usr/local/libexec/oci/hooks.d/seccomp-profiler
HOOK_CONF_DIR   := /usr/local/share/containers/oci/hooks.d
HOOK_CONF       := $(HOOK_CONF_DIR)/seccomp-profiler.json
DOCKER_CONF_DIR := /etc/seccomp-profiler
DOCKER_CONF     := $(DOCKER_CONF_DIR)/oci-hooks.json
DAEMON_JSON     := /etc/docker/daemon.json

.PHONY: all build generate deps install install-deps-debian install-deps-rhel clean

all: generate build

# ── Build ────────────────────────────────────────────────────────────────────

generate: $(BPF_SRC)
	go generate ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -o $(BINARY) .
	CGO_ENABLED=0 go build -o $(HOOK_BINARY) ./hook/
	@echo ""
	@echo "Built:"
	@echo "  $(BINARY)       — profiling daemon"
	@echo "  $(HOOK_BINARY)  — OCI hook"

deps:
	go mod download
	go mod tidy

# ── OCI hook installation ─────────────────────────────────────────────────────
# Podman/CRI-O: hook spec in containers/common format, picked up automatically.
# Docker:       oci-add-hooks registered as the default runtime via daemon.json.
# Requires: root, oci-add-hooks in PATH for Docker support.

install: $(HOOK_BINARY)
	@echo "Installing hook binary → $(HOOK_INSTALL)"
	mkdir -p $(dir $(HOOK_INSTALL))
	install -m 0755 $(HOOK_BINARY) $(HOOK_INSTALL)
	@echo "Installing Podman/CRI-O hook config → $(HOOK_CONF)"
	mkdir -p $(HOOK_CONF_DIR)
	install -m 0644 install/seccomp-profiler.json $(HOOK_CONF)
	@echo "Installing Docker hook config → $(DOCKER_CONF)"
	mkdir -p $(DOCKER_CONF_DIR)
	install -m 0644 install/oci-hook.json $(DOCKER_CONF)
	@if [ -f $(DAEMON_JSON) ]; then \
		echo ""; \
		echo "ACTION REQUIRED: merge the following into $(DAEMON_JSON) and run 'systemctl reload docker':"; \
		cat install/daemon.json; \
	else \
		install -m 0644 install/daemon.json $(DAEMON_JSON); \
		systemctl reload docker; \
		echo ""; \
		echo "Done. All containers are profiled automatically."; \
	fi

# ── Dependency installation helpers ──────────────────────────────────────────

install-deps-debian:
	apt-get install -y clang llvm libbpf-dev linux-libc-dev

install-deps-rhel:
	dnf install -y clang llvm libbpf-devel kernel-headers golang
	GOPATH=/usr/local go install github.com/awslabs/oci-add-hooks@latest

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY) $(HOOK_BINARY)
	rm -f tracker_bpf*.go tracker_bpf*.o
