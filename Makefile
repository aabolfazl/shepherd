OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_DIR := src/ebpf

$(shell mkdir -p $(OUTPUT))

BPF_CFLAGS := -g -O2 -Wall
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(OUTPUT)
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS += -I/usr/include

BPF_PROGRAMS := xdp_pkt_handler

BPF_OBJS := $(addprefix $(OUTPUT)/,$(addsuffix .bpf.o,$(BPF_PROGRAMS)))

$(info Building BPF objects: $(BPF_OBJS))
$(info Source directory: $(BPF_DIR))

$(OUTPUT)/vmlinux.h: 
	@echo "Generating $@..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(OUTPUT)/vmlinux.h
	@echo "Compiling $@..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

.PHONY: bpf
bpf: $(BPF_OBJS)

.PHONY: clean
clean:
	rm -rf $(OUTPUT)

.PHONY: list
list:
	@echo "BPF source files:"
	@ls -la $(BPF_DIR)
	@echo "\nOutput directory:"
	@ls -la $(OUTPUT)