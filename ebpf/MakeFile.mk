BPF_CLANG = clang
BPF_CFLAGS = -O2 -target bpf

all: load_balancer.o

load_balancer.o: load_balancer.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
