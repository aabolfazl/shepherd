#include <bpf/libbpf.h>
#include <net/if.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <signal.h>
#include <yaml-cpp/yaml.h>

class fix_flow_controller {
private:
    struct bpf_object *obj;
    std::string interface;
    bool running;
    struct sigaction sa;
    
    static void signal_handler(int signo, siginfo_t *info, void *context) {
        std::cout << "\nSignal_handler " << signo << std::endl;

        auto controller = static_cast<fix_flow_controller*>(info->si_value.sival_ptr);
        if (controller && (signo == SIGINT || signo == SIGTERM)) {
            std::cout << "\nReceived signal " << signo << ", shutting down..." << std::endl;
            controller->shutdown();
            exit(0);
        }
    }

    void load_config(const std::string& configPath) {
        try {
            YAML::Node config = YAML::LoadFile(configPath);
            interface = config["ebpf"]["interface"].as<std::string>();
        } catch (const YAML::Exception& e) {
            std::cerr << "Config error: " << e.what() << std::endl;
            throw;
        }
    }

    bool setup_signals(){
        sa.sa_sigaction = signal_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);

        struct sigaction old_sa;
        if (sigaction(SIGINT, &sa, &old_sa) == -1 ||
            sigaction(SIGTERM, &sa, &old_sa) == -1) {
            std::cerr << "Failed to set up signal handlers" << std::endl;
            return false;
        }


        sigset_t mask;
        sigemptyset(&mask);
        struct sigevent sev = {};
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGINT;
        sev.sigev_value.sival_ptr = this;

        return true;
    }

public:
    fix_flow_controller(const std::string& configPath) : obj(nullptr), running(true) {
        load_config(configPath);
    }

    int init() {
        // setup_signals();

        obj = bpf_object__open("/home/abolfazl/CLionProjects/shepherd/build/bpf/xdp_pkt_handler.bpf.o");
        if (!obj) {
            std::cerr << "Error opening BPF object" << std::endl;
            return 1;
        }

        if (bpf_object__load(obj)) {
            std::cerr << "Error loading BPF object" << std::endl;
            return 1;
        }

        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
        if (!prog) {
            std::cerr << "Error finding XDP program" << std::endl;
            return 1;
        }

        unsigned int ifindex = if_nametoindex(interface.c_str());
        if (ifindex == 0) {
            std::cerr << "Error finding interface " << interface << std::endl;
            return 1;
        }

        if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), 0, nullptr)) {
            std::cerr << "Error attaching XDP program to " << interface << std::endl;
            return 1;
        }

        return 0;
    }

    void run() {
        while (running) {
            struct bpf_map *map = bpf_object__find_map_by_name(obj, "packet_count");
            if (!map) {
                std::cerr << "Error finding map" << std::endl;
                break;
            }

            __u32 key = 0;
            __u32 value;
            
            int err = bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0);
            if (err == 0) {
                std::cout << "Packets processed: " << value << std::endl;
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void shutdown() {
        if (running) {
            running = false;
            
            if (!interface.empty()) {
                unsigned int ifindex = if_nametoindex(interface.c_str());
                if (ifindex > 0) {
                    bpf_xdp_attach(ifindex, -1, 0, nullptr);
                }
            }

            if (obj) {
                bpf_object__close(obj);
                obj = nullptr;
            }
        }
    }

    ~fix_flow_controller() {
        shutdown();
    }
};

void signal_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        std::cout << "\nReceived signal " << signo << ", shutting down..." << std::endl;
        exit(0);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config.yaml>" << std::endl;
        return 1;
    }

    try {
        fix_flow_controller controller(argv[1]);
        if (controller.init() != 0) {
            return 1;
        }

        controller.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}