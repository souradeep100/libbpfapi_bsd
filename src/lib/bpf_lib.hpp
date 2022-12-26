#ifndef _BPF_LIB_BSD
#define _BPF_LIB_BSD

#include "../prototypes/bpf_svc.h"
#include "config.hpp"
#include "platform.hpp"
#undef FALSE
#undef TRUE
#include "ebpf_verifier.hpp"

CLIENT* ebpf_connect(char *host);

edpf_verify_result* ebpf_verify_program(ebpf_verify_and_load_arg *args, CLIENT* clt);

ebpf_program_load_info* ebpf_load_program(const char * file_path, const char * section_name);

#endif