#ifndef BPF_SVC_VERIFIER
#define BPF_SVC_VERIFIER

#include "config.hpp"
#include "platform.hpp"
#include "../../prototypes/bpf_svc.h"
#include "ebpf_verifier.hpp"

ebpf_result_t verify_byte_code(
    const unsigned int* program_type,
    const ebpf_inst* instruction_array,
    unsigned int instruction_count,
    char *error_message);

#endif