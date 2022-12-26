#ifndef BPF_SVC_VERIFIER
#define BPF_SVC_VERIFIER

#include "config.hpp"
#include "platform.hpp"
#include "../../prototypes/bpf_svc.h"
#include "ebpf_verifier.hpp"

ebpf_result_t verify_byte_code(
    const ebpf_prog_type_t* program_type,
    const ebpf_inst* instruction_array,
    unsigned int instruction_count,
    const EbpfMapDescriptor * maps_array,
    uint32_t maps_count,
    char *error_message);

#endif