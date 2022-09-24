#ifndef BPF_SVC_COMMON
#define BPF_SVC_COMMON

#include <stdbool.h>

struct _ebpf_inst
{
    unsigned char opcode;
    unsigned char dst : 4; //< Destination register
    unsigned char src : 4; //< Source register
    unsigned short offset;
    int imm; //< Immediate constant
};

typedef struct _ebpf_inst ebpf_inst_t;

void set_verification_in_progress(bool value);

void log_info(const char* fmt, ...);

void ebpf_clear_thread_local_storage();

void set_program_under_verification(int program);

#endif