#ifndef BPF_SVC_IMPL
#define BPF_SVC_IMPL

struct _ebpf_inst
{
    unsigned char opcode;
    unsigned char dst : 4; //< Destination register
    unsigned char src : 4; //< Source register
    unsigned short offset;
    int imm; //< Immediate constant
};

typedef struct _ebpf_inst ebpf_inst_t;

#endif