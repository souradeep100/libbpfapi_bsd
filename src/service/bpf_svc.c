#include "../prototypes/bpf_svc.h"

int result;
int * ebpf_verify_load_program_1_svc(ebpf_verify_arg *args, struct svc_req *req)
{
    result = 0;
    if (!args)
    {
        printf("Arguments are empty\n");
        result = -1;
        return &result;
    }

    printf("Verifying BPF program...");

    return &result;
}