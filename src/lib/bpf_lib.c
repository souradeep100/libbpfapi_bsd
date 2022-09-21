#include <stdio.h>
#include "../prototypes/bpf_svc.h"
#include "bpf_lib.h"

CLIENT* ebpf_connect(char *host)
{
    CLIENT *clt = clnt_create(host, VERIFY_AND_LOAD, VERIFY_AND_LOAD_V1, "tcp");
    if (clt == NULL) {
        printf("Error connecting to eBPF server.\n");
    }

    return clt;
}

int ebpf_verify_load_program(ebpf_verify_arg *args, CLIENT* clt)
{
    if (!args)
    {
        printf("Arguments are NULL, please fill in the verification arguments.\n");
        return -1;
    }

    int *result = ebpf_verify_load_program_1(args, clt);
    if (result == NULL) {
        printf("Call to eBPF server failed.\n");
        return 1;
    }

    printf("Received request. Log size: %u\n", *(args->log_size));

    return 0;
}