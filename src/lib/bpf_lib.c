#include <stdio.h>
#include "../prototypes/bpf_svc.h"
#include "bpf_lib.h"

CLIENT* ebpf_connect(char *host)
{
    CLIENT *clt = clnt_create(host, BPF_SVC, BPF_SVC_V1, "tcp");
    if (clt == NULL) {
        printf("Error connecting to eBPF server.\n");
    }

    return clt;
}

int ebpf_verify_load_program(ebpf_verify_and_load_arg *args, CLIENT* clt)
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

edpf_verify_result* ebpf_verify_program(ebpf_verify_arg *args, CLIENT* clt)
{
    static edpf_verify_result result;
    if (!args)
    {
        printf("Arguments are NULL, please fill in the verification arguments.\n");

        result.message = "Arguments are NULL, please fill in the verification arguments";
        result.result = EBPF_VERIFIER_CALL_ERR;
        return &result;
    }

    printf("Arguments filled, file to be validated: %s\n", args->path);

    edpf_verify_result *svc_result = ebpf_verify_program_1(args, clt);
    if (svc_result == NULL) {
        printf("Call to eBPF server failed.\n");

        result.message = "Call to eBPF server failed";
        result.result = EBPF_VERIFIER_CALL_ERR;
        return &result;
    }

    printf("Successful call to eBPF service.\n");

    return svc_result;
}