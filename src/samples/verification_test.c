#include <stdio.h>
#include "../lib/bpf_lib.h"

int main (int argc, char **argv)
{
    printf("Starting client...\n");

    CLIENT *clt = ebpf_connect("localhost");
    printf("Opened connection...\n");

    struct ebpf_verify_arg args;
    args.path = argv[1];

    edpf_verify_result *result = ebpf_verify_program(&args, clt);

    switch (result->result)
    {
        case(EBPF_VERIFIER_NOT_PROCESSED):
            fprintf(stderr, "EBPF_VERIFIER_NOT_PROCESSED %s\n", result->message);
            break;
        case(EBPF_VERIFIER_CALL_ERR):
            fprintf(stderr, "EBPF_VERIFIER_CALL_ERR %s\n", result->message);
            break;
        case(EBPF_VERIFIER_ABNOR_EXIT):
            fprintf(stderr, "EBPF_VERIFIER_ABNOR_EXIT %s\n", result->message);
            break;
        case(EBPF_VERIFIER_NON_ZERO_EXIT):
            fprintf(stderr, "EBPF_VERIFIER_NON_ZERO_EXIT %s\n", result->message);
            break;
        case(EBPF_VERIFIER_PASS):
            printf("PASSED! Output: %s\n", result->message);
            break;
        case(EBPF_VERIFIER_INVALID):
            fprintf(stderr, "REJECTED: %s\n", result->message);
            break;
    }

    return 0;
}