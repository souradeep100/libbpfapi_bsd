#include <stdio.h>
#include "../lib/bpf_lib.h"

int main (int argc, char **argv)
{
    printf("Starting client...\n");

    CLIENT *clt = ebpf_connect("localhost");
    printf("Opened connection...\n");

    struct ebpf_verify_arg args;
    uint size = 10;
    args.log_size = &size;

    int result = ebpf_verify_load_program(&args, clt);

    if (result != 0)
    {
        printf("ERROR: status code is %i\n", result);
    }
    else
    {
        printf("Done sending the request\n");
    }

    return result;
}