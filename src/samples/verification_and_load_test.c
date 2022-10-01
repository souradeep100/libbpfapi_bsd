#include <stdio.h>
#include "../lib/bpf_lib.h"

int main (int argc, char **argv)
{
    printf("Starting client...\n");

    CLIENT *clt = ebpf_connect("localhost");
    printf("Opened connection...\n");

    struct ebpf_verify_and_load_arg args;
    int prog_type = 2;
    ebpf_program_load_info* info = malloc(sizeof(ebpf_program_load_info));
    info->object_name = "a";
    info->section_name = "a";
    info->program_name = "a";
    info->program_type = &prog_type;
    info->program_handle = 1;

    args.info = &info;
    args.error_message = "test";

    int result = ebpf_verify_load_program(&args, clt);

    if (result != 0)
    {
        printf("ERROR: status code is %d\n", (int)result);
    }
    else
    {
        printf("Done sending the request\n");
    }

    return result;
}