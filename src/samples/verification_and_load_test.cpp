#include "../lib/bpf_lib.hpp"

int main (int argc, char **argv)
{
    printf("Starting client...\n");

    CLIENT *clt = ebpf_connect("localhost");
    printf("Opened connection...\n");

    ebpf_program_load_info* prog_info = ebpf_load_program("/home/edguer/Projects/libbpfapi_bsd/external/ebpf-verifier/ebpf-samples/cilium/bpf_lxc.o", "2/1");

    ebpf_verify_and_load_arg* args = (ebpf_verify_and_load_arg*) malloc(sizeof(ebpf_verify_and_load_arg));
    args->info = prog_info;

    edpf_verify_result *result = ebpf_verify_program(args, clt);

    if (result->result != 0)
    {
        printf("ERROR: status code is %d\n", (int)result->result);
    }
    else
    {
        printf("Program is valid!\n");
    }

    return result->result;
}