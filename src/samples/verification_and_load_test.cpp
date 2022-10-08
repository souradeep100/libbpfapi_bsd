#include "../lib/bpf_lib.hpp"

int main (int argc, char **argv)
{
    printf("Starting client...\n");

    CLIENT *clt = ebpf_connect("localhost");
    printf("Opened connection...\n");

    ebpf_verify_and_load_arg* args = ebpf_load_program("/home/edguer/Projects/libbpfapi_bsd/external/ebpf-verifier/ebpf-samples/cilium/bpf_lxc.o");

    int result = ebpf_verify_program(args, clt);

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