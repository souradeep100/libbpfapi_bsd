#include "../lib/bpf_lib.hpp"

int main (int argc, char **argv)
{
    printf("Starting client...\n");

    CLIENT *clt = ebpf_connect("localhost");
    printf("Opened connection...\n");

    ebpf_program_load_info* prog_info = ebpf_load_program("/home/edguer/Projects/libbpfapi_bsd/external/ebpf-verifier/ebpf-samples/cilium/bpf_lxc.o");
    printf("val1: ");
    for(int i = 0; i < sizeof(*(prog_info->instructions.instructions_val)); i++)
    {
        printf("%02x",((unsigned char*)prog_info->instructions.instructions_val)[i]);
    }
    printf(" opcode %i", prog_info->instructions.instructions_val->offset);
    printf("\n");

    printf("instruction2: ");
    for(int i = 0; i < sizeof(*(prog_info->instruction)); i++)
    {
        printf("%02x",((unsigned char*)prog_info->instruction)[i]);
    }
    printf(" opcode %i", prog_info->instruction->offset);
    printf("\n");


    ebpf_verify_and_load_arg* args = (ebpf_verify_and_load_arg*) malloc(sizeof(ebpf_verify_and_load_arg));
    args->info = prog_info;
    args->info->instructions.instructions_val = args->info->instruction;

    edpf_verify_result *result = ebpf_verify_program(args, clt);

    if (result->result != 0)
    {
        printf("ERROR: status code is %d\n", (int)result->result);
    }
    else
    {
        printf("Done sending the request\n");
    }

    return result->result;
}