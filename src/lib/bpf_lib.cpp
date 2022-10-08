#include "bpf_lib.hpp"

CLIENT* ebpf_connect(char *host)
{
    CLIENT *clt = clnt_create(host, BPF_SVC, BPF_SVC_V1, "tcp");
    if (clt == NULL) {
        printf("Error connecting to eBPF server.\n");
    }

    return clt;
}

ebpf_result_t ebpf_verify_program(ebpf_verify_and_load_arg *args, CLIENT* clt)
{
    // printf("Sending program for verification...\n");
    // if (!args || !args->info)
    // {
    //     printf("Arguments are NULL, please fill in the verification arguments.\n");
    //     return EBPF_INVALID_ARGUMENT;
    // }

    // if (args->info->instruction_count == 0)
    // {
    //     printf("No instructions were provided.\n");
    //     return EBPF_INVALID_ARGUMENT;
    // }

    printf("BEFORE LOAD: %s\n", args->info->object_name);
    ebpf_result_t* result = ebpf_verify_load_program_1(args, clt);
    if (result == NULL) {
        printf("Call to eBPF server failed.\n");
        return EBPF_FAILED;
    }

    printf("Received request. Log size: %d\n", (int)*result);

    return *result;
}

ebpf_verify_and_load_arg* ebpf_load_program(const char * file_path)
{
    printf("Opening file...\n");
    std::vector<raw_program> raw_progs = read_elf(file_path, "2/1", &ebpf_verifier_default_options, &g_ebpf_platform_linux);

    printf("Opened file!\n");

    struct ebpf_verify_and_load_arg* args = (ebpf_verify_and_load_arg*) malloc(sizeof(ebpf_verify_and_load_arg));;

    ebpf_instruction_t** instructions = (ebpf_instruction_t**) malloc(sizeof(ebpf_instruction_t) * raw_progs.back().prog.size());

    uint inst_count = 0;
    for(ebpf_inst original_inst : raw_progs.back().prog)
    {
        instructions[inst_count] = reinterpret_cast<ebpf_instruction_t*>(&original_inst);
        printf("opcode: %i\n", instructions[inst_count]->opcode);
        ++inst_count;
    }

    ebpf_cxt_descriptor_t context_descriptor;

    ebpf_prog_type_t *prog_type = (ebpf_prog_type_t*) malloc(sizeof(ebpf_prog_type_t));
    prog_type->is_privileged = 1;
    prog_type->context_descriptor = context_descriptor;
    prog_type->name = "program";

    original_fd_handle_map_t *handle_map = (original_fd_handle_map_t*) malloc(sizeof(original_fd_handle_map_t*));

    ebpf_program_load_info* info = (ebpf_program_load_info*) malloc(sizeof(ebpf_program_load_info));
    info->object_name = "a";
    info->section_name = "a";
    info->program_name = "a";
    info->program_type = prog_type;
    info->program_handle = 1;
    info->instructions = instructions[0];
    info->instruction_count = inst_count;
    info->handle_map = handle_map;

    args->info = info;
    printf("name: %s\n", info->object_name);
    args->error_message = "test";

    return args;
}