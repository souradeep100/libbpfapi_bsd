#include "bpf_lib.hpp"

CLIENT* ebpf_connect(char *host)
{
    CLIENT *clt = clnt_create(host, BPF_SVC, BPF_SVC_V1, "tcp");
    if (clt == NULL) {
        printf("Error connecting to eBPF server.\n");
    }

    return clt;
}

edpf_verify_result* ebpf_verify_program(ebpf_verify_and_load_arg *args, CLIENT* clt)
{
    printf("Sending program for verification...\n");
    static edpf_verify_result result { .result = EBPF_SUCCESS };

    if (!args || !args->info)
    {
        printf("Arguments are NULL, please fill in the verification arguments.\n");
        result.result = EBPF_INVALID_ARGUMENT;
        return &result;
    }

    if (args->info->instruction_count == 0)
    {
        printf("No instructions were provided.\n");
        result.result = EBPF_INVALID_ARGUMENT;
        return &result;
    }

    if (!args->info->program_type)
    {
        printf("Program type is not provided.\n");
        result.result = EBPF_INVALID_ARGUMENT;
        return &result;
    }

    printf("BEFORE LOAD: %s\n", args->info->object_name);

    edpf_verify_result* svr_rst = ebpf_verify_load_program_1(args, clt);
    if (!svr_rst) {
        printf("Call to eBPF server failed.\n");
        result.result = EBPF_FAILED;
        return &result;
    }

    printf("Received request. Log size: %d\n", (int)svr_rst->result);

    return svr_rst;
}

ebpf_program_load_info* ebpf_load_program(const char * file_path)
{
    printf("Opening file...\n");
    std::vector<raw_program> raw_progs = read_elf(file_path, "2/1", &ebpf_verifier_default_options, &g_ebpf_platform_linux);
    raw_program raw_prog = raw_progs.back();

    printf("Opened file!\n");

    ebpf_instruction_t** instructions = (ebpf_instruction_t**) malloc(sizeof(ebpf_instruction_t) * raw_progs.back().prog.size());

    uint inst_count = 0;
    for(ebpf_inst original_inst : raw_prog.prog)
    {
        instructions[inst_count++] = reinterpret_cast<ebpf_instruction_t*>(&original_inst);
    }

    ebpf_prog_type_t *prog_type = (ebpf_prog_type_t*) malloc(sizeof(ebpf_prog_type_t));
    strcpy(prog_type->name, raw_prog.info.type.name.c_str());
    prog_type->is_privileged = raw_prog.info.type.is_privileged;

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

    printf("name: %s\n", info->object_name);

    return info;
}