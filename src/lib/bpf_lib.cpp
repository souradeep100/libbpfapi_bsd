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

    if (args->info->instructions.instructions_len == 0)
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
    printf("val2: ");
    for(int i = 0; i < sizeof(*(args->info->instructions.instructions_val)); i++)
    {
        printf("%02x",((unsigned char*)args->info->instructions.instructions_val)[i]);
    }
    printf(" opcode %i", args->info->instructions.instructions_val->offset);
    printf("\n");

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

    // std::vector<ebpf_instruction_t> instructions;
    ebpf_instruction_t* instructions = (ebpf_instruction_t*) malloc(sizeof(ebpf_instruction_t) * raw_prog.prog.size());
    short count = 0;
    for(ebpf_inst original_inst : raw_prog.prog)
    {
        ebpf_instruction_t* inst = (ebpf_instruction_t*) malloc(sizeof(ebpf_instruction_t));
        memcpy(inst, reinterpret_cast<ebpf_instruction_t*>(&original_inst), sizeof(ebpf_instruction_t));

        printf("sending inst original: ");
        for(int i = 0; i < sizeof(original_inst); i++)
        {
            printf("%02x",((unsigned char*)&original_inst)[i]);
        }
        printf(" opcode %i", original_inst.offset);
        printf("\n");

        printf("sending inst converted: ");
        for(int i = 0; i < sizeof(inst); i++)
        {
            printf("%02x",((unsigned char*)inst)[i]);
        }
        printf(" opcode %i", inst->offset);
        printf("\n");

        instructions[count] = *inst;
        count++;
    }

    printf("\n");

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
    info->instructions.instructions_val = instructions;
    info->instructions.instructions_len = raw_prog.prog.size();
    info->handle_map = handle_map;

    return info;
}