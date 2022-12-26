#include "bpf_lib.hpp"

CLIENT* ebpf_connect(char *host)
{
    CLIENT *clt = clnt_create(host, BPF_SVC, BPF_SVC_V1, "tcp");
    if (clt == NULL) {
        printf("Error connecting to eBPF server.\n");
        return NULL;
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

    edpf_verify_result* svr_rst = ebpf_verify_load_program_1(args, clt);
    if (!svr_rst) {
        printf("Call to eBPF server failed.\n");
        result.result = EBPF_FAILED;
        return &result;
    }

    printf("Received request. Log size: %d\n", (int)svr_rst->result);

    return svr_rst;
}

ebpf_program_load_info* ebpf_load_program(const char * file_path, const char * section_name)
{
    printf("Opening file...\n");
    std::vector<raw_program> raw_progs = read_elf(file_path, section_name, &ebpf_verifier_default_options, &g_ebpf_platform_linux);
    raw_program raw_prog = raw_progs.back();

    printf("Opened file!\n");

    ebpf_instruction_t* instructions = (ebpf_instruction_t*) malloc(sizeof(ebpf_instruction_t) * raw_prog.prog.size());
    short inst_count = 0;
    for(ebpf_inst original_inst : raw_prog.prog)
    {
        ebpf_instruction_t* inst = (ebpf_instruction_t*) malloc(sizeof(ebpf_instruction_t));
        memcpy(inst, reinterpret_cast<ebpf_instruction_t*>(&original_inst), sizeof(ebpf_instruction_t));

        instructions[inst_count++] = *inst;
    }

    ebpf_prog_type_t *prog_type = (ebpf_prog_type_t*) malloc(sizeof(ebpf_prog_type_t));
    prog_type->name = strdup(raw_prog.info.type.name.c_str());
    prog_type->is_privileged = raw_prog.info.type.is_privileged;
    ;

    string_item_t * section_prefixes = (string_item_t *) malloc(sizeof(string_item_t) * raw_prog.info.type.section_prefixes.size());
    unsigned short section_prefixes_count = 0;
    for (std::string section_prefix : raw_prog.info.type.section_prefixes)
    {
        section_prefixes[section_prefixes_count++].str = strdup(section_prefix.c_str());
        printf("Copied section prefix: %s", section_prefixes[section_prefixes_count++].str);
    }

    prog_type->section_prefixes.section_prefixes_len = raw_prog.info.type.section_prefixes.size();
    prog_type->section_prefixes.section_prefixes_val = section_prefixes;

    prog_type->context_descriptor.data = raw_prog.info.type.context_descriptor->data;
    prog_type->context_descriptor.end = raw_prog.info.type.context_descriptor->end;
    prog_type->context_descriptor.meta = raw_prog.info.type.context_descriptor->meta;
    prog_type->context_descriptor.size = raw_prog.info.type.context_descriptor->size;

    prog_type->platform_specific_data = raw_prog.info.type.platform_specific_data;

    ebpf_map_descriptor_t * ebpf_map_descriptors = (ebpf_map_descriptor_t *) malloc(sizeof(ebpf_map_descriptor_t) * raw_prog.info.map_descriptors.size());
    unsigned int map_descriptors_count = 0;
    for (EbpfMapDescriptor map : raw_prog.info.map_descriptors)
    {
        ebpf_map_descriptor_t* converted_map = (ebpf_map_descriptor_t*) malloc(sizeof(ebpf_map_descriptor_t));
        memcpy(converted_map, reinterpret_cast<ebpf_map_descriptor_t*>(&map), sizeof(ebpf_map_descriptor_t));

        ebpf_map_descriptors[map_descriptors_count++] = *converted_map;
    }

    original_fd_handle_map_t *handle_map = (original_fd_handle_map_t*) malloc(sizeof(original_fd_handle_map_t*));

    ebpf_program_load_info* info = (ebpf_program_load_info*) malloc(sizeof(ebpf_program_load_info));
    info->object_name = "a";
    info->section_name = strdup(section_name);
    info->program_name = "a";
    info->program_type = prog_type;
    info->program_handle = 1;
    info->instructions.instructions_len = inst_count;
    info->instructions.instructions_val = instructions;
    info->map_descriptors.map_descriptors_len = map_descriptors_count;
    info->map_descriptors.map_descriptors_val = ebpf_map_descriptors;
    info->handle_map = handle_map;

    return info;
}