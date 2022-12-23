#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include "platform.hpp"
#include "ebpf_verifier.hpp"
#include "../../prototypes/bpf_svc.h"
#include "../common.hpp"

static ebpf_result_t _analyze(raw_program& raw_prog, const char* error_message)
{
    log_info("Unmarshalling...\n");
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error))
    {
        // TODO: we are getting "2: invalid helper function id" here
        log_info("Unmarshalling error\n");
        log_info(std::get<std::string>(prog_or_error).c_str());
        // *error_message = allocate_string(std::get<std::string>(prog_or_error), error_message_size);
        return EBPF_VERIFICATION_FAILED; // Error;
    }

    InstructionSeq& prog = std::get<InstructionSeq>(prog_or_error);

    // First try optimized for the success case.
    ebpf_verifier_options_t options = ebpf_verifier_default_options;
    ebpf_verifier_stats_t stats;
    options.check_termination = true;
    bool res = ebpf_verify_program(std::cout, prog, raw_prog.info, &options, &stats);
    log_info("VERIFY RESULT: ");
    log_info(res ? "true" : "false");
    log_info("\n");
    if (!res) {
        // On failure, retry to get the more detailed error message.
        std::ostringstream oss;
        options.no_simplify = true;
        options.print_failures = true;
        (void)ebpf_verify_program(oss, prog, raw_prog.info, &options, &stats);

        // *error_message = allocate_string(oss.str(), error_message_size);
        log_info("VERIFICATION DETAILS: ");
        log_info(oss.str().c_str());
        log_info("\n");
        return EBPF_VERIFICATION_FAILED; // Error;
    }
    return EBPF_SUCCESS; // Success.
}

extern const ebpf_platform_t g_ebpf_platform_linux;
extern const ebpf_verifier_options_t ebpf_verifier_default_options;

ebpf_result_t verify_byte_code(
    const ebpf_prog_type_t* program_type,
    const ebpf_inst* instruction_array,
    unsigned int instruction_count,
    const EbpfMapDescriptor * maps_array,
    uint32_t maps_count,
    char *error_message)
{
    std::vector<ebpf_inst> instructions{instruction_array, instruction_array + instruction_count};
    std::vector<EbpfMapDescriptor> maps{maps_array, maps_array + maps_count};
    std::string section;
    std::string file;
    std::vector<raw_program> raw_progs;

    ebpf_context_descriptor_t cxt_descriptor { program_type->context_descriptor.size, program_type->context_descriptor.data, program_type->context_descriptor.end, program_type->context_descriptor.meta };

    std::vector<std::string> section_prefixes(program_type->section_prefixes.section_prefixes_len);
    for (size_t i = 0; i < program_type->section_prefixes.section_prefixes_len; i++)
    {
        section_prefixes.push_back(program_type->section_prefixes.section_prefixes_val[i].str);
    }

    EbpfProgramType type
    {
        .name = program_type->name,
        .context_descriptor = &cxt_descriptor,
        .platform_specific_data = program_type->platform_specific_data,
        .section_prefixes = section_prefixes,
        .is_privileged = (bool)program_type->is_privileged
    };

    program_info info{&g_ebpf_platform_linux, maps, type};

    raw_program raw_prog{file, section, instructions, info};

    return _analyze(raw_prog, error_message);
}