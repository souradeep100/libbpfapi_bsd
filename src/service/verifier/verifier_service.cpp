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
        log_info("Unmarshalling error\n");
        // *error_message = allocate_string(std::get<std::string>(prog_or_error), error_message_size);
        return EBPF_VERIFICATION_FAILED; // Error;
    }

    InstructionSeq& prog = std::get<InstructionSeq>(prog_or_error);

    // First try optimized for the success case.
    ebpf_verifier_options_t options = ebpf_verifier_default_options;
    ebpf_verifier_stats_t stats;
    options.check_termination = true;
    bool res = ebpf_verify_program(std::cout, prog, raw_prog.info, &options, &stats);
    if (!res) {
        // On failure, retry to get the more detailed error message.
        std::ostringstream oss;
        options.no_simplify = true;
        options.print_failures = true;
        (void)ebpf_verify_program(oss, prog, raw_prog.info, &options, &stats);

        // *error_message = allocate_string(oss.str(), error_message_size);
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
    char *error_message)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_linux;
    std::vector<ebpf_inst> instructions{instruction_array, instruction_array + instruction_count};
    log_info("Built instructions vector...\n");
    program_info info{platform};
    std::string section;
    std::string file;
    std::vector<raw_program> raw_progs;
    try
    {
        // TODO: verification works by using read_elf, need to start implementing posix functions
        log_info("Opening file...\n");
        raw_progs = read_elf("/home/edguer/Projects/libbpfapi_bsd/external/ebpf-verifier/ebpf-samples/cilium/bpf_lxc.o", "2/1", &ebpf_verifier_default_options, &g_ebpf_platform_linux);
        info.type = raw_progs.back().info.type;
        log_info("Parsed ELF file\n");
        // info.type = get_program_type_windows(*program_type);
    }
    catch (std::runtime_error e) {
        *error_message = *e.what();
        log_info("Verification failed...\n");
        return EBPF_VERIFICATION_FAILED;
    }

    if (raw_progs.size() > 0)
    {
        log_info("More than 1 raw_progs...\n");
    }

    raw_program raw_prog{file, section, instructions, info};

    return _analyze(raw_prog, error_message);
}