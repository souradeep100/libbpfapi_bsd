
#include <string>
#include <iostream>

#include "ebpf_verifier.hpp"

// #include "verifier/freebsd/freebsd_platform.hpp"

#include "../prototypes/bpf_svc.h"
#include "common.hpp"

static ebpf_result_t _analyze(raw_program& raw_prog, const char** error_message, uint32_t* error_message_size = nullptr)
{
    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
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

// TODO: use right error message types etc
ebpf_result_t verify_byte_code(
    const unsigned int* program_type,
    const ebpf_inst* instruction_array,
    unsigned int instruction_count,
    log_str_t *error_message,
    unsigned int *error_message_size)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_linux;
    return EBPF_INSUFFICIENT_BUFFER;
    std::vector<ebpf_inst> instructions{instruction_array, instruction_array + instruction_count};
    program_info info{platform};
    std::string section;
    std::string file;
    // try {
    //     info.type = get_program_type_windows(*program_type);
    // } catch (std::runtime_error e) {
    //     error << "error: " << e.what();
    //     *error_message = allocate_string(error.str());
    //     return EBPF_VERIFICATION_FAILED;
    // }

    raw_program raw_prog{file, section, instructions, info};

    return _analyze(raw_prog, NULL, error_message_size);
}

ebpf_result_t ebpf_verify_and_load_program(
    const unsigned int program_type,
    int program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    unsigned int handle_map_count,
    const original_fd_handle_map_t *handle_map,
    uint32_t instruction_count,
    const ebpf_inst *instructions,
    log_str_t *error_message,
    unsigned int *error_message_size)
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;
    uint64_t log_function_address;

    error_message = NULL;
    error_message_size = 0;

    // TODO: try/catch
    // Verify the program.
    set_verification_in_progress(true);
    // result = verify_byte_code(program_type, instructions, instruction_count, error_message, error_message_size);

    return result;
}

ebpf_result_t *ebpf_verify_load_program_1_svc(ebpf_verify_and_load_arg *args, struct svc_req *req)
{
    static ebpf_result_t result = EBPF_SUCCESS;
    if (!args)
    {
        log_info("Arguments are empty\n");
        result = EBPF_INVALID_ARGUMENT;
        return &result;
    }

    set_program_under_verification(args->info->program_handle);

    log_info("Verifying BPF program...");

    result = ebpf_verify_and_load_program(
        args->info->program_type,
        args->info->program_handle,
        args->info->execution_context,
        args->info->execution_type,
        args->info->map_count,
        args->info->handle_map,
        args->info->instruction_count,
        (ebpf_inst*)args->info->instructions,
        args->logs,
        args->log_size);

    ebpf_clear_thread_local_storage();

    return &result;
}