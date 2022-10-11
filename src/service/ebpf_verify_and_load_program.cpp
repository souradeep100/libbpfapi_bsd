
#include <string>
#include <iostream>

#include "ebpf_verifier.hpp"

#include "../prototypes/bpf_svc.h"
#include "common.hpp"
#include "verifier/verifier_service.hpp"

ebpf_result_t ebpf_verify_and_load_program(
    ebpf_prog_type_t *program_type,
    int program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    unsigned int handle_map_count,
    const original_fd_handle_map_t *handle_map,
    uint32_t instruction_count,
    const ebpf_inst *instructions,
    char *error_message)
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;
    uint64_t log_function_address;
    error_message = NULL;

    try
    {
        // Verify the program.
        log_info("Setting verificaiton in progress...\n");
        set_verification_in_progress(true);

        log_info("Calling verify_byte_code...\n");
        result = verify_byte_code(program_type, instructions, instruction_count, error_message);
    }
    catch (const std::bad_alloc&)
    {
        result = EBPF_NO_MEMORY;
    }
    catch (std::runtime_error& err)
    {
        auto message = err.what();
        *error_message = *message;

        result = EBPF_VERIFICATION_FAILED;
    }
    catch (...)
    {
        result = EBPF_FAILED;
    }

    return result;
}

edpf_verify_result *ebpf_verify_load_program_1_svc(ebpf_verify_and_load_arg *args, struct svc_req *req)
{
    log_info("Received call to ebpf_verify_load_program_1_svc...\n");
    static edpf_verify_result result { .result = EBPF_SUCCESS };
    result.message = "."; // must fill something, otherwise rpc fails

    if (!args)
    {
        log_info("Arguments are empty\n");
        result.result = EBPF_INVALID_ARGUMENT;
        return &result;
    }

    log_info("Program name:\n");
    log_info(args->info->program_type->name);
    log_info("\n");

    log_info("Setting program under verification...\n");
    set_program_under_verification(args->info->program_handle);

    log_info("Verifying BPF program...\n");

    result.result = ebpf_verify_and_load_program(
        NULL,
        args->info->program_handle,
        args->info->execution_context,
        args->info->execution_type,
        args->info->map_count,
        args->info->handle_map,
        args->info->instruction_count,
        reinterpret_cast<ebpf_inst*>(args->info->instructions),
        result.message);

    ebpf_clear_thread_local_storage();

    return &result;
}