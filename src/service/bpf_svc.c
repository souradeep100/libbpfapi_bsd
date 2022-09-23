#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../prototypes/bpf_svc.h"
#include "bpf.h"

static void log_info(const char* fmt, ...)
{
    // TODO: logging
}

static char* get_verifier_path()
{
    char* path = getenv("PREVAIL_PATH");

    if (!path)
    {
        fprintf(stderr, "PREVAIL_PATH environment variable is not set.\n");
        exit(-1);
    }

    return path;
}

ebpf_result_t ebpf_verify_and_load_program(
    const unsigned int program_type,
    int program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    unsigned int handle_map_count,
    const original_fd_handle_map_t* handle_map,
    uint32_t instruction_count,
    const ebpf_inst_t* instructions,
    const char** error_message,
    unsigned int* error_message_size)
{
}

ebpf_result_t* ebpf_verify_load_program_1_svc(ebpf_verify_and_load_arg *args, struct svc_req *req)
{
    static ebpf_result_t result = 0;
    if (!args)
    {
        log_info("Arguments are empty\n");
        result = EBPF_INVALID_ARGUMENT;
        return &result;
    }

    // implement thread-local handle: https://github.com/microsoft/ebpf-for-windows/blob/1160f7914e43ebac5e3619d662754eef1af02fb8/ebpfsvc/rpc_api.cpp#L27

    log_info("Verifying BPF program...");

    result = ebpf_verify_and_load_program(
        args->info->program_type,
        args->info->program_handle,
        args->info->execution_context,
        args->info->execution_type,
        args->info->map_count,
        args->info->handle_map,
        args->info->instruction_count,
        (ebpf_inst_t*)args->info->instructions,
        args->logs,
        args->log_size);

    // TODO: clear thread local storage: https://github.com/microsoft/ebpf-for-windows/blob/1160f7914e43ebac5e3619d662754eef1af02fb8/ebpfsvc/rpc_api.cpp#L41

    return &result;
}

edpf_verify_result * ebpf_verify_program_1_svc(ebpf_verify_arg *args, struct svc_req *req)
{
    static edpf_verify_result result;
    result.result = EBPF_VERIFIER_NOT_PROCESSED;
    result.message = NULL;
    char* byte_code_path = args->path;
    log_info("Received request, running check program, bytecode path is %s", byte_code_path);

    int fds[2];
    if (pipe(fds) == -1) {
        log_info("Unable to stand up pipe from/to verifier.\n");
        result.result = EBPF_VERIFIER_CALL_ERR;
        result.message = "Unable to stand up pipe from/to verifier";
        return &result;
    }

    log_info("Created pipe...\n");

    pid_t pid = fork();
    log_info("Forked...\n");
    if (pid == 0)
    {
        log_info("Starting child process...\n");
        while ((dup2(fds[1], STDOUT_FILENO) == -1)) {}
        while ((dup2(fds[1], STDERR_FILENO) == -1)) {}

        log_info("Closing file descriptors...\n");
        close(fds[1]);
        close(fds[0]);

        log_info("Calling verifier...\n");
        char *args[] = { "check", byte_code_path, "2/1",  "--domain=zoneCrab", NULL };
        int status = execvp(get_verifier_path(), args);

        log_info("Failed to execute command: %i\n", status);
        exit(status);
    }

    log_info("Closing parent file descriptor...\n");
    close(fds[1]);

    log_info("Waiting child process...\n");
    int check_status;
    waitpid(pid, &check_status, 0);

    int8_t verifier_exit_code = WEXITSTATUS(check_status);

    if (WIFSIGNALED(check_status))
    {
        log_info("Verifier process ended abnormally, exit code: %i\n", verifier_exit_code);
        result.result = EBPF_VERIFIER_ABNOR_EXIT;
        result.message = "Verifier process ended abnormally";
        return &result;
    }

    log_info("Verifier process exited, exit code: %i\n", verifier_exit_code);

    if (verifier_exit_code != 0)
    {
        log_info("Verifier process exited with non-zero value, exiting... Exit code: %i\n", verifier_exit_code);
        result.result = EBPF_VERIFIER_NON_ZERO_EXIT;
    }

    static char buffer[1024];
    for (short i = 0; i < 1024; i++)
    {
        buffer[i] = ' ';
    }

    ssize_t count = read(fds[0], buffer, sizeof(buffer));
    if (count == -1)
    {
        log_info("Error reading verifier output, count is %i\n", (int)count);
        result.result = EBPF_VERIFIER_CALL_ERR;
        return &result;
    }
    else if (count == 0)
    {
        log_info("Verifier's STDOUT is empty...\n");
    }

    log_info("Verifier output: %s\n", &buffer[0]);
    result.message = &buffer[0];
    if (result.result == EBPF_VERIFIER_NON_ZERO_EXIT)
    {
        return &result;
    }

    close(fds[0]);

    char verifier_status = buffer[0];
    if (verifier_status == '1')
    {
        log_info("Succeeded, verifier status: %s\n", &verifier_status);
        result.result = EBPF_VERIFIER_PASS;
    }
    else
    {
        log_info("Verifier returned non-success code: %s\n", &verifier_status);
        result.result = EBPF_VERIFIER_INVALID;
    }

    return &result;
}
