#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../prototypes/bpf_svc.h"

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

int * ebpf_verify_load_program_1_svc(ebpf_verify_and_load_arg *args, struct svc_req *req)
{
    static int result = 0;
    if (!args)
    {
        // printf("Arguments are empty\n");
        result = -1;
        return &result;
    }

    // printf("Verifying BPF program...");

    return &result;
}

edpf_verify_result * ebpf_verify_program_1_svc(ebpf_verify_arg *args, struct svc_req *req)
{
    static edpf_verify_result result;
    result.result = EBPF_VERIFIER_NOT_PROCESSED;
    result.message = NULL;
    char* byte_code_path = args->path;
    // printf("Received request, running check program, bytecode path is %s", byte_code_path);

    int fds[2];
    if (pipe(fds) == -1) {
        // printf("Unable to stand up pipe from/to verifier.\n");
        result.result = EBPF_VERIFIER_CALL_ERR;
        result.message = "Unable to stand up pipe from/to verifier";
        return &result;
    }

    // printf("Created pipe...\n");

    pid_t pid = fork();
    // printf("Forked...\n");
    if (pid == 0)
    {
        // printf("Starting child process...\n");
        while ((dup2(fds[1], STDOUT_FILENO) == -1)) {}
        while ((dup2(fds[1], STDERR_FILENO) == -1)) {}

        // printf("Closing file descriptors...\n");
        close(fds[1]);
        close(fds[0]);

        // printf("Calling verifier...\n");
        char *args[] = { "check", byte_code_path, "2/1",  "--domain=zoneCrab", NULL };
        int status = execvp(get_verifier_path(), args);

        // printf("Failed to execute command: %i\n", status);
        exit(status);
    }

    // printf("Closing parent file descriptor...\n");
    close(fds[1]);

    // printf("Waiting child process...\n");
    int check_status;
    waitpid(pid, &check_status, 0);

    int8_t verifier_exit_code = WEXITSTATUS(check_status);

    if (WIFSIGNALED(check_status))
    {
        // printf("Verifier process ended abnormally, exit code: %i\n", verifier_exit_code);
        result.result = EBPF_VERIFIER_ABNOR_EXIT;
        result.message = "Verifier process ended abnormally";
        return &result;
    }

    // printf("Verifier process exited, exit code: %i\n", verifier_exit_code);

    if (verifier_exit_code != 0)
    {
        // printf("Verifier process exited with non-zero value, exiting... Exit code: %i\n", verifier_exit_code);
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
        // printf("Error reading verifier output, count is %i\n", (int)count);
        result.result = EBPF_VERIFIER_CALL_ERR;
        return &result;
    }
    else if (count == 0)
    {
        // printf("Verifier's STDOUT is empty...\n");
    }

    // printf("Verifier output: %s\n", &buffer[0]);
    result.message = &buffer[0];
    if (result.result == EBPF_VERIFIER_NON_ZERO_EXIT)
    {
        return &result;
    }

    close(fds[0]);

    char verifier_status = buffer[0];
    if (verifier_status == '1')
    {
        // printf("Succeeded, verifier status: %s\n", &verifier_status);
        result.result = EBPF_VERIFIER_PASS;
    }
    else
    {
        // printf("Verifier returned non-success code: %s\n", &verifier_status);
        result.result = EBPF_VERIFIER_INVALID;
    }

    return &result;
}