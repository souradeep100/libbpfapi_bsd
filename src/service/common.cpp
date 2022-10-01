#include <memory>
#include <string>

#include "common.hpp"
#include "platform.hpp"
#include "../prototypes/bpf_svc.h"

#define INVALID_PROGRAM_HANDLE -1;

static thread_local bool _verification_in_progress = false;
static thread_local int _program_under_verification = INVALID_PROGRAM_HANDLE;

void set_program_under_verification(int program)
{
    _program_under_verification = program;
}

void set_verification_in_progress(bool value)
{
    _verification_in_progress = value;
}

void ebpf_clear_thread_local_storage()
{
    // TODO: uncheck other flags
    set_verification_in_progress(false);
}

void log_info(const char *fmt, ...)
{
    FILE *file = fopen("log.txt", "a");
    fprintf(file, fmt);
    fclose(file);
}