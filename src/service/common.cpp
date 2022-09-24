#include "common.hpp"

#define INVALID_PROGRAM_HANDLE -1;

// TODO make all thread local
static bool _verification_in_progress = false;
static int _program_under_verification = INVALID_PROGRAM_HANDLE;

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

void log_info(const char* fmt, ...)
{
    // TODO: logging
}