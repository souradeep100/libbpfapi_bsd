#ifndef BPF_SVC_COMMON
#define BPF_SVC_COMMON

#include <stdbool.h>

void set_verification_in_progress(bool value);

void log_info(const char* fmt, ...);

void ebpf_clear_thread_local_storage();

void set_program_under_verification(int program);

#endif