enum _ebpf_execution_type {
    EBPF_EXECUTION_ANY,
    EBPF_EXECUTION_JIT,
    EBPF_EXECUTION_INTERPRET,
    EBPF_EXECUTION_NATIVE
};

typedef enum _ebpf_execution_type ebpf_execution_type_t;

enum _ebpf_execution_context
{
	execution_context_user_mode,
	execution_context_kernel_mode
};

typedef enum _ebpf_execution_context ebpf_execution_context_t;

struct _ebpf_instruction {
    opaque opcode[1];
    opaque dst_src[1];
    short offset;
    int imm;
};

typedef struct _ebpf_instruction ebpf_instruction_t;

struct _original_fd_handle_map {
    unsigned int original_fd;
    unsigned int inner_map_original_fd;
    int file_handle;
};

typedef struct _original_fd_handle_map original_fd_handle_map_t;

struct _string_list
{
	string str<>;
};

typedef _string_list string_list;

struct __ebpf_context_descriptor {
    int size;
    int data;
    int end;
    int meta;
};

typedef __ebpf_context_descriptor ebpf_cxt_descriptor_t;

struct _ebpf_prog_type {
	string name<>;
    ebpf_cxt_descriptor_t context_descriptor;
    unsigned int platform_specific_data;
	opaque section_prefixes[100];
    bool is_privileged;
};

typedef _ebpf_prog_type ebpf_prog_type_t;

struct _ebpf_program_load_info {
    string object_name<>;
    string section_name<>;
    string program_name<>;
    ebpf_prog_type_t* program_type;
    ebpf_execution_type_t execution_type;
	ebpf_execution_context_t execution_context;
    int program_handle;
    unsigned int map_count;
    original_fd_handle_map_t *handle_map;
    ebpf_instruction_t instructions<>;
	ebpf_instruction_t *instruction;
};

typedef struct _ebpf_program_load_info ebpf_program_load_info;

struct ebpf_verify_and_load_arg {
    ebpf_program_load_info *info;
};

struct ebpf_verify_arg {
    string path<>;
};

enum _ebpf_result {
	EBPF_SUCCESS,
	EBPF_VERIFICATION_FAILED,
	EBPF_JIT_COMPILATION_FAILED,
	EBPF_PROGRAM_LOAD_FAILED,
	EBPF_INVALID_FD,
	EBPF_INVALID_OBJECT,
	EBPF_INVALID_ARGUMENT,
	EBPF_OBJECT_NOT_FOUND,
	EBPF_OBJECT_ALREADY_EXISTS,
	EBPF_FILE_NOT_FOUND,
	EBPF_ALREADY_PINNED,
	EBPF_NOT_PINNED,
	EBPF_NO_MEMORY,
	EBPF_PROGRAM_TOO_LARGE,
	EBPF_RPC_EXCEPTION,
	EBPF_ALREADY_INITIALIZED,
	EBPF_ELF_PARSING_FAILED,
	EBPF_FAILED,
	EBPF_OPERATION_NOT_SUPPORTED,
	EBPF_KEY_NOT_FOUND,
	EBPF_ACCESS_DENIED,
	EBPF_BLOCKED_BY_POLICY,
	EBPF_ARITHMETIC_OVERFLOW,
	EBPF_EXTENSION_FAILED_TO_LOAD,
	EBPF_INSUFFICIENT_BUFFER,
	EBPF_NO_MORE_KEYS,
	EBPF_KEY_ALREADY_EXISTS,
	EBPF_NO_MORE_TAIL_CALLS,
	EBPF_PENDING,
	EBPF_OUT_OF_SPACE,
	EBPF_CANCELED
};

typedef enum _ebpf_result ebpf_result_t;

enum edpf_verify_result_code
{
	EBPF_VERIFIER_NOT_PROCESSED,
	EBPF_VERIFIER_CALL_ERR,
	EBPF_VERIFIER_ABNOR_EXIT,
	EBPF_VERIFIER_NON_ZERO_EXIT,
	EBPF_VERIFIER_PASS,
	EBPF_VERIFIER_INVALID
};

struct edpf_verify_result
{
	ebpf_result_t result;
	string message<>;
};

program BPF_SVC {
    version BPF_SVC_V1 {
        edpf_verify_result EBPF_VERIFY_LOAD_PROGRAM(ebpf_verify_and_load_arg) = 1;
    } = 1;
} = 0x2ffffffa;