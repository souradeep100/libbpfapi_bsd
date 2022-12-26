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

struct _string_item
{
	string str<>;
};

typedef _string_item string_item_t;

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
    unsigned long platform_specific_data;
	string_item_t section_prefixes<>;
    bool is_privileged;
};

typedef _ebpf_prog_type ebpf_prog_type_t;

struct _ebpf_map_descriptor {
    int original_fd;
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int inner_map_fd;
};

typedef _ebpf_map_descriptor ebpf_map_descriptor_t;

struct _ebpf_program_load_info {
    string object_name<>;
    string section_name<>;
    string program_name<>;
    ebpf_prog_type_t* program_type;
	ebpf_map_descriptor_t map_descriptors<>;
    ebpf_execution_type_t execution_type;
	ebpf_execution_context_t execution_context;
    int program_handle;
    unsigned int map_count;
    original_fd_handle_map_t *handle_map;
    ebpf_instruction_t instructions<>;
};

typedef struct _ebpf_program_load_info ebpf_program_load_info;

struct ebpf_verify_and_load_arg {
    ebpf_program_load_info *info;
};

struct ebpf_verify_arg {
    string path<>;
};

enum _ebpf_result {
	EBPF_SUCCESS = 0,
	EBPF_VERIFICATION_FAILED = 1,
	EBPF_JIT_COMPILATION_FAILED = 2,
	EBPF_PROGRAM_LOAD_FAILED = 3,
	EBPF_INVALID_FD = 4,
	EBPF_INVALID_OBJECT = 5,
	EBPF_INVALID_ARGUMENT = 6,
	EBPF_OBJECT_NOT_FOUND = 7,
	EBPF_OBJECT_ALREADY_EXISTS = 8,
	EBPF_FILE_NOT_FOUND = 9,
	EBPF_ALREADY_PINNED = 10,
	EBPF_NOT_PINNED = 11,
	EBPF_NO_MEMORY = 12,
	EBPF_PROGRAM_TOO_LARGE = 13,
	EBPF_RPC_EXCEPTION = 14,
	EBPF_ALREADY_INITIALIZED = 15,
	EBPF_ELF_PARSING_FAILED = 16,
	EBPF_FAILED = 17,
	EBPF_OPERATION_NOT_SUPPORTED = 18,
	EBPF_KEY_NOT_FOUND = 19,
	EBPF_ACCESS_DENIED = 20,
	EBPF_BLOCKED_BY_POLICY = 21,
	EBPF_ARITHMETIC_OVERFLOW = 22,
	EBPF_EXTENSION_FAILED_TO_LOAD = 23,
	EBPF_INSUFFICIENT_BUFFER = 24,
	EBPF_NO_MORE_KEYS = 25,
	EBPF_KEY_ALREADY_EXISTS = 26,
	EBPF_NO_MORE_TAIL_CALLS = 27,
	EBPF_PENDING = 29,
	EBPF_OUT_OF_SPACE = 30,
	EBPF_CANCELED = 31
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