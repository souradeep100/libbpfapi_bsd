cmake_minimum_required(VERSION 3.10)

project(BPF_SVC)

set(CMAKE_CXX_STANDARD 20)

# ebpf-verifier includes
include_directories(external/ebpf-verifier/src)
include_directories(external/ebpf-verifier/src/external)

add_subdirectory("external")

# service
# src/service/verifier/freebsd/gpl/spec_prototypes.cpp src/service/verifier/freebsd/freebsd_platform.cpp
add_executable(bpf_svc src/service/common.cpp src/service/ebpf_verify_and_load_program.cpp src/service/ebpf_verify_program.cpp src/prototypes/bpf_svc_svc.c src/prototypes/bpf_svc_xdr.c)

target_link_libraries("bpf_svc" PRIVATE
  "external::ebpfverifier"
)
