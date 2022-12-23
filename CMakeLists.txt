cmake_minimum_required(VERSION 3.10)

project(BPF_SVC)

set(CMAKE_CXX_STANDARD 17)

# ebpf-verifier includes
include_directories(/usr/local/include)
include_directories(external/ebpf-verifier/src)
include_directories(external/ebpf-verifier/src/external)

add_subdirectory("external")

# run rpcgen
set(RPC_AUTOGEN_DROP "${CMAKE_SOURCE_DIR}/src/prototypes")
set(proto_src "${RPC_AUTOGEN_DROP}/bpf_svc.x")
set(rpc_proto_hdr "${RPC_AUTOGEN_DROP}/bpf_svc.h")
set(rpc_client_stub_src "${RPC_AUTOGEN_DROP}/bpf_svc_clnt.c")
set(rpc_server_stub_src "${RPC_AUTOGEN_DROP}/bpf_svc_svc.c")
set(rpc_server_xdr_src "${RPC_AUTOGEN_DROP}/bpf_svc_xdr.c")

configure_file("src/prototypes/bpf_svc.x" "${proto_src}" COPYONLY)

# add_custom_target(auto_gen ALL 
#   COMMAND rpcgen "${proto_src}"
#   BYPRODUCTS "${rpc_proto_hdr}" "${rpc_client_stub_src}" "${rpc_server_stub_src}" "{rpc_server_xdr_src}")

# add_custom_command(
#     OUTPUT "${rpc_proto_hdr}" "${rpc_client_stub_src}" "${rpc_server_stub_src}" "{rpc_server_xdr_src}"
#     BYPRODUCTS "${rpc_proto_hdr}" "${rpc_client_stub_src}" "${rpc_server_stub_src}" "{rpc_server_xdr_src}"
#     DEPENDS "${proto_src}"
#     COMMAND rpcgen
#     ARGS "${proto_src}"
#     WORKING_DIRECTORY "${RPC_AUTOGEN_DROP}"
#     COMMENT "Generating rpc protocol header and stubs ..."
# )

# service
add_executable(
  bpf_svc

  src/service/common.cpp
  src/service/ebpf_verify_and_load_program.cpp
  src/service/verifier/verifier_service.cpp

  ${rpc_server_stub_src}
  ${rpc_server_xdr_src}
)

target_link_libraries("bpf_svc" PRIVATE
  "external::ebpfverifier"
)

add_library(
  bpf_lib

  src/lib/bpf_lib.cpp

  ${rpc_client_stub_src}
  ${rpc_server_xdr_src}
)

# samples
add_executable(
  verification_and_load_test

  src/samples/verification_and_load_test.cpp
)

target_link_libraries("verification_and_load_test" PRIVATE
  "bpf_lib"
)

target_link_libraries("verification_and_load_test" PRIVATE
  "external::ebpfverifier"
)
