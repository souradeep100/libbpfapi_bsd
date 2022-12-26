find_package(yaml-cpp REQUIRED)

add_subdirectory("ebpf-verifier" EXCLUDE_FROM_ALL)

cmake_policy(SET CMP0079 NEW)

add_library("ebpf_for_windows_external_settings" INTERFACE)

target_link_libraries("ebpfverifier" PRIVATE
  "ebpf_for_windows_external_settings"
)

target_compile_definitions("ebpf_for_windows_external_settings" INTERFACE
  "_CRT_SECURE_NO_WARNINGS"
  "_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS"
)

target_include_directories("ebpfverifier" INTERFACE
  ebpf-verifier/src
  ebpf-verifier/external/elfio
)

# add_dependencies("ebpfverifier"
#   "yaml-cpp"
# )

add_library("external::ebpfverifier" ALIAS "ebpfverifier")

add_library("ebpfverifier_headers" INTERFACE)
target_include_directories("ebpfverifier_headers" INTERFACE
  ebpf-verifier/src
)

add_library("external::ebpfverifier_headers" ALIAS "ebpfverifier_headers")