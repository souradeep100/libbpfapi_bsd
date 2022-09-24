echo "Building ebpf-verifier..."
cd ../external/ebpf-verifier
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

echo "Creating build directories..."
cd ../../
mkdir -p .build
mkdir -p .build/service
mkdir -p .build/samples

echo "Generating stubs..."
cd src/prototypes
rpcgen bpf_svc.x

echo "Building service..."
cd ../..
g++ -I external/ebpf-verifier/src -I external/ebpf-verifier/external -std=c++17 src/service/verifier/freebsd/gpl/spec_prototypes.cpp src/service/verifier/freebsd/freebsd_platform.cpp src/service/common.cpp src/service/ebpf_verify_and_load_program.cpp src/service/ebpf_verify_program.cpp src/prototypes/bpf_svc_svc.c src/prototypes/bpf_svc_xdr.c -o .build/service/bpf_svc

echo "Building samples..."
cc src/samples/verification_and_load_test.c src/lib/bpf_lib.c src/prototypes/bpf_svc_clnt.c src/prototypes/bpf_svc_xdr.c -o .build/samples/verification_and_load_test
cc src/samples/verification_test.c src/lib/bpf_lib.c src/prototypes/bpf_svc_clnt.c src/prototypes/bpf_svc_xdr.c -o .build/samples/verification_test