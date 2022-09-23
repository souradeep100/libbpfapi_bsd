echo "Creating build directories..."
mkdir -p .build
mkdir -p .build/service
mkdir -p .build/samples

echo "Generating stubs..."
cd prototypes
rpcgen bpf_svc.x

echo "Building service..."
cd ..
cc service/bpf_svc.c prototypes/bpf_svc_svc.c prototypes/bpf_svc_xdr.c -o .build/service/bpf_svc

echo "Building samples..."
cc samples/verification_and_load_test.c lib/bpf_lib.c prototypes/bpf_svc_clnt.c prototypes/bpf_svc_xdr.c -o .build/samples/verification_and_load_test
cc samples/verification_test.c lib/bpf_lib.c prototypes/bpf_svc_clnt.c prototypes/bpf_svc_xdr.c -o .build/samples/verification_test