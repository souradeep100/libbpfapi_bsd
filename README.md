# libbpfapi_bsd

## Pre-reqs

- rpcgen
- rpcbind running (install if needed, and run the command 'rpcbind' to start it)
- ebpf-verifier cloned and compiled (https://github.com/vbpf/ebpf-verifier)

## Build

Run 'src/build.sh'

## Running the service

Run 'sudo env PREVAIL_PATH={prevail check executable} .build/service/bpf_svc'
- 'check' executable should be found under ebpf-verifier root folder after compilation

## Running the sample client

For verification only: run '.build/samples/verification_test {bpf compiled file}'
- ebpf-verifier repo has many sample files under 'ebpf-samples/'
- ebpf-samples/invalid contains some invalid files for testing