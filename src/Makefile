.SUFFIXES:
.SUFFIXES: .c .o
LIB = bpf_lib
SVC = bpf_svc
CFLAGS = -g -Wall

SVC_OBJ = bpf_svc_svc_proc.o bpf_svc_xdr.o bpf_svc_svc.o
LIB_OBJ = bpf_liv.o bpf_svc_xdr.o bpf_svc_lib.o

.c.o:; gcc -c -o $@ $(CFLAGS) $<

default: $(LIB) $(SVC)

$(LIB): $(LIB_OBJ)
	gcc -o $(LIB) $(LIB_OBJ)

$(SVC): $(SVC_OBJ)
	gcc -o $(SVC) $(SVC_OBJ)