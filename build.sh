clang -O2 -emit-llvm -c all_allow.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o all_allow.o
objdump -h all_allow.o|grep .text | awk '{printf "if=all_allow.o of=/dev/stdout bs=1 count=%d skip=%d",strtonum("0x"$3), strtonum("0x"$6)}' |xargs dd > all_allow.bpf
g++ main.cpp -g
