# SPDX-License-Identifier: GPL-2.0
# List of programs to build
hostprogs-y := multisocket

# Libbpf dependencies
LIBBPF := ../../../tools/lib/bpf/bpf.o
CGROUP_HELPERS := ../../../tools/testing/selftests/bpf/cgroup_helpers.o

multisocket := multisocket.o $(LIBBPF) bpf_load.o 

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS += -I$(objtree)/usr/include
HOSTCFLAGS += -I$(srctree)/tools/lib/
HOSTCFLAGS += -I$(srctree)/tools/testing/selftests/bpf/
HOSTCFLAGS += -I$(srctree)/tools/lib/ -I$(srctree)/tools/include
HOSTCFLAGS += -I$(srctree)/tools/perf
HOSTCFLAGS += -DHAVE_ATTR_TEST=0

HOSTCFLAGS_bpf_load.o += -I$(objtree)/usr/include -Wno-unused-variable
HOSTLOADLIBES_multisocket +=  -g $(srctree)/samples/bpf/bpf_load.c $(srctree)/tools/lib/bpf/bpf.c $(HOSTCFLAGS) -lelf
HOSTLOADLIBES_syscall_tp += -lelf

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

# Detect that we're cross compiling and use the cross compiler
ifdef CROSS_COMPILE
HOSTCC = $(CROSS_COMPILE)gcc
CLANG_ARCH_ARGS = -target $(ARCH)
endif

# Trick to allow make to be run from this directory
all: $(LIBBPF)
	$(MAKE) -C ../../../ $(CURDIR)/

clean:
	$(MAKE) -C ../../../ M=$(CURDIR) clean
	rm multisocket
	@find $(CURDIR) -type f -name '*~' -delete

$(LIBBPF): FORCE
	$(MAKE) -C $(dir $@) $(notdir $@)

$(obj)/syscall_nrs.s:	$(src)/syscall_nrs.c
	$(call if_changed_dep,cc_s_c)

$(obj)/syscall_nrs.h:	$(obj)/syscall_nrs.s FORCE
	$(call filechk,offsets,__SYSCALL_NRS_H__)

clean-files += syscall_nrs.h

FORCE:


# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: $(CLANG) $(LLC)

#$(src)/*.c: multisocket
#$(src)/*.cc: multisocket

# $(obj)/tracex5_kern.o: $(obj)/syscall_nrs.h

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
$(obj)/%.o: $(src)/%.c 
	$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) -I$(obj) \
		-I$(srctree)/tools/testing/selftests/bpf/ \
		-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
