
#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stddef.h>
#include <linux/byteorder/little_endian.h>
#include "prototype-kernel/kernel/samples/bpf/tools/include/linux/types.h"
#include "prototype-kernel/kernel/samples/bpf/bpf_helpers.h"
#define DO_DROP 0
#define DO_PASS 0xffffffff

#define inline_htons(input) (((input) >> 8)|(((input)&0xff)<<8))/*(__builtin_memcpy(scratch, &input, sizeof(unsigned short)), \
 input = scratch[0], \
 input <<= 8, \
 input |= scratch[ 1], \
 input)*/


           /* Some used BPF intrinsics. */
           unsigned long long load_byte(void *skb, unsigned long long off)
               asm ("llvm.bpf.load.byte");
           unsigned long long load_half(void *skb, unsigned long long off)
               asm ("llvm.bpf.load.half");

unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");


char _license[] SEC("license") = "GPL";
//u32 _version SEC("version") = LINUX_VERSION_CODE;

struct bpf_map_def SEC("maps") counter_map = {
    .type = BPF_MAP_TYPE_HASH,//BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(long),
    .value_size = sizeof(long),
    .max_entries = 8,
};

SEC("socket_filter")
int udpfilter(struct __sk_buff *skb)
{
    unsigned short src_port = load_half(skb, offsetof(struct udphdr, source));
    long key = src_port; // FIXME: add ip in there
    long zero = 0;
    long *cycle = bpf_map_lookup_elem(&counter_map, &zero);
    if (!cycle) {
        return DO_PASS;
    }
    long cycle_mask = 1;
    cycle_mask <<= (sizeof(cycle)*8 - 16);
    cycle_mask -= 1;
    long masked_cycle = (*cycle) & cycle_mask;
    long *counter = bpf_map_lookup_elem(&counter_map, &key);
    /*
    char fmta[] = "Cycle mask %lx\n";
    bpf_trace_printk(fmta, sizeof(fmta), masked_cycle);
    char fmtb[] = "Counter cycle %lx\n";
    bpf_trace_printk(fmtb, sizeof(fmtb), counter ?((*counter >> 16) & cycle_mask): 0xdeadbeef);
    char fmtc[] = "Counter counter %lx\n";
    bpf_trace_printk(fmtc, sizeof(fmtc), counter? (0xffff&*counter):0xdeadbeef);
    char fmtd[] = "Counter port %ld\n";
    bpf_trace_printk(fmtd, sizeof(fmtd), src_port);
    */
    if (!counter || ((*counter >> 16) & cycle_mask) != masked_cycle) {
        long one = 1 | (masked_cycle << 16);
        bpf_map_update_elem(&counter_map, &key, &one, 0);
    } else {
        if ((0xffff&*counter) > 2) {
            return DO_DROP;
        }
        *counter = (*counter + 1);
    }
    return DO_PASS;
  /*
  if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_UDP ||
      load_byte(skb, ETH_HLEN) != 0x45)
     return 0;
    
    unsigned char scratch[sizeof(unsigned short)];
    unsigned int size = ctx->data_end - ctx->data;
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/if_ether.h
    if (size < sizeof(struct ethhdr)) {
        return DO_PASS;
    }
    unsigned char *data = (void *)(long)ctx->data;
    struct ethhdr eth;
    __builtin_memcpy(&eth, data, sizeof(struct ethhdr));
    // Handle only IP packets (v4?)
    if (inline_htons(eth.h_proto) != ETH_P_IP){
        return DO_PASS;
    }
    return DO_DROP;
  */
    /*
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/ip.h
    struct iphdr *iph;
    iph = eth + 1;
    if (iph + 1 > data_end)
        return DO_DROP;
    // Minimum valid header length value is 5.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    if (iph->ihl < 5)
        return DO_DROP;
    // IP header size is variable because of options field.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    //if ((void *) iph + iph->ihl * 4 > data_end)
    //    return DO_DROP;
    // TODO support IP header with variable size
    if (iph->ihl != 5) 
        return DO_DROP;

    // We only handle UDP traffic
    if (iph->protocol != IPPROTO_UDP) {
        return DO_DROP;
    }
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    struct udphdr *udp;
    //udp = (void *) iph + iph->ihl * 4;
    udp = iph + 1;
    if (udp + 1 > data_end)
        return DO_DROP;
    
    return 0;
    */
}
