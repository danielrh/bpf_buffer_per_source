
#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stddef.h>
#include <linux/byteorder/little_endian.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define DO_DROP 0
#define DO_PASS 0xffffffff

char _license[] SEC("license") = "BSD";

struct bpf_map_def SEC("maps") counter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(long),
    .value_size = sizeof(long),
    .max_entries = 8,
};

#define MAX_PACKETS_PER_SOURCE 2
#define COUNTER_BITS 16

unsigned long cycle_mask(void) {
    unsigned long mask = 1;
    mask <<= (sizeof(mask)*8 - COUNTER_BITS);
    mask -= 1;
    return mask;
}
unsigned long counter_mask(void) {
    return (1 << COUNTER_BITS) - 1;
}

unsigned long extract_cycle_id(unsigned long per_source_data) {
    return ((per_source_data >> COUNTER_BITS) & cycle_mask());
}
unsigned long extract_packet_count(unsigned long per_source_data) {
    return counter_mask()&per_source_data;
}
unsigned long new_per_source_data(unsigned long num_pkt, unsigned long cycles) {
    return num_pkt | (cycles << COUNTER_BITS);
}
SEC("socket_filter")
int udpfilter(struct __sk_buff *skb)
{
    unsigned long key = load_half(skb, offsetof(struct udphdr, source));
    unsigned long zero = 0;
    // key 0 holds the processing cycle set by the consuming process
    unsigned long *cycle = bpf_map_lookup_elem(&counter_map, &zero);
    if (!cycle) {
        // receiver has not been setup:
        // wait for confirmation before allowing any packets
        return DO_DROP;
    }
    unsigned long masked_cycle = (*cycle) & cycle_mask();
    // per source data has the count of packets received + the recorded
    // cycle the packet count is attached to
    unsigned long *per_source_data = bpf_map_lookup_elem(&counter_map, &key);
    // if this is a new system or the current cycle != the recorded cycle
    if (!per_source_data || extract_cycle_id(*per_source_data) != masked_cycle)
    {
        // set a fresh packet count for a new cycle
        unsigned long fresh_count = new_per_source_data(1, masked_cycle);
        bpf_map_update_elem(&counter_map, &key, &fresh_count, 0);
    }
    else
    {
        // we have already received a packet this cycle
        // check if we have too many in the buffer already
        if (extract_packet_count(*per_source_data) >= MAX_PACKETS_PER_SOURCE)
        {
            return DO_DROP;
        }
        // we are free to consume the packet: increment packet count
        *per_source_data += 1;
    }
    return DO_PASS;
}
