#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <netdb.h>
#include <vector>
extern "C" {
#include <linux/bpf.h>
    #include <linux/filter.h>
//#include <bpf/libbpf.h>
}
#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# elif defined(__arc__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
                          unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}
int
bpf_prog_load(enum bpf_prog_type type,
              const struct bpf_insn *insns, int insn_cnt,
              const char *license) {
    const size_t LOG_BUF_SIZE = 16384;
    char bpf_log_buf[LOG_BUF_SIZE] = {0};

    union bpf_attr attr;
    attr.prog_type = type;
    attr.insns     = (uint64_t)(insns);
    attr.insn_cnt  = insn_cnt;
    attr.license   = (uint64_t)(license);
    attr.log_buf   = (uint64_t)(bpf_log_buf);
    attr.log_size  = LOG_BUF_SIZE;
    attr.log_level = 1;
    
    int ret = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (ret < 0) {
        fprintf(stderr, "%s\n", bpf_log_buf);
    }
    return ret;
}

int load_bpf_by_file(int sockfd, const char*filename) {
    FILE * fp = fopen(filename, "rb");
    if (!fp) {
        return -1;
    }
    std::vector<uint8_t> bpf_program;
    unsigned char tmp[1024];
    while(true) {
        size_t count = fread(tmp, 1, sizeof(tmp), fp);
        if (count ==0) {
            break;
        }
        bpf_program.insert(bpf_program.end(), (uint8_t*)tmp, (uint8_t*)tmp + count);
    }
    fclose(fp);
    int bpf_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, (const struct bpf_insn *)bpf_program.data(), bpf_program.size()/ sizeof(struct bpf_insn), "BSD");
    if (bpf_fd < 0) {
        return bpf_fd;
    }
    /*
    struct sock_filter *bpf_bytecode = (sock_filter*)bpf_program.data(); // bytecode generated by hand or using "tcpdump -dd"
    struct sock_fprog fprog = { (uint16_t)(bpf_program.size() / sizeof(bpf_insn)), bpf_bytecode};
    */
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_BPF, &bpf_fd, sizeof(bpf_fd))) {
		perror("setsockopt ATTACH_FILTER");
		return 1;
	}
    return 0;
}


int send_packets(int src_port, int dst_port, int count) {
    int sockfd;
    struct sockaddr_in srvaddr, cliaddr;
    uint8_t data[8] = {'0','b','a','d', 'f','0', '0','0'};
    memset(&cliaddr, 0, sizeof(cliaddr));
      
    // Filling client information
    cliaddr.sin_family    = AF_INET; // IPv4
    cliaddr.sin_addr.s_addr = INADDR_ANY;
    cliaddr.sin_port = htons(src_port);
    
    srvaddr.sin_family    = AF_INET; // IPv4
    srvaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srvaddr.sin_port = htons(dst_port);
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    if ( bind(sockfd, (const struct sockaddr *)&cliaddr, 
            sizeof(cliaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    for (int i = 0;i <count ; ++i) {
        data[7] = 'a' + i% 10;
        data[6] = '0' + (i/ 10)% 10;
        data[5] = '0' + (i/ 100)% 10;
        int ret = sendto(sockfd, data, sizeof(data),
                         0, (const struct sockaddr *) &srvaddr, 
                         sizeof(srvaddr));
        //fprintf(stderr, "%d->%d %d\n", src_port,  dst_port, ret);
        assert(ret == sizeof(data));
    }
    close(sockfd);
}

int main() {
    int sockfd;
    const size_t MAXLINE = 65537;
    char buffer[MAXLINE] = {0};
    struct sockaddr_in srvaddr, cliaddr;
      
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (load_bpf_by_file(sockfd, "all_allow.bpf") < 0) {
        perror("BPF FAILED");
    }

    memset(&srvaddr, 0, sizeof(srvaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
      
    // Filling server information
    srvaddr.sin_family    = AF_INET; // IPv4
    srvaddr.sin_addr.s_addr = INADDR_ANY;
    srvaddr.sin_port = 0;
      
    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&srvaddr, 
            sizeof(srvaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    socklen_t srvlen = sizeof(srvaddr);
    getsockname(sockfd, (sockaddr*)&srvaddr, &srvlen);
    uint16_t port = ntohs(srvaddr.sin_port);
    send_packets(9999, port, 16);
    send_packets(9998, port, 16);
    socklen_t len, n;

    for (int i = 0; i <  32; ++ i) {
        len = sizeof(cliaddr);  //len is value/resuslt
        n = recvfrom(sockfd, (char *)buffer, MAXLINE - 1, 
                     MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                     &len);
        buffer[n] = '\0';
        char addr_buffer[INET6_ADDRSTRLEN];
        if (getnameinfo((struct sockaddr*)&cliaddr,len,addr_buffer,sizeof(addr_buffer),
                        0,0,0) < 0) {
            perror("getname info error");
        }
        printf("[%s:%d]: %s\n",addr_buffer, ntohs(cliaddr.sin_port), buffer);
        fflush(stdout);
    }
    return 0;
}
