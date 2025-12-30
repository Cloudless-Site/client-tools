// Copyright 2026 Cloudless Site
// SPDX-License-Identifier: Apache-2.0

/*
 * KITE - Hyper-Converged UDP Bridge (Final Gold - Syntax Fix)
 * 
 * Implements "Ad-Hoc" Syntax:
 * 1. SSH Adapter Mode:  kite -L <TcpListen>:<UdpHost>:<UdpPort>
 * 2. Cloud Direct Mode: kite -r <CloudHost>:<CloudPort>:<Token> -l <UdpHost>:<UdpPort>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "pthreadVC2.lib") 
    #endif
    #define close closesocket
    #define shutdown shutdown
    #define SHUT_RDWR SD_BOTH
    typedef int socklen_t;
    #define FAST_ACK(fd)
    #define PIN_THREAD(id)
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #ifdef __linux__
        #include <sched.h> 
    #endif
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

// --- Constants ---
#define TCP_CHUNK_SIZE (256 * 1024) 
#define MAX_PAYLOAD_MTU 1472        
#define MAX_WIRE_SIZE   (64 * 1024) 
#define SOCK_BUF_SIZE (4 * 1024 * 1024) 
#define VLEN 64 

typedef struct {
    SOCKET tcp_fd; 
    SOCKET udp_fd;
    volatile int running;
    volatile int traffic_active; 
    struct sockaddr_storage target_addr; 
    socklen_t target_len;
} kite_ctx_t;

static kite_ctx_t g_ctx;

// Args
static char *g_connect = NULL; // Host:Port        
static char *g_token   = NULL; // Auth Token
static int   g_listen_tcp = 0;        
static int   g_target_udp_port = 0;   
static char *g_target_udp_host = NULL; 

// --- Helpers ---

#if defined(__linux__)
static void fast_ack(SOCKET fd) {
    int i = 1; setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &i, sizeof(int));
}
static void pin_thread(int core_id) {
    cpu_set_t c; CPU_ZERO(&c); CPU_SET(core_id, &c);
    pthread_setaffinity_np(pthread_self(), sizeof(c), &c);
}
#else
static void fast_ack(SOCKET fd) { (void)fd; }
static void pin_thread(int id) { (void)id; }
#endif

static void tune_socket(SOCKET fd, int is_tcp) {
    int b = SOCK_BUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&b, sizeof(b));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&b, sizeof(b));
    if (is_tcp) {
        int f = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&f, sizeof(f));
#ifdef __linux__
        int cnt = 3, idle = 10, intvl = 5;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &f, sizeof(f));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
    }
}

static void force_exit(const char *msg) {
    if (g_ctx.running) {
        g_ctx.running = 0;
        if(msg) fprintf(stderr, "[!] %s\n", msg);
        if(g_ctx.tcp_fd != INVALID_SOCKET) shutdown(g_ctx.tcp_fd, SHUT_RDWR);
        if(g_ctx.udp_fd != INVALID_SOCKET) shutdown(g_ctx.udp_fd, SHUT_RDWR);
    }
}
static void handle_sig(int s) { (void)s; force_exit("Terminating..."); }

static int read_n(SOCKET fd, void *buf, size_t n) {
    size_t t = 0; char *p = (char*)buf;
    while(t < n && g_ctx.running) {
        ssize_t r = recv(fd, p + t, (int)(n - t), 0);
        if (r <= 0) return -1;
        t += r;
    }
    return (t == n) ? 0 : -1;
}

static int write_n(SOCKET fd, const void *buf, size_t n) {
    size_t t = 0; const char *p = (const char*)buf;
    while(t < n && g_ctx.running) {
#ifdef _WIN32
        ssize_t w = send(fd, p + t, (int)(n - t), 0);
#else
        ssize_t w = send(fd, p + t, n - t, MSG_NOSIGNAL);
#endif
        if (w < 0) return -1;
        t += w;
    }
    return 0;
}

// --- THREAD 1: DOWNSTREAM (From Cloud) ---
void *thread_downstream(void *arg) {
    (void)arg; pin_thread(1); 
    char *buf = malloc(MAX_WIRE_SIZE);
    if (!buf) { force_exit("OOM"); return NULL; }

    while (g_ctx.running) {
        fast_ack(g_ctx.tcp_fd);
        uint32_t net_len = 0;
        if (read_n(g_ctx.tcp_fd, &net_len, 4) < 0) break;
        uint32_t len = ntohl(net_len);
        if (len > MAX_WIRE_SIZE) { force_exit("Protocol Violation"); break; }
        if (len == 0) continue; 

        if (read_n(g_ctx.tcp_fd, buf, len) < 0) break;

        if (g_ctx.traffic_active == 0) g_ctx.traffic_active = 1;
        sendto(g_ctx.udp_fd, buf, len, 0, (struct sockaddr*)&g_ctx.target_addr, g_ctx.target_len);
    }
    free(buf);
    if (g_ctx.running) force_exit("Tunnel Down");
    return NULL;
}

// --- THREAD 2: UPSTREAM (From Intranet) ---
void *thread_upstream(void *arg) {
    (void)arg; pin_thread(2); 

    char *tcp_batch = malloc(TCP_CHUNK_SIZE);
    if (!tcp_batch) { force_exit("OOM"); return NULL; }

#if defined(__linux__)
    struct mmsghdr msgs[VLEN];
    struct iovec iovecs[VLEN];
    uint8_t (*packet_bufs)[MAX_WIRE_SIZE] = calloc(VLEN, sizeof(*packet_bufs));
    
    if(!packet_bufs) { free(tcp_batch); force_exit("OOM"); return NULL; }

    for(int i=0; i<VLEN; i++) {
        iovecs[i].iov_base = packet_bufs[i];
        iovecs[i].iov_len  = MAX_WIRE_SIZE;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = NULL;
        msgs[i].msg_hdr.msg_namelen = 0;
    }

    uint64_t drop_mtu = 0;
    while(g_ctx.running) {
        struct timespec ts = {1, 0};
        int npkt = recvmmsg(g_ctx.udp_fd, msgs, VLEN, 0, &ts);
        
        if (npkt <= 0) continue; 
        if (g_ctx.traffic_active == 0) continue; 

        size_t batch_len = 0;
        for (int i=0; i<npkt; i++) {
            uint32_t len = msgs[i].msg_len;
            if (len > MAX_PAYLOAD_MTU) { drop_mtu++; continue; }
            if (len == 0) continue;

            if (batch_len + 4 + len > TCP_CHUNK_SIZE) {
                if(write_n(g_ctx.tcp_fd, tcp_batch, batch_len) < 0) goto end_loop;
                batch_len = 0;
            }
            uint32_t nl = htonl(len);
            memcpy(tcp_batch + batch_len, &nl, 4);
            memcpy(tcp_batch + batch_len + 4, packet_bufs[i], len);
            batch_len += (4 + len);
        }
        if (batch_len > 0) {
            if(write_n(g_ctx.tcp_fd, tcp_batch, batch_len) < 0) break;
        }
    }
end_loop:
    free(packet_bufs);

#else
    char *udp_pkt = malloc(MAX_WIRE_SIZE);
    while(g_ctx.running) {
        ssize_t n = recv(g_ctx.udp_fd, udp_pkt, MAX_WIRE_SIZE, 0);
        if (n <= 0) break;
        if (g_ctx.traffic_active == 0) continue; 
        if (n > MAX_PAYLOAD_MTU) continue;

        uint32_t nl = htonl((uint32_t)n);
        memcpy(tcp_batch, &nl, 4);
        memcpy(tcp_batch + 4, udp_pkt, n);
        if (write_n(g_ctx.tcp_fd, tcp_batch, n + 4) < 0) break;
    }
    free(udp_pkt);
#endif

    free(tcp_batch);
    if(g_ctx.running) force_exit("UDP Socket Error");
    return NULL;
}

// --- Utils ---
static int parse_port(const char *s) {
    long p = strtol(s, NULL, 10); return (p>0 && p<65536) ? (int)p : -1;
}

static char* extract_host_port(const char *s, int *out_port) {
    char *copy = strdup(s);
    char *colon = strrchr(copy, ':');
    if (colon) {
        *colon = '\0';
        *out_port = parse_port(colon+1);
        char *host = copy;
        if(host[0]=='[' && host[strlen(host)-1]==']') {
            host[strlen(host)-1]=0; host++;
        }
        return strdup(host);
    } 
    *out_port = parse_port(s);
    free(copy);
    return strdup("127.0.0.1"); // Default local
}

static void parse_ssh_adapter(const char *arg) {
    char *copy = strdup(arg);
    char *c1 = strchr(copy, ':');
    if(c1) {
        *c1 = '\0';
        g_listen_tcp = parse_port(copy);
        if (g_target_udp_host) free(g_target_udp_host);
        g_target_udp_host = extract_host_port(c1+1, &g_target_udp_port);
    } else {
        g_listen_tcp = parse_port(copy);
    }
    free(copy);
}

static void parse_target(const char *arg) {
    if (g_target_udp_host) free(g_target_udp_host);
    g_target_udp_host = extract_host_port(arg, &g_target_udp_port);
}

static void parse_remote_str(const char *arg) {
    char *copy = strdup(arg);
    char *last = strrchr(copy, ':'); 
    if(last) {
        *last = '\0';
        g_token = strdup(last+1);
        g_connect = strdup(copy);
    }
    free(copy);
}

static SOCKET tcp_conn_init(const char *hp) {
    char *d=strdup(hp),*h=d,*p=strrchr(d,':');
    if(p){*p=0;p++;} else {free(d);return INVALID_SOCKET;}
    struct addrinfo ah={0},*res,*rp; ah.ai_family=AF_UNSPEC; ah.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(h,p,&ah,&res)!=0){free(d);return INVALID_SOCKET;}
    SOCKET fd=INVALID_SOCKET;
    for(rp=res;rp;rp=rp->ai_next){fd=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol);if(fd==INVALID_SOCKET)continue;if(connect(fd,rp->ai_addr,rp->ai_addrlen)!=-1)break;close(fd);fd=INVALID_SOCKET;}
    freeaddrinfo(res); free(d);
    if(fd!=INVALID_SOCKET) tune_socket(fd,1);
    return fd;
}

static SOCKET tcp_listen_init(int port) {
    SOCKET s=socket(AF_INET6,SOCK_STREAM,0); int y=1,n=0;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&y,sizeof(y));
    setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(char*)&n,sizeof(n));
    struct sockaddr_in6 a={0}; a.sin6_family=AF_INET6; a.sin6_port=htons(port);
    if(bind(s,(struct sockaddr*)&a,sizeof(a))<0)return INVALID_SOCKET;
    listen(s,1);
    return s;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
#endif
    signal(SIGINT, handle_sig); signal(SIGTERM, handle_sig);

    for(int i=1; i<argc; i++) {
        if(i+1>=argc) break;
        const char *opt = argv[i]; const char *val = argv[++i];
        
        if(!strcmp(opt,"-L")) parse_ssh_adapter(val);
        else if(!strcmp(opt,"-r") || !strcmp(opt,"--connect")) parse_remote_str(val);
        else if(!strcmp(opt,"-l") || !strcmp(opt,"--local") || !strcmp(opt,"-p")) parse_target(val);
        else if(!strcmp(opt,"--token")) g_token = strdup(val);
    }

    if (!g_target_udp_port || (!g_connect && !g_listen_tcp)) {
        printf("Kite - UDP Bridge (Ultimate)\n");
        printf("1. SSH Adapter:  kite -L <TcpListen>:<UdpHost>:<UdpPort>\n");
        printf("2. Cloud Direct: kite -r <CloudHost>:<CloudPort>:<Token> -l <UdpHost>:<UdpPort>\n");
        return 1;
    }
    
    if (!g_target_udp_host) g_target_udp_host = strdup("127.0.0.1");
    g_ctx.running = 1;
    
    // Resolve Target (Immutable)
    struct addrinfo h={0}, *r; h.ai_family=AF_UNSPEC; h.ai_socktype=SOCK_DGRAM;
    char pstr[16]; sprintf(pstr, "%d", g_target_udp_port);
    if(getaddrinfo(g_target_udp_host, pstr, &h, &r)!=0) { fprintf(stderr, "DNS Error\n"); return 1; }
    if(r->ai_family==AF_INET){memcpy(&g_ctx.target_addr,r->ai_addr,sizeof(struct sockaddr_in));g_ctx.target_len=sizeof(struct sockaddr_in);}
    else{memcpy(&g_ctx.target_addr,r->ai_addr,sizeof(struct sockaddr_in6));g_ctx.target_len=sizeof(struct sockaddr_in6);}
    freeaddrinfo(r);

    g_ctx.udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    int no=0; setsockopt(g_ctx.udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
    tune_socket(g_ctx.udp_fd, 0);
    struct sockaddr_in6 la={0}; la.sin6_family=AF_INET6; 
    bind(g_ctx.udp_fd,(struct sockaddr*)&la,sizeof(la));

    if(g_connect) {
        printf("[KITE] Connecting %s...\n", g_connect);
        g_ctx.tcp_fd = tcp_conn_init(g_connect);
        if(g_ctx.tcp_fd == INVALID_SOCKET) { fprintf(stderr, "TCP Fail\n"); return 1; }
        
        char ab[32] = {0}; 
        size_t l = g_token ? strlen(g_token) : 0;
        if (l > 32) l = 32;
        if (l > 0) memcpy(ab, g_token, l);
        
        if (write_n(g_ctx.tcp_fd, ab, 32) < 0) return 1;
    } else {
        printf("[KITE] Listen TCP %d...\n", g_listen_tcp);
        SOCKET l=tcp_listen_init(g_listen_tcp);
        if(l==INVALID_SOCKET) return 1;
        g_ctx.tcp_fd = accept(l,NULL,NULL); close(l);
        if(g_ctx.tcp_fd==INVALID_SOCKET) return 1;
        tune_socket(g_ctx.tcp_fd, 1);
        printf("[KITE] Client Connected.\n");
    }

    printf("[KITE] Link UP -> UDP Target %s:%d\n", g_target_udp_host, g_target_udp_port);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_downstream, NULL);
    pthread_create(&t2, NULL, thread_upstream, NULL);
    pthread_join(t1, NULL); pthread_join(t2, NULL);

#ifdef _WIN32
    WSADATA x; WSAStartup(MAKEWORD(2,2),&x);
#endif
    return 0;
}
