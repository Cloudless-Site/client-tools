// Copyright 2026 Cloudless Site
// SPDX-License-Identifier: Apache-2.0

/*
 * KITE - Hyper-Converged UDP Bridge (Authenticated v2)
 * 
 * Implements "Ad-Hoc" Syntax:
 * 1. SSH Adapter Mode:  kite -L <TcpListen>:<UdpHost>:<UdpPort>
 * 2. Cloud Direct Mode: kite -r <CloudHost>:<CloudPort>:<Token> -l <UdpHost>:<UdpPort>
 * 
 * SECURITY: Uses HMAC-SHA256 Challenge-Response for authentication.
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
#include <ctype.h>

/* --- CRYPTO START (Embedded Zero-Dep HMAC-SHA256) --- */

#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = (rotr(m[i-2], 17) ^ rotr(m[i-2], 19) ^ (m[i-2] >> 10)) + m[i-7] + 
               (rotr(m[i-15], 7) ^ rotr(m[i-15], 18) ^ (m[i-15] >> 3)) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    for (i = 0; i < 64; ++i) {
        t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + m[i];
        t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t tk[32];
    size_t i;

    if (key_len > SHA256_BLOCK_SIZE) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, out);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, out, 32);
    sha256_final(&ctx, out);
}
/* --- CRYPTO END --- */


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
    char *first = strchr(copy, ':');
    char *last  = strrchr(copy, ':');
    if (!first) { free(copy); return; }
    if (first == last) {
        g_connect = strdup(copy); // host:port, token passed separately
    } else {
        *last = '\0';
        if (!g_token) g_token = strdup(last+1);
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
	else if(!strcmp(opt,"-T") || !strcmp(opt,"--token-file")) {
            FILE *f = fopen(val, "rb");
            if (!f) { fprintf(stderr, "token-file open failed: %s\n", val); exit(2); }
            char tbuf[128]; size_t n = fread(tbuf, 1, sizeof(tbuf)-1, f); fclose(f);
            tbuf[n] = 0;
            char *s=tbuf; while(*s && isspace((unsigned char)*s)) s++;
            char *e=s+strlen(s); while(e>s && isspace((unsigned char)e[-1])) *--e=0;
            if(*s==0){ fprintf(stderr, "token-file empty\n"); exit(2); }
            g_token = strdup(s);
        }
    }

    if (!g_target_udp_port || (!g_connect && !g_listen_tcp)) {
        printf("Kite - UDP Bridge (Ultimate)\n");
	printf("2. Cloud Direct (safe): kite -r <CloudHost>:<CloudPort> -T <token_file> -l <UdpHost>:<UdpPort>\n");
        printf("   (compat)            kite -r <CloudHost>:<CloudPort>:<Token> -l <UdpHost>:<UdpPort>\n");
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
        
        // --- PATCH START: Challenge-Response HMAC Handshake ---
        
        // 1. Leggi NONCE dal server (16 byte)
        uint8_t nonce[16];
        if (read_n(g_ctx.tcp_fd, nonce, sizeof(nonce)) < 0) {
            fprintf(stderr, "Kite Auth Error: Failed to read Challenge Nonce from server.\n");
            return 1;
        }

        // 2. Calcola HMAC(Token, Nonce)
        uint8_t hmac_result[32];
        if (!g_token) {
            fprintf(stderr, "Kite Auth Error: Token required for Direct Mode (-r/--token).\n");
            return 1;
        }
        hmac_sha256((uint8_t*)g_token, strlen(g_token), nonce, sizeof(nonce), hmac_result);

        // 3. Invia HMAC (32 byte)
        if (write_n(g_ctx.tcp_fd, hmac_result, 32) < 0) {
            fprintf(stderr, "Kite Auth Error: Failed to send Auth Response.\n");
            return 1;
        }

        printf("[KITE] Authenticated.\n");
        // --- PATCH END ---

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
