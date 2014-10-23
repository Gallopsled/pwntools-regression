#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <link.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

#define STDIN   STDIN_FILENO
#define STDOUT  STDOUT_FILENO
#define STDERR  STDERR_FILENO

#define ARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))

int
main
(
);

char bss_data[0x1000] = {0};
char binsh[] = "/bin/sh";

//******************************************************************************
//                               SEGFAULT HANDLER
//******************************************************************************
void
handler
(
    int         sig,
    siginfo_t   *si,
    void        *unused
)
{
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}



__attribute__((constructor))
static void
register_handler
(
)
{
    struct sigaction sa;

    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;

    if (sigaction(SIGSEGV, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

//******************************************************************************
//                                   HELPERS
//******************************************************************************

//
// read_addr
//
// Reads a pointer over stdin
//
char*
read_ptr()
{
    char* ptr = 0;
    read(STDIN, &ptr, sizeof(ptr));
    return ptr;
}

//
// read_size
//
// Reads four bytes over stdin.
//
uint32_t
read_size()
{
    uint32_t size = 0;
    read(STDIN, &size, sizeof(size));
    return size;
}

//
// fill_buffer
//
// Reads four bytes over stdin.
// Interprets those as an unsigned integer of four bytes, N.
// Allocates N bytes, receives N bytes into the buffer.
//
// Caller must free the buffer.
//
// malloc() is not checked for NULL so we can simulate crashing
// behavior.
//
char*
fill_buffer()
{
    uint32_t size   = read_size();
    char    *buffer = malloc(size);
    read(STDIN, buffer, size);
    return buffer;
}


//******************************************************************************
//                                   COMMANDS
//******************************************************************************
void
do_ptrsize
(
)
{
    uint32_t size = sizeof(void*);
    write(STDOUT, &size, sizeof(size));
}

void
do_write
(
)
{

    char      * addr = read_ptr();
    uint32_t    size = read_size();

    read(STDIN, addr, size);
}



void
do_read
(
)
{
    char      * addr = read_ptr();
    uint32_t    size = read_size();

    write(STDOUT, addr, size);
}



void
do_overflow_stack
(
)
{
    char        buf[0x10];
    uint32_t    size = read_size();

    read(STDIN, buf, size);
}



void
do_overflow_string
(
)
{
    char buf[0x10];
    scanf("%s", buf);
}



void
do_allocate
(
)
{
    uint32_t    size = read_size();
    char        *buf = malloc(size);
    write(STDOUT, &buf, sizeof(buf));
}



void
do_release
(
)
{
    free(read_ptr());
}



void
do_format
(
)
{
    uint32_t    size = read_size();
    char        *buf = alloca(size);

    read(STDIN, buf, size);
    dprintf(STDOUT, buf);

}



void
do_leak_address
(
)
{
    void * _main = &main;
    write(STDOUT, &_main, sizeof(_main));
}



void
do_leak_libc
(
)
{
    struct link_map *lm = (struct link_map*) dlopen("libc.so.6", RTLD_LAZY);
    write(STDOUT, &lm->l_addr, sizeof(lm->l_addr));
}


void
do_shell
(
)
{
    system(fill_buffer());
}


void
do_exit
()
{
    write(STDOUT, "exit", 4);
    close(STDIN);
    close(STDOUT);
    close(STDERR);
    exit(0);
}



void
do_segfault
()
{
    char* deadbeef = (char*) 0xdeadbeef;
    *deadbeef = 0;
}

void
do_onebyte
()
{
    char c = 'X';
    write(STDOUT, &c, 1);
}

void do_call
()
{
    void (*ptr)() = (void*) read_ptr();
}

uint16_t g_port = 0;

void do_getport
()
{
    write(STDOUT, &g_port, sizeof(g_port));
}

void do_leak_baseaddress()
{
    uintptr_t start = (uintptr_t) &do_leak_baseaddress;
    start &= ~(0x1000 - 1);

    while(memcmp((char*)start+1, "ELF", 3))
        start -= 0x1000;

    write(STDOUT, &start, sizeof(start));
}

void do_get_linkmap()
{
    struct link_map *lm = (struct link_map*) dlopen("libc.so.6", RTLD_LAZY);
    write(STDOUT, &lm, sizeof(lm));
}


void do_get_libc_system()
{
    void *libc   = dlopen("libc.so.6", RTLD_LAZY);
    void *systm  = dlsym(libc, "__libc_system");
    write(STDOUT, &systm, sizeof(systm));
}


typedef void (*funcptr)();

funcptr functions[] = {
    do_ptrsize,         // 0
    do_write,           // 1
    do_read,            // 2
    do_overflow_stack,  // 3
    do_overflow_string, // 4
    do_allocate,        // 5
    do_release,         // 6
    do_format,          // 7
    do_leak_address,    // 8
    do_leak_libc,       // 9
    do_shell,           // 10
    do_segfault,        // 11
    do_exit,            // 12
    do_onebyte,         // 13
    do_call,            // 14
    do_getport,         // 15
    do_leak_baseaddress,// 16
    do_get_linkmap,     // 17
    do_get_libc_system  // 18
};

//******************************************************************************
//                                SERVER THREAD
//******************************************************************************
void *
sockserver(void* unused)
{
    struct sockaddr_in addr;
    int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sd < 0) {
        perror("socket");
        exit(1);
    }

    // set socket reuse option
    char tmp = 1;  // optval
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    // bind
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sd, (const struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    // find out what port we got
    socklen_t len = sizeof(addr);
    if(0 != getsockname(sd, &addr, &len)) {
        perror("getsockname");
        exit(1);
    }

    g_port = ntohs(addr.sin_port);

    // listen for new connections
    if (listen(sd, 16) == -1) {
        perror("listen");
        exit(1);
    }

    // accept connections, do nothing with them
    while(1) {
        char* message = "conn";
        int c = accept(sd, NULL, NULL);
        write(c, message, strlen(message));
    }
}

//******************************************************************************
//                                     MAIN
//******************************************************************************
int
main
(
)
{

    //
    // Listener thread
    //
    pthread_t thread;

    if(pthread_create(&thread, NULL, sockserver, NULL)) {
        perror("pthread_create");
        exit(1);
    }


    //
    // Set effective user/group id so that we can test setuid/setgid
    // shellcodes.
    //
    seteuid(getuid());
    setegid(getgid());

    while (1)
    {
        unsigned char c;
        read(STDIN, &c, 1);

        if(c < ARRAYSIZE(functions))
        {
            functions[c]();
        }
        else
        {
            exit(1);
        }
    }

    return 0;
}



