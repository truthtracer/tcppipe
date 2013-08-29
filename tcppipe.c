/*
* Datapipe - Create a listen socket to pipe connections to another
* machine/port. 'localport' accepts connections on the machine running
* datapipe, which will connect to 'remoteport' on 'remotehost'.
* It will fork itself into the background on non-Windows machines.
*
* This implementation of the traditional "datapipe" does not depend on
* forking to handle multiple simultaneous clients, and instead is able
* to do all processing from within a single process, making it ideal
* for low-memory environments.  The elimination of the fork also
* allows it to be used in environments without fork, such as Win32.
*
* This implementation also differs from most others in that it allows
* the specific IP address of the interface to listen on to be specified.
* This is useful for machines that have multiple IP addresses.  The
* specified listening address will also be used for making the outgoing
* connections on.
*
* Note that select() is not used to perform writability testing on the
* outgoing sockets, so conceivably other connections might have delayed
* responses if any of the connected clients or the connection to the
* target machine is slow enough to allow its outgoing buffer to fill
* to capacity.
*
* Compile with:
*     cc -O -o datapipe datapipe.c
* On Solaris/SunOS, compile with:
*     gcc -Wall datapipe.c -lsocket -lnsl -o datapipe
* On Windows compile with:
*     bcc32 /w datapipe.c                (Borland C++)
*     cl /W3 datapipe.c wsock32.lib      (Microsoft Visual C++)
*
* Run as:
*   datapipe localhost localport remoteport remotehost
*
*
* written by Jeff Lawson <[email]jlawson@bovine.net[/email]>
* inspired by code originally by Todd Vierling, 1995.
*/

/*
============================================set rmem_max / wmem_max to 131071
Mar 22 09:42:03 tn001 TCPPIPE[8760]: tcppipe start to serve. listening on 192.168.3.157:2200 forward to 192.168.3.103:22
Mar 22 09:42:10 tn001 TCPPIPE[8760]: client peer connected from 192.168.3.156:54552 on local 192.168.3.157:2200
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 1(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 1(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 1(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 1(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 9(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 9(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 9(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 9(1) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 7(1048576) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 7(262142) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 8(1048576) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 8(262142) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 7(1048576) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 7(262142) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: setsockopt 8(1048576) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: getsockopt 8(262142) return 0 : Success
Mar 22 09:42:10 tn001 TCPPIPE[8760]: connected from local 192.168.3.157:53387 to remote 192.168.3.103:22
Mar 22 09:44:11 tn001 TCPPIPE[8760]: connection closed by remote 192.168.3.103:22
Mar 22 09:44:11 tn001 TCPPIPE[8760]: closed connection pair
Mar 22 09:46:23 tn001 TCPPIPE[8760]: SIGSIG : 15
Mar 22 09:46:23 tn001 TCPPIPE[8760]: select < 0 : Interrupted system call
Mar 22 09:46:23 tn001 TCPPIPE[8760]: tcppipe exiting...
============================================set rmem_max / wmem_max to 16777216
Mar 22 09:46:23 tn001 TCPPIPE[8773]: tcppipe start to serve. listening on 192.168.3.157:2200 forward to 192.168.3.103:22
Mar 22 09:46:34 tn001 TCPPIPE[8773]: client peer connected from 192.168.3.156:54576 on local 192.168.3.157:2200
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 1(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 1(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 1(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 1(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 9(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 9(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 9(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 9(1) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 7(1048576) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 7(2097152) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 8(1048576) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 8(2097152) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 7(1048576) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 7(2097152) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: setsockopt 8(1048576) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: getsockopt 8(2097152) return 0 : Success
Mar 22 09:46:34 tn001 TCPPIPE[8773]: connected from local 192.168.3.157:54322 to remote 192.168.3.103:22
Mar 22 09:48:34 tn001 TCPPIPE[8773]: connection closed by remote 192.168.3.103:22
Mar 22 09:48:34 tn001 TCPPIPE[8773]: closed connection pair
Mar 22 09:59:10 tn001 sshd[21239]: SSH: Server;Ltype: Kex;Remote: 192.168.3.156-42685;Enc: aes256-ctr;MAC: hmac-sha1;Comp: none
Mar 22 10:02:06 tn001 TCPPIPE[8773]: SIGSIG : 15
Mar 22 10:02:06 tn001 TCPPIPE[8773]: select < 0 : Interrupted system call
Mar 22 10:02:06 tn001 TCPPIPE[8773]: tcppipe exiting...
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#if defined(__WIN32__) || defined(WIN32) || defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock.h>
#define bzero(p, l) memset(p, 0, l)
#define bcopy(s, t, l) memmove(t, s, l)
#else
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>    /* for TCP_NODELAY definition */
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <netdb.h>
#include <strings.h>
#define recv(x,y,z,a) read(x,y,z)
#define send(x,y,z,a) write(x,y,z)
#define closesocket(s) close(s)
typedef int SOCKET;
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#include "logging.h"
setlogmask_fun logmask;
syslog_fun tlog;

volatile int flag_shutdown = 0;
void signal_2(int sig)
{
    tlog(LOG_NOTICE, "SIGSIG : %d", sig);
    flag_shutdown = 1;
}

struct client_t
{
    int inuse;
    SOCKET csock, osock;
    time_t lastactivity;
    time_t firstactivity;
    sockaddr sa_cli_peer;
    sockaddr sa_rmt_peer;
};

// ensure MAXTXSIZE in range of system rcv/send buffers (sysctl -a / edit sysctl.conf / sysctl -p ...)
// sysctl -w net.core.rmem_max=16777216 # net.core.rmem_max = 16777216
// sysctl -w net.core.wmem_max=16777216 # net.core.wmem_max = 16777216
#define BIGGERBUFSIZE       (1024*1024)
#define SMALLERBUFSIZE      (1024*1024)
#define MAXTXSIZE           (BIGGERBUFSIZE)
#define MAXCLIENTS          20
#define IDLETIMEOUT         300

const char ident[] = "$Id: datapipe.c,v 1.8 1999/01/29 01:21:54 jlawson Exp $";
char dev1[]="eth0"; // Interface of ISP1
char dev2[]="eth1"; // Interface of ISP2

char *getaddr(struct sockaddr *addr, char *ipstr, int ipstr_len, int &port)
{
    port = 0;
    memset(ipstr, 0, ipstr_len);

    // deal with both IPv4 and IPv6:
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &s->sin_addr, ipstr, ipstr_len);
        port = ntohs(s->sin_port);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, ipstr_len);
        port = ntohs(s->sin6_port);
    }

    return ipstr;
}

char *getaddr(SOCKET s, bool bpeer, struct sockaddr *addr, char *ipstr, int ipstr_len, int &port)
{
    socklen_t addr_size = sizeof(*addr);
    memset(addr, 0, addr_size);

    if(bpeer) {
        if (0 != getpeername(s, addr, &addr_size) ) tlog(LOG_ERR, "getpeername failed : %m");
    }
    else {
        if(0 != getsockname(s, addr, &addr_size) ) tlog(LOG_ERR, "getsockname failed : %m");
    }
    
    getaddr(addr, ipstr, ipstr_len, port);

    return ipstr;
}

void setsockoption(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    int result = -1;
    result = setsockopt(sockfd, level, optname, optval, optlen);
    tlog(LOG_INFO, "setsockopt %d(%d) return %d : %m", optname, *(int *)optval, result);

    int optval_get = -1;
    socklen_t optlen_get = optlen;
    result = getsockopt(sockfd, level, optname, (void *)&optval_get, &optlen_get);
    tlog(LOG_INFO, "getsockopt %d(%ld) return %d : %m", optname, optval_get, result);
}

void init()
{
    // ensure recv/send buffer size in range of system parameters
    int rmem_max = -1, wmem_max = -1;
    char szbuf[33] = { 0 };
    FILE *pf = fopen("/proc/sys/net/core/rmem_max", "r");
    if (pf && fgets(szbuf, 33, pf) > 0) { rmem_max = atoi(szbuf); fclose(pf); pf = 0; }
    pf = fopen("/proc/sys/net/core/wmem_max", "r");
    if (pf && fgets(szbuf, 33, pf) > 0) { wmem_max = atoi(szbuf); fclose(pf); pf = 0; }

    if (rmem_max != -1 && rmem_max < BIGGERBUFSIZE) system("echo '16777216' > /proc/sys/net/core/rmem_max");
    if (wmem_max != -1 && wmem_max < SMALLERBUFSIZE) system("echo '16777216' > /proc/sys/net/core/wmem_max");
}

int main(int argc, char *argv[])
{
    SOCKET lsock = -1;
    char buf[MAXTXSIZE] = { 0 };
    struct sockaddr_in laddr = { 0 }, oaddr = { 0 }, raddr = { 0 };
    int i = 0;
    int reuse = 1;
    int optone = 1;
    int biggerbufsize = BIGGERBUFSIZE;
    int smallerbufsize = SMALLERBUFSIZE;
    struct client_t clients[MAXCLIENTS] = { 0 };
    char ipstr[2][INET6_ADDRSTRLEN] = { {0} };
    int port[2] = { 0 };

#if defined(__WIN32__) || defined(WIN32) || defined(_WIN32)
    /* Winsock needs additional startup activities */
    WSADATA wsadata;
    WSAStartup(MAKEWORD(1,1), &wsadata);
#endif

    openlog("TCPPIPE", LOG_CONS | LOG_PID, 0);
    get_syslog_logger(&tlog, 0, &logmask);
    //logmask(LOG_UPTO(LOG_NOTICE));

    //signal(1, signal_log); signal(2,signal_2);
    signal(3, signal_2);
    signal(15, signal_2);
    signal(SIGPIPE, SIG_IGN);

    init();

    /* check number of command line arguments */
    if (argc < 5) {
        fprintf(stderr,"Usage: %s localip localport remoteip remoteport [outgoingip]\n",argv[0]);
        return 30;
    }

    /* init all of the client structures */
    for (i = 0; i < MAXCLIENTS; i++)
        memset(&clients[i], 0, sizeof(struct client_t));

    /* determine the listener address and port */
    bzero(&laddr, sizeof(struct sockaddr_in));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons((unsigned short) atol(argv[2]));
    laddr.sin_addr.s_addr = inet_addr(argv[1]);
    if (!laddr.sin_port) {
        fprintf(stderr, "invalid listener port\n");
        return 20;
    }
    if (laddr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *n;
        if ((n = gethostbyname(argv[1])) == NULL) {
            perror("gethostbyname");
            return 20;
        }
        bcopy(n->h_addr, (char *) &laddr.sin_addr, n->h_length);
    }

    /* determine the remote address and port */
    bzero(&raddr, sizeof(struct sockaddr_in));
    raddr.sin_family = AF_INET;
    raddr.sin_port = htons((unsigned short) atol(argv[4]));
    if (!raddr.sin_port) {
        fprintf(stderr, "invalid remote port\n");
        return 25;
    }
    raddr.sin_addr.s_addr = inet_addr(argv[3]);
    if (raddr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *n;
        if ((n = gethostbyname(argv[3])) == NULL) {
            perror("gethostbyname");
            return 25;
        }
        bcopy(n->h_addr, (char *) &raddr.sin_addr, n->h_length);
    }

    /* determine the outgoing address and port */
    if (argc > 5) {
        bzero(&oaddr, sizeof(struct sockaddr_in));
        oaddr.sin_family = AF_INET;
        /*oaddr.sin_port = htons((unsigned short) atol(argv[2]));
        if (!oaddr.sin_port) {
            fprintf(stderr, "invalid outgoing port\n");
            return 25;
        }*/
        oaddr.sin_addr.s_addr = inet_addr(argv[5]);
        if (oaddr.sin_addr.s_addr == INADDR_NONE) {
            struct hostent *n;
            if ((n = gethostbyname(argv[5])) == NULL) {
                perror("gethostbyname");
                return 25;
            }
            bcopy(n->h_addr, (char *) &oaddr.sin_addr, n->h_length);
        }
    }

    /* create the listener socket */
    if ((lsock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return 20;
    }
    if ( setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1){
        perror("setsockopt error");
        closesocket(lsock);
        return 20;
    }
    if (bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr))) {
        perror("bind");
        return 20;
    }
    if (listen(lsock, 5)) {
        perror("listen");
        return 20;
    }

    /* fork off into the background. */
#if !defined(__WIN32__) && !defined(WIN32) && !defined(_WIN32)
    if ((i = fork()) == -1) {
        perror("fork");
        return 20;
    }
    if (i > 0)
        return 0;
    setsid();
#endif

    getaddr((struct sockaddr *)&raddr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
    tlog(LOG_INFO, "tcppipe start to serve. listening on %s:%d forward to %s:%d", inet_ntoa(laddr.sin_addr), ntohs(laddr.sin_port), ipstr[0], port[0]);
    
    /* main polling loop. */
    while (0 == flag_shutdown) {
        fd_set fdsr;
        int maxsock;
        struct timeval tv = {1, 0};
        time_t now = time(NULL);
        int ret = -1;

        struct sockaddr cli_addr = { 0 };
        socklen_t cli_addr_size = sizeof(struct sockaddr);
 
        /* build the list of sockets to check. */
        FD_ZERO(&fdsr);
        FD_SET(lsock, &fdsr);
        maxsock = (int) lsock;
        for (i = 0; i < MAXCLIENTS; i++)
            if (clients[i].inuse) {
                FD_SET(clients[i].csock, &fdsr);
                if ((int) clients[i].csock > maxsock)
                    maxsock = (int) clients[i].csock;
                FD_SET(clients[i].osock, &fdsr);
                if ((int) clients[i].osock > maxsock)
                    maxsock = (int) clients[i].osock;
            }
            if (select(maxsock + 1, &fdsr, NULL, NULL, &tv) < 0) {
                tlog(LOG_ERR, "select < 0 : %m");
                goto end;
            }

            /* check if there are new connections to accept. */
            if (FD_ISSET(lsock, &fdsr))
            {
               SOCKET csock = accept(lsock, &cli_addr, &cli_addr_size);

                getaddr(&cli_addr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
                getaddr(csock, false, &cli_addr, ipstr[1], INET6_ADDRSTRLEN, port[1]);
                tlog(LOG_INFO, "client peer connected from %s:%d on local %s:%d", ipstr[0], port[0], ipstr[1], port[1]);

                for (i = 0; i < MAXCLIENTS; i++)
                    if (!clients[i].inuse) break;
                if (i < MAXCLIENTS)
                {
                    /* connect a socket to the outgoing host/port */
#ifdef RAW
                    struct ifreq ifr = { 0 };
                    memset(&ifr, 0, sizeof (ifr));
                    strncpy(ifr.ifr_name, dev1, sizeof (ifr.ifr_name) -1); //WangTong Interface
                    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
#endif
                    SOCKET osock = -1;
#ifdef RAW
                    if ((osock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ) == -1) {
#else
                    if ((osock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
#endif
                        closesocket(csock);
                        tlog(LOG_ERR, "socket error : %m");
                    }
#ifdef RAW
                    else if (ioctl(osock, SIOCGIFHWADDR, &ifr) < 0 ) {
                        closesocket(csock);
                        tlog(LOG_ERR, "ioctl error : %m");
                    }
#endif
                    else if ( setsockopt(osock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
                        closesocket(csock);
                        closesocket(osock);
                        tlog(LOG_ERR, "setsockopt error : %m");
                    }

                    //Try to bind outgoing IP
                    if (0 != memcmp(&laddr, &oaddr, sizeof laddr) && bind(osock, (struct sockaddr *)&oaddr, sizeof(oaddr)) == -1) {
                        //closesocket(csock);
                        //closesocket(osock);
                        tlog(LOG_NOTICE, "bind outgoing addr %s:%d failed, data will be transfered via localip : %m", inet_ntoa(oaddr.sin_addr), ntohs(oaddr.sin_port));
                    }

                    if (connect(osock, (struct sockaddr *)&raddr, sizeof(raddr))) {
                        closesocket(csock);
                        closesocket(osock);
                        tlog(LOG_ERR, "failed to connect %s:%d : %m", inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));
                    }
                    else {
                        // setsockopt failure is acceptable
                        setsockoption(osock, IPPROTO_TCP, TCP_NODELAY, (const void *)&optone, (socklen_t)sizeof(optone));
                        setsockoption(csock, IPPROTO_TCP, TCP_NODELAY, (const void *)&optone, (socklen_t)sizeof(optone));
                        setsockoption(osock, SOL_SOCKET, SO_KEEPALIVE, (const void *)&optone, (socklen_t)sizeof(optone));
                        setsockoption(csock, SOL_SOCKET, SO_KEEPALIVE, (const void *)&optone, (socklen_t)sizeof(optone));
                        setsockoption(osock, SOL_SOCKET, SO_SNDBUF, (const void *)&smallerbufsize, (socklen_t)sizeof(smallerbufsize));
                        setsockoption(osock, SOL_SOCKET, SO_RCVBUF, (const void *)&biggerbufsize, (socklen_t)sizeof(smallerbufsize));
                        setsockoption(csock, SOL_SOCKET, SO_SNDBUF, (const void *)&smallerbufsize, (socklen_t)sizeof(biggerbufsize));
                        setsockoption(csock, SOL_SOCKET, SO_RCVBUF, (const void *)&biggerbufsize, (socklen_t)sizeof(biggerbufsize));

                        memcpy(&clients[i].sa_cli_peer, &cli_addr, sizeof(struct sockaddr));
                        memcpy(&clients[i].sa_rmt_peer, &raddr, sizeof(struct sockaddr));
                        clients[i].osock = osock;
                        clients[i].csock = csock;
                        clients[i].firstactivity = now;
                        clients[i].lastactivity = now;
                        clients[i].inuse = 1;

                        getaddr(osock, false, &cli_addr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
                        tlog(LOG_INFO, "connected from local %s:%d to remote %s:%d", ipstr[0], port[0], inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));
                    }
                } else {
                    closesocket(csock);
                    tlog(LOG_ERR, "too many clients, closed client peer");
                }
            }

            /* service any client connections that have waiting data. */
            for (i = 0; i < MAXCLIENTS; i++)
            {
                int nbyt, closeneeded = 0;
                if (!clients[i].inuse) {
                    continue;
                } else if (FD_ISSET(clients[i].csock, &fdsr)) {
                    nbyt = recv(clients[i].csock, buf, sizeof(buf), 0);
                    getaddr(clients[i].csock, true, &cli_addr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
                    if (nbyt < 0)
                    {
                        closeneeded = 1;
                        tlog(LOG_ERR, "recv error from client %s:%d : %m", ipstr[0], port[0]);
                    }else if(nbyt == 0)
                    {
                        closeneeded = 1;
                        tlog(LOG_NOTICE, "connection closed by client %s:%d", ipstr[0], port[0]);
                    }else if(nbyt > 0)
                    {
                        ret = send(clients[i].osock, buf, nbyt, 0);
                        getaddr(clients[i].osock, true, &cli_addr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
                        if(ret < 0)
                        {
                            closeneeded = 1;
                            tlog(LOG_ERR, "send error to remote %s:%d: %m", ipstr[0], port[0]);
                        }else if(ret == 0)
                        {
                            closeneeded = 1;
                            tlog(LOG_NOTICE, "connection closed by remote %s:%d", ipstr[0], port[0]);
                        }else if(ret > 0) clients[i].lastactivity = now;
                    }
                } else if (FD_ISSET(clients[i].osock, &fdsr)) {
                    nbyt = recv(clients[i].osock, buf, sizeof(buf), 0);
                    getaddr(clients[i].osock, true, &cli_addr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
                    if (nbyt < 0)
                    {
                        closeneeded = 1;
                        tlog(LOG_ERR, "recv error from remote %s:%d : %m", ipstr[0], port[0]);
                    }else if(nbyt == 0)
                    {
                        closeneeded = 1;
                        tlog(LOG_NOTICE, "connection closed by remote %s:%d", ipstr[0], port[0]);
                    }else if(nbyt > 0)
                    {
                        ret = send(clients[i].csock, buf, nbyt, 0);
                        getaddr(clients[i].csock, true, &cli_addr, ipstr[0], INET6_ADDRSTRLEN, port[0]);
                        if(ret < 0)
                        {
                            closeneeded = 1;
                            tlog(LOG_ERR, "send error to client %s:%d: %m", ipstr[0], port[0]);
                        }else if(ret == 0)
                        {
                            closeneeded = 1;
                            tlog(LOG_NOTICE, "connection closed by client %s:%d", ipstr[0], port[0]);
                        }else if(ret > 0) clients[i].lastactivity = now;
                    }
                } else if (now - clients[i].lastactivity > IDLETIMEOUT) {
                    closeneeded = 1;
                    tlog(LOG_ERR, "client activity idle timeout");
                }
                if (closeneeded) {
                    closesocket(clients[i].csock);
                    closesocket(clients[i].osock);
                    clients[i].inuse = 0;
                    tlog(LOG_NOTICE, "closed connection pair");
                }
            }
    }

end:
    // close all connections
    for (i = 0; i < MAXCLIENTS; i++)
    {
        if (clients[i].inuse) {
            closesocket(clients[i].csock);
            closesocket(clients[i].osock);
            clients[i].inuse = 0;
        }
    }
    
    tlog(LOG_NOTICE, "tcppipe exiting...");
    
    closelog();
    
    return 0;
}
