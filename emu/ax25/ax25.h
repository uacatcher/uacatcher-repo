#include <termios.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdint.h>
#include <pty.h>
#include <linux/tty.h>
#include <net/if.h>
#include <linux/socket.h>
#include <netax25/ax25.h>
#include <linux/netlink.h>
#include <ctype.h>

#define SOL_AX25	257
#define SO_BINDTODEVICE	25
#define ULONG_MAX	(~0UL)
#define N_AX25		5
#define N_6PACK		7

struct user_opt{
    void *p;
    int size;
};
char buf[100]={'0'};
struct user_opt user;

struct pparam {
  int mfd;
  int sfd;
  int sock;
};

#ifndef HZ
#define HZ 100
#endif

struct sockaddr_ax25 my, their;
struct ax25_ctl_struct ax25_ctl;
struct ifreq ifr;//ifconfig 命令相关

pthread_t th1,th2,th3,th4;
pid_t pid;
struct pparam res = {0};
int random_del1;
int random_del2;
int random_del3;
int random_del4;

int getmaster(void);
int getslave(int fdm);
int setserial(int fd, int ldisc);
void ax25_initialize(int ldisc);

//tty相关操作
int getpt (void);
int grantpt (int filedes);
int unlockpt (int filedes);
char *ptsname (int filedes);
int toupper(int c);
