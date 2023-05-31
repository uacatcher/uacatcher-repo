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
#include <linux/socket.h>
#include <linux/tty.h>
#include <linux/can.h>
#include <net/if.h>

struct pparam {
  int mfd;
  int sfd;
  int sock;
};

int random_del1;
int random_del2;

pthread_t th1,th2;

struct pparam res = {0};
struct ifreq ifr;//ifconfig 命令相关

int getmaster(void);
int getslave(int fdm);
int setserial(int fd);
void can_initialize();
//tty相关操作
int getpt (void);
int grantpt (int filedes);
int unlockpt (int filedes);
char *ptsname (int filedes);
int toupper(int c);
