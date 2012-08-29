/*
** main.c for kdevid in /home/phil/Travail/Development/Pam/libpam-devid/kdevid
**
** Made by Philippe THIERRY
** Login   <Philippe.THIERRY@thalesgroup.com>
**
** Started on  mar. 28 août 2012 17:30:45 CEST Philippe THIERRY
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/types.h>
#include <linux/netlink.h>

#include <string.h>

#include "main.h"

static void die(const char *s)
{
  write(2,s,strlen(s));
  exit(1);
}

int main(int argc __attribute__((unused)),
         char *argv[] __attribute__((unused)))
{
  struct sockaddr_nl nls;
  struct pollfd pfd;
  char buf[512];
  struct udev_env udevenv;

  memset(&udevenv, 0, sizeof(struct udev_env));

  // Open hotplug event netlink socket

  memset(&nls, 0, sizeof(struct sockaddr_nl));
  nls.nl_family = AF_NETLINK;
  nls.nl_pid = getpid();
  nls.nl_groups = -1;

  pfd.events = POLLIN;
  pfd.fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
  if (pfd.fd==-1)
    die("Not root\n");

  // Listen to netlink socket

  if (bind(pfd.fd, (void *)&nls, sizeof(struct sockaddr_nl)))
    die("Bind failed\n");
  while (-1!=poll(&pfd, 1, -1)) {
    int i, len = recv(pfd.fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (len == -1) die("recv\n");

    // Print the data to stdout.
    i = 0;
    while (i<len) {
      if (strncmp(buf+i, "ACTION=add", 10)) {
        udevenv.action = ACTION_ADD;
      }
      else if (!strncmp(buf+i, "ID_BUS=usb", 10)) {
        udevenv.idbus = IDBUS_USB;
      }
      else if (!strncmp(buf+i, "DEVTYPE=disk", 12)) {
        udevenv.devtype = DEVTYPE_DISK;
      }
      else if (!strncmp(buf+i, "DEVTYPE=usb_device", 18)) {
        udevenv.devtype = DEVTYPE_USBDEVICE;
      }
      else if (!strncmp(buf+i, "DEVPATH=", 8)) {
        udevenv.devpath = strdup(buf+i+8);
      }
      else if (!strncmp(buf+i, "ID_SERIAL_SHORT=", 16)) {
        udevenv.serial = strdup(buf+i+16);
      }
      /* printf("%s\n", buf+i); */
      i += strlen(buf+i)+1;
    }
    if (udevenv.action == ACTION_ADD &&
        udevenv.devtype > 0 &&
        udevenv.idbus > 0) {
      printf("add new usb device\n");
      printf("this device serial is %s\n", udevenv.serial);
      printf("this device dev path is /sys%s\n", udevenv.devpath);
    }
    if (udevenv.serial) {
      free(udevenv.serial);
    }
    if (udevenv.devpath) {
      free(udevenv.devpath);
    }
  }
  die("poll\n");

  // Dear gcc: shut up.
  return 0;
}
