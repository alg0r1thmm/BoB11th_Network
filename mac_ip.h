#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma once

int get_ip_addr(char *ip_str, const char *if_name);
int get_mac(char *mac_str, const char *if_name);