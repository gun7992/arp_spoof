#pragma once
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include <stdint.h>
#include "headers.h"


#define REQUEST     0x0001
#define REPLY       0x0002
#define RARP_REQ    0x0003
#define RARP_RES    0x0004


void get_my_mac(uint8_t* smac, char* iface)
{
     int fd;

     struct ifreq ifr;
     char *mac;

     fd = socket(AF_INET, SOCK_DGRAM, 0);

     ifr.ifr_addr.sa_family = AF_INET;
     strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

     ioctl(fd, SIOCGIFHWADDR, &ifr);

     close(fd);

     mac = (char *)ifr.ifr_hwaddr.sa_data;
     for(int i=0; i<6; i++) smac[i] = mac[i];
}

u_char* make_arp(int opcode, uint8_t* source_mac, uint8_t* destination_mac, uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* target_mac, uint8_t* target_ip)
{
     u_char* packet = (u_char*)malloc(128);
     struct ethernet_hdr eth;
     struct arp_hdr arp;
     int i = 0;
     memcpy(eth.ether_dmac, destination_mac,6);
     memcpy(eth.ether_smac, source_mac, 6);
     memcpy(arp.S_hardware_addr, sender_mac, 6);
     memcpy(arp.T_hardware_addr, target_mac, 6);

     for(i = 0; i < 4; i++)
     {
         arp.S_protocol_addr[i] = sender_ip[i];
         arp.T_protocol_addr[i] = target_ip[i];
     }
     arp.Opcode = htons(opcode);
     eth.ether_type = htons(0x0806);
     arp.hardware_type = htons(0x0001);
     arp.protocol_type = htons(0x0800);
     arp.H_add_len = 0x06;
     arp.P_add_len = 0x04;

     memcpy(packet, &eth, 14);
     memcpy(packet+14, &arp, 28);

     return packet;
}

