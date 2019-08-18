#pragma once
#include <stdint.h>
#define ETHER_MAC_SIZE		0x06
#define ETHER_HDR_SIZE		0x0e
#define ETHER_PROTO_SIZE	0X04

struct session
{
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

struct ethernet_hdr
{
    uint8_t ether_dmac[ETHER_MAC_SIZE];
    uint8_t ether_smac[ETHER_MAC_SIZE];
    uint16_t ether_type;
};

struct arp_hdr
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t H_add_len;
    uint8_t P_add_len;
    uint16_t Opcode;
    uint8_t S_hardware_addr[ETHER_MAC_SIZE];
    uint8_t S_protocol_addr[4];
    uint8_t T_hardware_addr[ETHER_MAC_SIZE];
    uint8_t T_protocol_addr[4];
};

struct ip_hdr
{
    uint8_t version_length;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identifier;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t S_ip[4];
    uint8_t D_ip[4];
};
