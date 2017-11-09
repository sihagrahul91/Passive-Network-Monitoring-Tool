#include "myStruct.h"
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char * bytes);
extern int packet_count;

void printPayload(u_char *packet, int len) {

	if(len<=0) return;

	u_char buffer[16];
	memset(buffer,0,16);
	int i=0,count=0;
	for(i=0,count=0;i<len;) {
		printf("%02x ",(buffer[count++]=packet[i++]));
		if(count==16 || i==len) {
			if(count<16) {
				int t;
				for(t=count;t<16;t++) {
					printf("   ");
				}
			}
			printf("   ");
			int j;
			for(j=0;j<count;j++) {
				if (isprint(buffer[j]))
					printf("%c", buffer[j]);
				else
					printf(".");

			}
			count = 0;
			memset(buffer,0,16);	
			printf("\n");
		}
	}
}

void printeth(const u_char * bytes, size_t length) {
	struct ether_header *arp_hdr = (struct ether_header *)bytes;
	int i=0;
	u_char *addr_ptr;
	addr_ptr = arp_hdr->ether_shost;
	printf(" ");
	while(i<ETHER_ADDR_LEN) {
		if(i<ETHER_ADDR_LEN-1)
			printf("%02x:",*addr_ptr++);
		else
			printf("%02x",*addr_ptr++);
		i++;
	}
	printf(" -> ");
	i=0;
	addr_ptr = arp_hdr->ether_dhost;
	while(i<ETHER_ADDR_LEN) {
		if(i<ETHER_ADDR_LEN-1)
			printf("%02x:",*addr_ptr++);
		else
			printf("%02x",*addr_ptr++);
		i++;
	}
	if(ntohs(arp_hdr->ether_type) == ETHERTYPE_IP) {
		printf(" type 0x%04x", ETHERTYPE_IP);
	} else if (ntohs(arp_hdr->ether_type) == ETHERTYPE_ARP) {
		printf(" type 0x%04x", ETHERTYPE_ARP);
	} else {
		printf(" type 0x%04x", ntohs(arp_hdr->ether_type));
	}
	printf(" len %u\n", (u_int) length);
}
/* Print ICMP Payload. Printing all including ICMP header */
void printicmp(u_char *packet,int size_ip,const struct pcap_pkthdr *h) {
	struct icmp *icmp_ = (struct icmp *)(packet + SIZE_ETHERNET + size_ip);
	struct sniff_ip	*ip_hdr = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	printf("%d.%d.%d.%d -> %d.%d.%d.%d", ip_hdr->ip_src.byte1, ip_hdr->ip_src.byte2, ip_hdr->ip_src.byte3, ip_hdr->ip_src.byte4,
					     ip_hdr->ip_dst.byte1, ip_hdr->ip_dst.byte2, ip_hdr->ip_dst.byte3, ip_hdr->ip_dst.byte4);
	printf(" ICMP");
	printf(" ICMP type: %d ", icmp_->icmp_type);
	printf(" ICMP code: %d ", icmp_->icmp_code);
	printf(" ICMP length = %u ", h->len - (SIZE_ETHERNET + size_ip + SIZE_ICMP));
	printf("\n");
	printPayload(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP, h->len - (SIZE_ETHERNET + size_ip + SIZE_ICMP));
}

void printudp(u_char *packet,int size_ip,const struct pcap_pkthdr *h) {
	/* size of UDP Header is sizeof(struct udphdr) = 8 bytes. */
	struct udphdr *udp_hdr= (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);
	struct sniff_ip	*ip_hdr = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d", ip_hdr->ip_src.byte1, ip_hdr->ip_src.byte2, ip_hdr->ip_src.byte3, ip_hdr->ip_src.byte4, ntohs(udp_hdr->source),
						   ip_hdr->ip_dst.byte1, ip_hdr->ip_dst.byte2, ip_hdr->ip_dst.byte3, ip_hdr->ip_dst.byte4, ntohs(udp_hdr->dest));
	printf(" UDP");
	printf(" UDP length = %lu", h->len - (SIZE_ETHERNET + size_ip + sizeof(struct udphdr)));
	printf("\n");
	printPayload(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr), h->len - (SIZE_ETHERNET + size_ip + sizeof(struct udphdr)));

}

void printtcp(u_char *packet,int size_ip,const struct pcap_pkthdr *h) {
	struct sniff_tcp *tcp_hdr;
	struct sniff_ip	*ip_hdr = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	u_int size_tcp;
	tcp_hdr = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d", ip_hdr->ip_src.byte1, ip_hdr->ip_src.byte2, ip_hdr->ip_src.byte3, ip_hdr->ip_src.byte4, ntohs(tcp_hdr->th_sport),
						   ip_hdr->ip_dst.byte1, ip_hdr->ip_dst.byte2, ip_hdr->ip_dst.byte3, ip_hdr->ip_dst.byte4, ntohs(tcp_hdr->th_dport));
	size_tcp = TH_OFF(tcp_hdr)*4;
	printf(" TCP");
	printf(" TCP length = %u", h->len - (SIZE_ETHERNET + size_ip + size_tcp));
	printf("\n");
	printPayload(packet + SIZE_ETHERNET + size_ip + size_tcp, h->len - (SIZE_ETHERNET + size_ip + size_tcp));
}

void parse(char *input, char *payload_filter, char *bpf_filter, bool intf) {

	char *s[] = {"pcap file","interface"};
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpf;
	pcap_t *handle = NULL;
	bpf_u_int32 mask = 0;   /* The netmask of our sniffing device */
	bpf_u_int32 net = 0;    /* The IP of our sniffing device */

	if(intf) {	
		if(pcap_lookupnet(input, &net, &mask, errbuf) == -1) {
			printf("Failed to get netmask of device: %s\n",errbuf);
			return;
		}
		/* pcap_open_live takes device, snaplen, promisc, to_ms(read timeout in ms), error buffer as arguments */
		handle = pcap_open_live(input, BUFSIZ, 1, 1000, errbuf);
	}
	else
		handle = pcap_open_offline(input,errbuf);

	if(!handle) {
		printf("Failed to open %s: %s\n",s[intf],errbuf);
		return;
	}

	/* Compile the filter and apply it */
	if(bpf_filter) {
		if(pcap_compile(handle, &bpf, bpf_filter, 0, net) == -1) {
			printf("Failed to compile filter %s: %s\n", bpf_filter, pcap_geterr(handle));
			return;
		}

		if(pcap_setfilter(handle, &bpf) == -1) {
			printf("Failed to apply filter %s: %s\n", bpf_filter, pcap_geterr(handle));
			return;
		}

	}
	pcap_loop(handle, -1, callback, (u_char *) payload_filter);   /* using cnt as -1 to work with older versions of libpcap */

}

bool search_payload(const u_char *bytes, size_t len, const u_char *user) {  //TODO
	int i,hlen = SIZE_ETHERNET;
	const struct ether_header *arp_hdr = (struct ether_header *)bytes;
	if (ntohs(arp_hdr->ether_type) != ETHERTYPE_ARP) {
		const struct sniff_ip *ip = (struct sniff_ip *)(bytes + SIZE_ETHERNET);
		const struct sniff_tcp *tcp_hdr;
		int size_ip = IP_HL(ip)*4;
		hlen += size_ip;    //add IP header length.
		switch (ip->ip_p) {
			case TYPE_ICMP:
				hlen += SIZE_ICMP;
				break;
			case TYPE_TCP:
				tcp_hdr = (struct sniff_tcp *)(bytes + SIZE_ETHERNET + size_ip);
				hlen += TH_OFF(tcp_hdr)*4;
				break;
			case TYPE_UDP:
				hlen += sizeof(struct udphdr);
				break;
			default:
				break;
		}
	}
	u_char payload[len-hlen+1];
	memcpy(payload, bytes+hlen, len-hlen);
	payload[len-hlen]='\0'; //NULL terminate the payload buffer
	for(i=0; i<len-hlen; i++) {
		if(user && user[0]==payload[i]) {
			if(memcmp(user,payload+i,strlen((const char *)user))==0) return 1;
		}
	}
	return 0;
}

void printarp(const u_char *bytes,int length) {
	struct arphdr *arp_hdr = (struct arphdr *)(bytes+SIZE_ETHERNET);
	if (ntohs(arp_hdr->ar_op) == 1) {
		printf("ARP, Request who-has %d.%d.%d.%d tell %d.%d.%d.%d, length %d\n", 
				arp_hdr->__ar_tip[0], arp_hdr->__ar_tip[1], arp_hdr->__ar_tip[2], arp_hdr->__ar_tip[3],
				arp_hdr->__ar_sip[0], arp_hdr->__ar_sip[1], arp_hdr->__ar_sip[2], arp_hdr->__ar_sip[3], length);
	} else if (ntohs(arp_hdr->ar_op) == 2) {
		printf("ARP, Reply %d.%d.%d.%d is-at ", arp_hdr->__ar_sip[0], arp_hdr->__ar_sip[1],
						        arp_hdr->__ar_sip[2], arp_hdr->__ar_sip[3]);
		struct ether_header *arp_hdr = (struct ether_header *)bytes;
		int i=0;
		u_char *addr_ptr = arp_hdr->ether_shost;
		while(i<ETHER_ADDR_LEN) {
			if(i<ETHER_ADDR_LEN-1)
				printf("%02x:",*addr_ptr++);
			else
				printf("%02x",*addr_ptr++);
			i++;
		}
		printf(" (oui Unknown), length %d\n",length);
	}
	return;
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char * bytes) {

	if(user && !search_payload(bytes, h->len, user)) {
		return; /* Payload string not found */
	}
	struct ether_header *arp_hdr = (struct ether_header *)bytes;
	u_char *packet = (u_char *)bytes;
	packet_count+=1; //packet count
	//printf("Count: %d\n",packet_count);     For debugging purposes

	char buffer[26];
	time_t tv_sec = h->ts.tv_sec;
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&tv_sec));
	printf("\n%s.%06d", buffer,h->ts.tv_usec); 	//print timestamp
	
	printeth(bytes,h->len - SIZE_ETHERNET);		//print ethernet header details
	
	/* check if its an ARP packet */
	if (ntohs(arp_hdr->ether_type) == ETHERTYPE_ARP) {
		printarp(bytes,h->len - SIZE_ETHERNET);
		printPayload(packet + SIZE_ETHERNET,  h->len - SIZE_ETHERNET);
		return;
	}
	
	/* The IP header */
	const struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	u_int size_ip = IP_HL(ip)*4;
	/* if (size_ip < 20) { //check for IP header length.
	   printf("   * Invalid IP header length: %u bytes\n", size_ip);
	   return;
	   } */

	switch (ip->ip_p) {
		case TYPE_ICMP:
			printicmp(packet,size_ip,h);
			break;
		case TYPE_TCP:
			printtcp(packet,size_ip,h);	
			break;
		case TYPE_UDP:
			printudp(packet,size_ip,h);
			break;
		default:
			printPayload(packet + SIZE_ETHERNET + size_ip,  h->len - (SIZE_ETHERNET + size_ip)); //print payload
			break;
	}
}

int
main (int argc, char *argv[])
{
	char *interface = NULL, *file = NULL, *string = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	int c;
	while ((c = getopt (argc, argv, "i:r:s:")) != -1) {
		switch (c) {
			case 'i':
				interface = optarg;
				printf ("Interface: %s\n",interface);
				break;
			case 'r':
				file = optarg;
				printf ("File: %s\n",file);
				break;
			case 's':
				string = optarg;
				printf ("Payload Filter: %s\n",string);
				break;
			case '?':
				if(optopt == 'i') continue;
				else if(optopt == 'r')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if(optopt == 's') continue;
				else if (isprint(optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
				return 1;
			default:
				abort ();
		}
	}

	/* Extract the <expression> i.e BPF filter that specifies which packets will be dumped. Only packets matching <expression> will be dumped. */
	char bpf_filter[100] = {0};
	int i;
	for(i = optind; i < argc; i++) {
		strcat(bpf_filter,argv[i]);
		if(i<argc-1)
			strcat(bpf_filter," ");
	}
	printf ("BPF Filter: '%s'\n",bpf_filter);
	/* Can't provide both interface and file */
	if(interface && file) {
		printf("Please provide either interface OR pcap file!\n");
		return 0;	
	}

	if(!interface && !file) {
		interface = pcap_lookupdev(errbuf);
		if(!interface) {
			printf("Couldn't find default device: %s\n",errbuf);
			return 0;
		}
		printf("Sniffing on default device: %s\n",interface);				
	}
	if(file) {
		parse(file,string,bpf_filter,0);		
	}
	else {
		parse(interface,string,bpf_filter,1);		
	}
	//printf("\nFrame Count: %d",packet_count);
	return 0;

}
