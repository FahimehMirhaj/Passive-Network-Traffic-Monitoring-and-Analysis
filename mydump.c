// commands to execute:
// 1) make clean
// 2) make
// 3) ./mydump -r sample.pcap -s GET > output.txt


#include <time.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header

#include "headers.h"

#define LOG

// function headers
const char *timestamp_string(struct timeval ts);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); 
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);


char * string = NULL;

int main(int argc, char **argv) {

    int iFlag = 0;
    int rFlag = 0;
    int sFlag = 0;
    char * interface = NULL;
    char * fileName = NULL;
    char * BPFExpression = NULL;

    char dashI[] = "-i";
    char dashR[] = "-r";
    char dashS[] = "-s";

    // Handling the program arguments
    int counter = 1;
    if (counter < argc && strcmp(dashI, argv[counter]) == 0) {
        iFlag = 1;
        counter++;
        interface = argv[counter];
        counter++;
    }
    if (counter < argc && strcmp(dashR, argv[counter]) == 0) {
        rFlag = 1;
        counter++;
        fileName = argv[counter];
        counter++;
    }
    if (counter < argc && strcmp(dashS, argv[counter]) == 0) {
        sFlag = 1;
        counter++;
        string = argv[counter];
        counter++;
    }
    if (counter < argc)
        BPFExpression = argv[counter];
#ifdef LOG
    printf ("Log::iFlag = %d, interface = %s, rFlag = %d, fileName = %s\n",iFlag, interface, rFlag, fileName);
    printf ("Log::sFlag = %d, string = %s, Filter expression = %s\n", sFlag, string, BPFExpression);
#endif
    // END Handling the program arguments

    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */

    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */


    if (iFlag == 1 && rFlag == 1) {
        fprintf(stderr, "Error::The program either listens to the interface \"%s\" or reads packets from file \"%s\"\n",
            interface, fileName);
        exit(EXIT_FAILURE);
    }
    else if (rFlag == 1) { // reading packets from the file
        handle = pcap_open_offline(fileName, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error: Couldn't read the file: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else { // reading packets live from the interface passed to the program or default interface
        if (!(iFlag == 1)) { // reading packets live from the default interface
            /*
            pcap_lookupdev() returns a pointer to a string giving the name of a network device suitable for use with 
            pcap_create() and pcap_activate(), or with pcap_open_live(), and with pcap_lookupnet().
            */
            interface = pcap_lookupdev(errbuf);
            if (interface == NULL) {
                fprintf(stderr, "Error::Couldn't find default device: %s\n", errbuf);
                exit(EXIT_FAILURE);
            }
        }

        /*
        pcap_lookupnet() is used to determine the IPv4 network number and mask associated with the network device device.
        */
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Error::Couldn't get netmask for device %s: %s\n", interface, errbuf);
            net = 0;
            mask = 0;
        }

#ifdef LOG
        printf("Log::Interface: %s\n", interface);
#endif        

        /*
        pcap_open_live() is used to obtain a packet capture handle to look at packets on the network.
        */
        handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error::Couldn't open device %s: %s\n", interface, errbuf);
            exit(EXIT_FAILURE);
        }

        /* make sure we're capturing on an Ethernet interface */
        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Error::%s is not an Ethernet\n", interface);
            exit(EXIT_FAILURE);
        }

    }

    struct bpf_program fp;          /* compiled filter program (expression) */
    if (BPFExpression != NULL) {
        /* compile the filter expression */
        if (pcap_compile(handle, &fp, BPFExpression, 0, net) == -1) {
            fprintf(stderr, "Error::Couldn't parse filter %s: %s\n", BPFExpression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Error::Couldn't install filter %s: %s\n", BPFExpression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    pcap_loop(handle, 0, process_packet, NULL);

    /* cleanup */
    if (BPFExpression != NULL)
        pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}


// function definitions
const char *timestamp_string(struct timeval tv){
    char mbuff[64];
    static char buff[64];

    time_t time = (time_t)tv.tv_sec;
    strftime(mbuff, 20, "%Y-%m-%d %H:%M:%S", localtime(&time));
    snprintf(buff, sizeof buff, "%s.%06d", mbuff, (int)tv.tv_usec);
    return buff;
}


/*
 * print data in rows of 16 bytes: hex   ascii
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    // printf("%05d   ", offset);
    
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02X ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}


/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

/*
 * print packet information
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    /* declare pointers to packet headers */
    const struct ethernet_header *ethernet;  /* The ethernet header [1] */
    const struct ip_header *ip;              /* The IP header */
    const struct tcp_header *tcp;            /* The TCP header */
    const struct udphdr *udph;               /* The UPD header */
    struct icmphdr *icmph;                   /* The ICMP header */
    const char *payload;                     /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;
        
    

    /* define ethernet header */
    ethernet = (struct ethernet_header*)(packet);
    /* define/compute ip header offset */
    ip = (struct ip_header*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    // if (size_ip < 20) {
    //     fprintf(stderr, "Error::Invalid IP header length: %u bytes\n", size_ip);
    //     exit(EXIT_FAILURE);
    // }

    
    /* determine protocol */    
    switch(ip->ip_p) {
        case IPPROTO_TCP:

            /* define/compute tcp header offset */
            tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
                exit(EXIT_FAILURE);
            }

            
            /* define/compute tcp payload (segment) offset */
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);


            if ((string == NULL) || 
                ((string != NULL) && (size_payload > 0) && (strstr(payload, string) != NULL))) {
                // capture the packet

                // COMMON
                printf("\n%s ", timestamp_string(header->ts));
                
                printf("%02X:%02X:%02X:%02X:%02X:%02X",
                (unsigned)ethernet->ether_shost[0],
                (unsigned)ethernet->ether_shost[1],
                (unsigned)ethernet->ether_shost[2],
                (unsigned)ethernet->ether_shost[3],
                (unsigned)ethernet->ether_shost[4],
                (unsigned)ethernet->ether_shost[5]);

                printf(" -> ");
                printf("%02X:%02X:%02X:%02X:%02X:%02X ",
                (unsigned)ethernet->ether_dhost[0],
                (unsigned)ethernet->ether_dhost[1],
                (unsigned)ethernet->ether_dhost[2],
                (unsigned)ethernet->ether_dhost[3],
                (unsigned)ethernet->ether_dhost[4],
                (unsigned)ethernet->ether_dhost[5]);

                printf("type 0x%04x ", ntohs(ethernet->ether_type));
                printf("len %d\n", header->len);
                // END COMMON
                // TCP - RELATED

                /* print source and destination IP addresses */
                printf("%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), 
                    inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
                printf("TCP \n");

                if (size_payload > 0) {
                    print_payload(payload, size_payload);
                }
            }

            break;
        case IPPROTO_UDP:
            
            udph = (struct udphdr *) (packet + SIZE_ETHERNET + size_ip);

            /* define/compute tcp payload (segment) offset */
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof udph);
            
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + sizeof udph);

            if ((string == NULL) || 
                ((string != NULL) && (size_payload > 0) && (strstr(payload, string) != NULL))) {
                // capture the packet

                // COMMON
                printf("\n%s ", timestamp_string(header->ts));
                
                printf("%02X:%02X:%02X:%02X:%02X:%02X",
                (unsigned)ethernet->ether_shost[0],
                (unsigned)ethernet->ether_shost[1],
                (unsigned)ethernet->ether_shost[2],
                (unsigned)ethernet->ether_shost[3],
                (unsigned)ethernet->ether_shost[4],
                (unsigned)ethernet->ether_shost[5]);

                printf(" -> ");
                printf("%02X:%02X:%02X:%02X:%02X:%02X ",
                (unsigned)ethernet->ether_dhost[0],
                (unsigned)ethernet->ether_dhost[1],
                (unsigned)ethernet->ether_dhost[2],
                (unsigned)ethernet->ether_dhost[3],
                (unsigned)ethernet->ether_dhost[4],
                (unsigned)ethernet->ether_dhost[5]);

                printf("type 0x%04x ", ntohs(ethernet->ether_type));
                printf("len %d\n", header->len);
                // END COMMON
                // TCP - RELATED

                /* print source and destination IP addresses */
                printf("%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), ntohs(udph->source), 
                    inet_ntoa(ip->ip_dst), ntohs(udph->dest));
                printf("UDP \n");

                if (size_payload > 0) {
                    print_payload(payload, size_payload);
                }
            }

            break;
        case IPPROTO_ICMP:
            icmph = (struct icmphdr *)(packet + SIZE_ETHERNET + size_ip);
            /* define/compute tcp payload (segment) offset */
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof icmph);
            
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + sizeof icmph);

            if ((string == NULL) || 
                ((string != NULL) && (size_payload > 0) && (strstr(payload, string) != NULL))) {
                // capture the packet

                // COMMON
                printf("\n%s ", timestamp_string(header->ts));
                
                printf("%02X:%02X:%02X:%02X:%02X:%02X",
                (unsigned)ethernet->ether_shost[0],
                (unsigned)ethernet->ether_shost[1],
                (unsigned)ethernet->ether_shost[2],
                (unsigned)ethernet->ether_shost[3],
                (unsigned)ethernet->ether_shost[4],
                (unsigned)ethernet->ether_shost[5]);

                printf(" -> ");
                printf("%02X:%02X:%02X:%02X:%02X:%02X ",
                (unsigned)ethernet->ether_dhost[0],
                (unsigned)ethernet->ether_dhost[1],
                (unsigned)ethernet->ether_dhost[2],
                (unsigned)ethernet->ether_dhost[3],
                (unsigned)ethernet->ether_dhost[4],
                (unsigned)ethernet->ether_dhost[5]);

                printf("type 0x%04x ", ntohs(ethernet->ether_type));
                printf("len %d\n", header->len);
                // END COMMON
                // TCP - RELATED

                /* print source and destination IP addresses */
                printf("%s -> %s ", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
                printf("ICMP \n");

                if (size_payload > 0) {
                    print_payload(payload, size_payload);
                }
            }
            break;

        default:
            // COMMON
            printf("\n%s ", timestamp_string(header->ts));
            
            printf("%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned)ethernet->ether_shost[0],
            (unsigned)ethernet->ether_shost[1],
            (unsigned)ethernet->ether_shost[2],
            (unsigned)ethernet->ether_shost[3],
            (unsigned)ethernet->ether_shost[4],
            (unsigned)ethernet->ether_shost[5]);

            printf(" -> ");
            printf("%02X:%02X:%02X:%02X:%02X:%02X ",
            (unsigned)ethernet->ether_dhost[0],
            (unsigned)ethernet->ether_dhost[1],
            (unsigned)ethernet->ether_dhost[2],
            (unsigned)ethernet->ether_dhost[3],
            (unsigned)ethernet->ether_dhost[4],
            (unsigned)ethernet->ether_dhost[5]);

            printf("type 0x%04x ", ntohs(ethernet->ether_type));
            printf("len %d\n", header->len);
            // END COMMON
            // TCP - RELATED

            /* print source and destination IP addresses */
            printf("%s -> %s ", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
            printf("OTHER \n");
            
            break;
    }

    return;
}