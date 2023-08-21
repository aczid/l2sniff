// Based on https://github.com/vozlt/sniff-ipmac/blob/master/ipmac.c
// And also on https://gist.github.com/cnlohr/c30db04f8d48f47eb80aaa13a83655d6

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#define ETH_ADDRSTRLEN 18

uint8_t my_mac[ETH_ALEN] = {0};
const uint8_t broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void macbytes2str(char * str, const uint8_t mac[]){
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool log_outgoing       = true;
bool log_only_broadcast = false;

void sniff_packet_ipmac(const uint8_t *pkt_data){
    // Parse Ethernet header
    const struct ether_header *etherh = (struct ether_header*)(pkt_data);

    if(!log_outgoing && memcmp(etherh->ether_shost, my_mac, ETH_ALEN) == 0){
        // Don't log messages originating from our own interface
        return;
    }

    if(log_only_broadcast && memcmp(etherh->ether_dhost, broadcast_mac, ETH_ALEN) != 0){
        // Don't log messages that are not broadcast
        return;
    }

    // Get MACs
    char src_mac[ETH_ADDRSTRLEN] = {0};
    char dst_mac[ETH_ADDRSTRLEN] = {0};
    macbytes2str(src_mac, etherh->ether_shost);
    macbytes2str(dst_mac, etherh->ether_dhost);

    // Parse TCP/IP header
    struct tcphdr *tcph;
    char src_ip[INET6_ADDRSTRLEN] = {0};
    char dst_ip[INET6_ADDRSTRLEN] = {0};
    uint8_t ip_proto = IPPROTO_IP;

    switch(ntohs(etherh->ether_type)){
        case ETHERTYPE_IP: {
            // Parse IPv4 header
            struct ip *iph;
            iph  = (struct ip*)    (pkt_data + sizeof(struct ether_header));

            // Set pointer to TCP header
            tcph = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip));

            // Get IPv4 addresses
            if(inet_ntop(AF_INET, &iph->ip_src, src_ip, INET_ADDRSTRLEN) == NULL){
                perror("inet_ntop");
                return;
            }
            if(inet_ntop(AF_INET, &iph->ip_dst, dst_ip, INET_ADDRSTRLEN) == NULL){
                perror("inet_ntop");
                return;
            }

            // Get IP protocol
            ip_proto = iph->ip_p;
            break;
        }
        case ETHERTYPE_IPV6: {
            // Parse IPv6 header
            struct ip6_hdr *iph;
            iph = (struct ip6_hdr*)(pkt_data + sizeof(struct ether_header));

            // Set pointer to TCP header
            tcph = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

            // Get IPv6 addresses
            if(inet_ntop(AF_INET6, &iph->ip6_src, src_ip, INET6_ADDRSTRLEN) == NULL){
                perror("inet_ntop");
                return;
            }
            if(inet_ntop(AF_INET6, &iph->ip6_dst, dst_ip, INET6_ADDRSTRLEN) == NULL){
                perror("inet_ntop");
                return;
            }

            // Get IP protocol
            ip_proto = iph->ip6_nxt;
            break;
        }
        case ETHERTYPE_ARP: {
            // Parse ARP header
            struct ether_arp *arph;
            arph = (struct ether_arp*)(pkt_data + sizeof(struct ether_header));

            // Check sender MAC
            if(memcmp(arph->arp_sha, etherh->ether_shost, ETH_ALEN) != 0){
                char spoofed_mac[ETH_ADDRSTRLEN] = {0};
                macbytes2str(spoofed_mac, arph->arp_sha);
                printf("Spoofed ARP packet from %s as %s\n", src_mac, spoofed_mac);
            }
            switch(ntohs(arph->arp_op)){
                case ARPOP_REQUEST: {
                    break;
                }
                case ARPOP_REPLY: {
                    // Check receiver MAC
                    if(memcmp(arph->arp_tha, etherh->ether_dhost, ETH_ALEN) != 0){
                        char wrong_mac[ETH_ADDRSTRLEN] = {0};
                        macbytes2str(wrong_mac, arph->arp_tha);
                        printf("Broken ARP reply for %s to %s\n", wrong_mac, dst_mac);
                    }
                    break;
                }
                default: {
                    fprintf(stderr, "%s sent unknown ARP op: 0x%04X\n", src_mac, ntohs(arph->arp_op));
                    break;
                }
            }

            // Get IPv4 addresses
            if(inet_ntop(AF_INET, arph->arp_spa, src_ip, INET_ADDRSTRLEN) == NULL){
                perror("inet_ntop");
                return;
            }
            if(inet_ntop(AF_INET, arph->arp_tpa, dst_ip, INET_ADDRSTRLEN) == NULL){
                perror("inet_ntop");
                return;
            }
            printf("ARP  %-52s%s ~> %-52s%s\n", src_ip, src_mac, dst_ip, dst_mac);
            return;
        }
        default : {
            fprintf(stderr, "%s sent unknown EtherType: 0x%04X\n", src_mac, ntohs(etherh->ether_type));
            return;
        }
    }

    // Parse TCP, UDP and ICMP
    char * proto = NULL;
    switch(ip_proto){
        case IPPROTO_UDP: {
            proto = "UDP ";
            break;
        }
        case IPPROTO_TCP: {
            proto = "TCP ";
            break;
        }
        case IPPROTO_ICMP: {
            proto = "ICMP";
            printf("%s %-52s%s ~> %-52s%s\n", proto, src_ip, src_mac, dst_ip, dst_mac);
            return;
        }
        default: {
            fprintf(stderr, "%s sent unknown IP protocol 0x%02X\n", src_ip, ip_proto);
            return;
        }
    }

    // Get ports from TCP header (port numbers for UDP overlap)
    const uint16_t src_port = ntohs(tcph->source);
    const uint16_t dst_port = ntohs(tcph->dest);

    // Print with alignment
    char srcs[INET6_ADDRSTRLEN+6] = {0};
    char dsts[INET6_ADDRSTRLEN+6] = {0};
    sprintf(srcs, "%s:%hu", src_ip, src_port);
    sprintf(dsts, "%s:%hu", dst_ip, dst_port);
    printf("%s %-52s%s ~> %-52s%s\n", proto, srcs, src_mac, dsts, dst_mac);
}

int get_raw_socket(){
    // Create PF_PACKET socket
    const int sock_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_raw < 0){
        perror("socket");
        fprintf(stderr, "You must be root (have CAP_NET_RAW capability) to create a raw socket\n");
        return -1;
    }
    return sock_raw;
}

int get_interface_mac(const char * interface, uint8_t mac[]){
    const int sock_raw = get_raw_socket();
    if(sock_raw < 0){
        // Error handling done by get_raw_socket
        return -1;
    }

    // Get named interface's MAC address
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    if(ioctl(sock_raw, SIOCGIFHWADDR, &ifr) < 0){
        perror("ioctl");
        close(sock_raw);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(sock_raw);
    return 0;
}

int get_l2_socket(const char * interface){
    const int sock_raw = get_raw_socket();
    if(sock_raw < 0){
        // Error handling done by get_raw_socket
        return -1;
    }

    // Bind raw socket to link layer device
    struct sockaddr_ll sa = {0};
    sa.sll_family  = PF_PACKET;
    sa.sll_ifindex = if_nametoindex(interface);
    if(bind(sock_raw, (const struct sockaddr *) &sa, sizeof(sa)) < 0){
        perror("bind");
        close(sock_raw);
        return -1;
    }
    return sock_raw;
}

int main(int argc, char* argv[]){
    char* interface = NULL;
    if(argc > 1){
        interface = argv[1];
    } else {
        printf("Usage: %s <interface>\n", argv[0]);
        return -1;
    }

    if(get_interface_mac(interface, my_mac) < 0){
        // Error handling done by get_interface_mac
        return -1;
    }

    const int sock_l2 = get_l2_socket(interface);
    if(sock_l2 < 0){
        // Error handling done by get_l2_socket
        return -1;
    }

    uint8_t rbuff[ETH_FRAME_LEN] = {0};
    while(true){
        if(recv(sock_l2, rbuff, sizeof(rbuff), 0) < 0){
            perror("recv");
            return -1;
        }
        sniff_packet_ipmac(rbuff);
    }

    close(sock_l2);

    return 0;
}

