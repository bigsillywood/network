

#include <pcap.h>


void got_pack(u_char *param1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void free_packet(u_char *param);