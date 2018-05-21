#include <stdio.h>
#include <stdlib.h>					//strncmp
#include <regex>					//std::regex
#include <string>					//std::string
#include <iostream>
#include <unordered_set>
#include <set>
#include <fstream>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#define LIBNET_LIL_ENDIAN 1
#include <libnet/libnet-headers.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <chrono>
u_int8_t NF_flag = NF_ACCEPT;
std::unordered_set<std::string> ban_list;
using namespace std;

typedef std::chrono::high_resolution_clock::time_point Clock;

  typedef std::chrono::high_resolution_clock::duration Diff;

  typedef std::chrono::high_resolution_clock Timer;

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *data;
	NF_flag = NF_ACCEPT;

	ph = nfq_get_msg_packet_hdr(tb);
    	if (ph) {
        	id = ntohl(ph->packet_id);
    	}

	ret = nfq_get_payload(tb, &data);
	if(ret >= 0) {
		struct libnet_ipv4_hdr* ipH = (struct libnet_ipv4_hdr *) data;
		if(ipH->ip_p == 6){
			data += (ipH->ip_hl)*4;
			struct libnet_tcp_hdr* tcpH = (struct libnet_tcp_hdr *) data;
			u_int16_t len = (ipH->ip_hl * 4)+(tcpH->th_off * 4);
			if((ntohs(tcpH->th_sport) == 80) || (ntohs(tcpH->th_dport) == 80)){
				if(ipH->ip_len > len){
					data += (tcpH->th_off * 4);
					string s_data, check_host;
					s_data = (char*) data;
					static regex check("Host: ([^\r]*)");
					smatch host;

					if(regex_search(s_data, host, check)) {
						check_host = host[1];
					//	check_host.erase(check_host.length()-1, 1);
						unordered_set<string>::iterator iter;
						iter = ban_list.find(check_host);
						if(iter != ban_list.end()) {
							NF_flag = NF_DROP;
							cout << "host = " << *iter << endl;
						}
					}
				}
			}
		}
	}

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

	if(NF_flag == NF_DROP) printf("***************** block *****************\n");
//    	else printf("entering callback\n");

    	return nfq_set_verdict(qh, id, NF_flag, 0, NULL);

}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        printf("error during nfq_open()\n");
        exit(1);
    }

    Timer timer;
    Clock start = timer.now();
    ifstream list_file("/root/1m_detect/1m_list.txt");
    string ban;
    while(!list_file.eof()) {
	getline(list_file, ban);
	ban_list.insert(ban);
    }
    list_file.close();
    Clock end = timer.now();
    cout << (end - start).count() << endl;

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    qh = nfq_create_queue(h,  0, &cb, NULL);					// Queue create
    if (!qh) {
        printf("error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
 //           printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
