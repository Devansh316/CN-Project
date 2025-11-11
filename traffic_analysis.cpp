#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <cstring>
#include <ctime>
using namespace std;

// Global counters
int total_packets = 0, tcp_count = 0, udp_count = 0, icmp_count = 0, other_count = 0;
map<string, int> srcIP_count;
map<string, int> dstIP_count;

void packet_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    total_packets++;

    // Skip Ethernet header (14 bytes)
    const struct ip* ip_header = (struct ip*)(packet + 14);
    string src_ip = inet_ntoa(ip_header->ip_src);
    string dst_ip = inet_ntoa(ip_header->ip_dst);

    srcIP_count[src_ip]++;
    dstIP_count[dst_ip]++;

    switch(ip_header->ip_p) {
        case IPPROTO_TCP:
            tcp_count++;
            break;
        case IPPROTO_UDP:
            udp_count++;
            break;
        case IPPROTO_ICMP:
            icmp_count++;
            break;
        default:
            other_count++;
            break;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    // Find a network device automatically
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        cerr << "Error finding device: " << errbuf << endl;
        return 1;
    }
    cout << "✅ Capturing on device: " << dev << endl;

    // Open device for capture
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Could not open device " << dev << ": " << errbuf << endl;
        return 1;
    }

    cout << "⏳ Capturing 100 packets... (Press Ctrl+C to stop early)\n";
    pcap_loop(handle, 100, packet_handler, nullptr);

    pcap_close(handle);

    cout << "\n📊 === Traffic Summary ===\n";
    cout << "Total packets: " << total_packets << endl;
    cout << "TCP: " << tcp_count << "\nUDP: " << udp_count 
         << "\nICMP: " << icmp_count << "\nOther: " << other_count << endl;

    cout << "\n🌐 Top Source IPs:\n";
    int limit = 0;
    for (auto &entry : srcIP_count) {
        cout << entry.first << " -> " << entry.second << " packets\n";
        if (++limit == 5) break;
    }

    cout << "\n📡 Top Destination IPs:\n";
    limit = 0;
    for (auto &entry : dstIP_count) {
        cout << entry.first << " -> " << entry.second << " packets\n";
        if (++limit == 5) break;
    }

    // Simple anomaly detection
    cout << "\n⚠️ Suspicious IPs (more than 100 packets):\n";
    for (auto &entry : srcIP_count) {
        if (entry.second > 100) {
            cout << "🚨 " << entry.first << " sent " << entry.second << " packets\n";
        }
    }

    cout << "\n✅ Analysis complete.\n";
    return 0;
}
