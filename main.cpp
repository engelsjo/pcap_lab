//
//  main.cpp
//  457LabOne_RetrievePacketsInfo
//
//  Created by Joshua Engelsma on 8/26/14.
//  Copyright (c) 2014 Joshua Engelsma. All rights reserved.
//

#include <cstdio>
#include <math.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <string>
#include <iostream>


//helper classes
class SourceDestPairs{
public:
    std::string source;
    std::string destination;
    
    bool operator == (const SourceDestPairs& op2) const{
        return source.compare(op2.source) == 0 && destination.compare(op2.destination) == 0;
    }
    
    bool operator < (const SourceDestPairs& op2) const{
        return source < op2.source;
    }
};

class SourceDestPorts{
public:
    int srcPort;
    int destPort;
    
    bool operator == (const SourceDestPorts& op2) const{
        return srcPort == op2.srcPort && destPort == op2.destPort;
    }
    
    bool operator < (const SourceDestPorts& op2) const{
        return srcPort < op2.srcPort;
    }
    
};

class SourceDestPortsAndCounts{
public:
    int srcPort;
    int destPort;
    int count;
    
    bool operator == (const SourceDestPortsAndCounts& op2) const{
        return count == op2.count;
    }
    
    bool operator < (const SourceDestPortsAndCounts& op2) const{
        return count > op2.count;
    }
};


//global variables...
int nbrOfEther8023, nbrOfEtherII, nbrOfIP, nbrOfIPV6, nbrOfARP, nbrOfBytes, nbrOfTCP, nbrOfUPD, nbrOfICMP, nbrOfPkts = 0;
std::map<int, int> etherTypesAndTheirCounts;
std::map<int, int> etherTypesAndTheirBytes;
std::map<SourceDestPairs, int> srcDestPairs;
std::map<SourceDestPorts, int> tcpSrcDestPorts;
std::map<SourceDestPorts, int> udpSrcDestPorts;
std::set<SourceDestPortsAndCounts> tcpSrcDestPortsAndCounts;
std::set<SourceDestPortsAndCounts> udpSrcDestPortsAndCounts;

//forward method declarations...
void processEthernetTypesStepOne(int etherType, const struct pcap_pkthdr* h);
void processEthernetTwoTypesStepTwo(int etherType);
void processEthernetTwoNbrOfBytesStepThree(int etherType, const struct pcap_pkthdr*);
void processIPV4SourceDestinationStepFour(const struct ether_header*, const struct ip*);
void processTransportLayerStepFive(const struct ether_header*, const struct ip*);
void processTcpUdpSourceDestinationsStepSix(const struct ether_header* eptr, const struct ip* ip_hdr, const u_char* bytes);
void printPcapFileStatistics();

void process_pkt(u_char *junk, const struct pcap_pkthdr *h, const u_char *bytes){
    ++nbrOfPkts;
    struct ether_header *eptr = (struct ether_header*)bytes; //get ether header
    int etherType = ntohs(eptr->ether_type);
    
    bytes += sizeof(struct ether_header); //get ip header
    struct ip* ip_hdr;
    ip_hdr = (struct ip*)bytes;
    
    processEthernetTypesStepOne(etherType, h);
    processEthernetTwoTypesStepTwo(etherType);
    processEthernetTwoNbrOfBytesStepThree(etherType, h);
    processIPV4SourceDestinationStepFour(eptr, ip_hdr);
    processTransportLayerStepFive(eptr, ip_hdr);
    processTcpUdpSourceDestinationsStepSix(eptr, ip_hdr, bytes);
}

void processEthernetTypesStepOne(int etherType, const struct pcap_pkthdr* h){
    etherType >= 1536 ? nbrOfEtherII++, nbrOfBytes += h->len : nbrOfEther8023++;
}

void processEthernetTwoTypesStepTwo(int etherType){
    if(etherType >= 1536 && !etherTypesAndTheirCounts.insert(std::pair<int, int>(etherType, 1)).second){
        etherTypesAndTheirCounts[etherType]++;
    }
}

void processEthernetTwoNbrOfBytesStepThree(int etherType, const struct pcap_pkthdr* h){
    if(etherType >= 1536 && !etherTypesAndTheirBytes.insert(std::pair<int, int>(etherType, h->len)).second){
        etherTypesAndTheirBytes[etherType] += h->len;
    }
}

void processIPV4SourceDestinationStepFour(const struct ether_header* eptr, const struct ip* ip_hdr){
    if(ntohs(eptr->ether_type) == ETHERTYPE_IP){ //ipv4 packets only
        char src_ip[100], dst_ip[100];
        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));
        SourceDestPairs node;
    
        std::string source(src_ip);
        std::string destination(dst_ip);
        
        node.source = source;
        node.destination = destination;
        if(!srcDestPairs.insert(std::make_pair(node, 1)).second){
            srcDestPairs[node]++;
        }
    }
}

void processTransportLayerStepFive(const struct ether_header* eptr, const struct ip* ip_hdr){
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP){
        if(ip_hdr->ip_p == IPPROTO_TCP){
            nbrOfTCP++;
        }else if(ip_hdr->ip_p == IPPROTO_UDP){
            nbrOfUPD++;
        }else if(ip_hdr->ip_p == IPPROTO_ICMP){
            nbrOfICMP++;
        }
    }
    
}

void processTcpUdpSourceDestinationsStepSix(const struct ether_header* eptr, const struct ip* ip_hdr, const u_char* bytes){
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP){
        if(ip_hdr->ip_p == IPPROTO_TCP){ //collect source and destinations for tcp
            struct tcphdr* tcp_hdr; //get tcp header
            tcp_hdr = (struct tcphdr*)(bytes + ip_hdr->ip_hl * 4);
            int sourcePort = ntohs(tcp_hdr->th_sport);
            int destPort = ntohs(tcp_hdr->th_dport);
            SourceDestPorts node;
            node.srcPort = sourcePort;
            node.destPort = destPort;
            if (!tcpSrcDestPorts.insert(std::make_pair(node, 1)).second){
                tcpSrcDestPorts[node] += 1;
            }
        } else if(ip_hdr->ip_p == IPPROTO_UDP){ //collect source and destination for udp
            struct udphdr* udp_hdr; //get udp header
            udp_hdr = (struct udphdr*)(bytes + ip_hdr->ip_hl * 4);
            int sourcePort = ntohs(udp_hdr->uh_sport);
            int destPort = ntohs(udp_hdr->uh_dport);
            SourceDestPorts node;
            node.srcPort = sourcePort;
            node.destPort = destPort;
            if (!udpSrcDestPorts.insert(std::make_pair(node, 1)).second){
                udpSrcDestPorts[node] += 1;
            }
        }
    }
}

void printPcapFileStatistics(){
    //step 2 in assignment
    double percentII = nbrOfEtherII/(double)nbrOfPkts * 100;
    double percent8023 = nbrOfEther8023/(double)nbrOfPkts * 100;
    printf("PERCENT OF EACH ETHERNET TYPE\n");
    printf("Percent of (EthernetII): %g%%\n", percentII);
    printf("Percent of (Ether802.3): %g%% percent\n", percent8023);
    printf("\n");
    //step 3 in assignment
    printf("PERCENT OF EACH TYPE OF ETHERNET II (ARP, IP ETC)\n");
    for(auto iter=etherTypesAndTheirCounts.begin(); iter != etherTypesAndTheirCounts.end(); ++iter){
        int ethernetType = (*iter).first;
        double ethernetTypePercent = (*iter).second/(double)nbrOfEtherII*100;
        if(ethernetType == ETHERTYPE_ARP){
            nbrOfARP = (*iter).second;
            printf("Percent of ARP (%x): %g%%\n", ethernetType, ethernetTypePercent);
        } else if (ethernetType == ETHERTYPE_IP){
            nbrOfIP = (*iter).second;
            printf("Percent of IP (%x): %g%%\n", ethernetType, ethernetTypePercent);
        } else if(ethernetType == ETHERTYPE_IPV6){
            nbrOfIPV6 = (*iter).second;
            printf("Percent of IPv6 (%x): %g%%\n", ethernetType, ethernetTypePercent);
        } else{
            printf("Percent of %x: %g%%\n", ethernetType, ethernetTypePercent);
        }
    }
    //step 4 in assignment
    printf("\nTOTAL BYTES TRANSFERRED AND PERCENT BYTES FOR EACH NETWORK LAYER PROTOCOL\n");
    printf("Total Bytes Transferred on Ethernet II: %d bytes\n",nbrOfBytes);
    for(auto iter = etherTypesAndTheirBytes.begin(); iter != etherTypesAndTheirBytes.end(); ++iter){
        int ethernetType = (*iter).first;
        double ethernetTypePercentOfBytes = (*iter).second/(double)nbrOfBytes*100;
        if(ethernetType == ETHERTYPE_ARP){
            printf("Percent of bytes transferred using ARP (%x): %g%%\n", ethernetType, ethernetTypePercentOfBytes);
        } else if (ethernetType == ETHERTYPE_IP){
            printf("Percent of bytes transferred using IP (%x): %g%%\n", ethernetType, ethernetTypePercentOfBytes);
        } else if(ethernetType == ETHERTYPE_IPV6){
            printf("Percent of bytes transferred using IPv6 (%x): %g%%\n", ethernetType,ethernetTypePercentOfBytes);
        } else{
            printf("Percent of bytes transferred using %x: %g%%\n", ethernetType, ethernetTypePercentOfBytes);
        }
    }
    //step 5 in assignment
    std::cout << "\nIPV4 SOURCE/DESTINATION PAIRS AND THEIR COUNTS \n";
    for(auto iter = srcDestPairs.begin(); iter != srcDestPairs.end(); ++iter){
        SourceDestPairs node = (*iter).first;
        int nodeCount = (*iter).second;
        double nodePercent = (double)nodeCount/nbrOfIP * 100;
        std::cout << "Source: " << node.source << "\nDestination: " << node.destination << "\nPercent of IPV4: " << nodePercent << "%%\n\n";
    }
    //step 6 in assignment
    double percentTCP = (double)nbrOfTCP/nbrOfIP * 100;
    double percentUDP = (double)nbrOfUPD/nbrOfIP * 100;
    double percentICMP =(double)nbrOfICMP/nbrOfIP *100;
    std::cout << "\nTRANSPORT LAYER FOR IP PACKETS AND PERCENTAGES THEY ARE USED\n";
    std::cout << "Percent of IP packets using TCP: " << percentTCP << "%\n";
    std::cout << "Percent of IP packets using UDP: " << percentUDP << "%\n";
    std::cout << "Percent of IP packets using ICMP: " << percentICMP << "%\n";
    //step 7 in assignment
    std::cout << "\nTCP SOURCE DESTINATION PORTS AND THEIR PERCENTAGE OF PACKETS\n";
    for(auto iter = tcpSrcDestPorts.begin(); iter != tcpSrcDestPorts.end(); ++iter){
        SourceDestPorts node = (*iter).first;
        int count = (*iter).second;
        SourceDestPortsAndCounts nodeToInsert;
        nodeToInsert.srcPort = node.srcPort;
        nodeToInsert.destPort = node.destPort;
        nodeToInsert.count = count;
        tcpSrcDestPortsAndCounts.insert(nodeToInsert);
    }
    int nbrOfNodesPrinted = 0;
    for(auto iter = tcpSrcDestPortsAndCounts.begin(); iter != tcpSrcDestPortsAndCounts.end(); ++iter){
        SourceDestPortsAndCounts node = (*iter);
        int src = node.srcPort;
        int dest = node.destPort;
        double percent = (double)node.count/(double)nbrOfTCP * 100;
        std::cout << "Source Port: " << src << " Dest Port: " << dest << " Percent: " << percent << "%\n";
        if (nbrOfNodesPrinted > 3){
            break;
        }
        else{
            ++nbrOfNodesPrinted;
        }
    }
    std::cout << "\nUDP SOURCE DESTINATION PORTS AND THEIR PERCENTAGE OF PACKETS\n";
    for(auto iter = udpSrcDestPorts.begin(); iter != udpSrcDestPorts.end(); ++iter){
        SourceDestPorts node = (*iter).first;
        int count = (*iter).second;
        SourceDestPortsAndCounts nodeToInsert;
        nodeToInsert.srcPort = node.srcPort;
        nodeToInsert.destPort = node.destPort;
        nodeToInsert.count = count;
        udpSrcDestPortsAndCounts.insert(nodeToInsert);
    }
    nbrOfNodesPrinted = 0;
    for(auto iter = udpSrcDestPortsAndCounts.begin(); iter != udpSrcDestPortsAndCounts.end(); ++iter){
        SourceDestPortsAndCounts node = (*iter);
        int src = node.srcPort;
        int dest = node.destPort;
        double percent = (double)node.count/(double)nbrOfUPD * 100;
        std::cout << "Source Port: " << src << " Dest Port: " << dest << " Percent: " << percent << "%\n";
        if (nbrOfNodesPrinted > 3){
            break;
        }
        else{
            ++nbrOfNodesPrinted;
        }
    }
}


int main(int argc, char *argv[]){
    if(argc!=2){
        fprintf(stderr, "Usage: %s <pcapfile>\n",argv[0]);
        return 1;
    }
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[1], err);
    if(pcap == NULL){
        fprintf(stderr, "Error: %s\n", err);
        return 1;
    }
    pcap_loop(pcap,500,process_pkt,NULL);
    printPcapFileStatistics();
    return 0;
}

