#include <stdio.h>
#include <pcap.h>


#define FILTER_RULE1 "port 80"
#define FILTER_RULE2 "port 53"

int total_header_size =0;	//from ip header to end
int tcp_header_size =0;		//TCP header size
int proto =0;			//TCP(1) or UDP(2)
int no2 =0;				//HTTP(1) or DNS(2)
int type=0;				//Each num of loop

struct eth_header
{
	u_char ether_dhost[6];
	u_char  ether_shost[6];
	u_short  ether_type;
};
//ether header struct
struct ip_header
{
	u_char ip_info1[2];
	u_char ip_size[2];
	u_short ip_info2[2];
	u_char ip_info3[12];
};
//ip header struct
struct tcp_header
{
	u_char tcp_info1[4];
	u_char tcp_info2[9];
	
};
//tcp struct
struct dns_header
{
	u_char dns_info[12];
};
//dns struct
struct http_header
{
	u_char http_info[10000];

};
//http header struct

void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data) {
	
	int s_port =0;
	int d_port =0;

	
//=================================================ether-net header ==================================	
	struct eth_header *eth = (struct eth_header *)pkt_data;
/*	
	u_char *b=eth->ether_dhost;
	printf("%x : %x : %x : %x : %x : %x femkfmekfmek \n",b[0],b[1],b[2],b[3],b[4],b[5]);
*/

	pkt_data = pkt_data + (sizeof(char) *14);

//***********************************************<<<<<<<<<<<<<<<<<<<<< when the HTTP get in >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>***************************************

	if(no2==1){
		
//=================================================ip header ==================================
		struct ip_header *ip = (struct ip_header *)pkt_data;

		pkt_data = pkt_data + (sizeof(char) *2);

		u_char *sli_size = ip->ip_size;

		total_header_size = (sli_size[0]*256+sli_size[1]);
//printf("%d ip total size\n", total_header_size);	//ip total size

		pkt_data = pkt_data + (sizeof(char) *6);

		u_char *sli_ip2 = ip->ip_info3;

//checking what protocol type (6=tcp 17 =udp)
		if(sli_ip2[1] == 6){
			proto =1;
		}
		else{
			proto =2;
		}
//printf("%d protocol\n",sli_ip2[1]); // 1= icmp 6=tcp 17 =udp

		pkt_data = pkt_data + (sizeof(char) *(12));


		if(proto ==1){

//=================================================tcp header ==================================
			struct tcp_header *tcp = (struct tcp_header *)pkt_data;

			u_char *sli_tcp = tcp->tcp_info1;
//soure port
			s_port = (sli_tcp[0]*256)+sli_tcp[1];
						//print the soure port

//destination port
			d_port = (sli_tcp[2]*256)+sli_tcp[3];


			pkt_data = pkt_data + (sizeof(char) *(4));

			u_char *sli_tcp2 = tcp->tcp_info2;

//tcp data offset size
			tcp_header_size =(sli_tcp2[8]/16);
//			printf("%d Dataoffset\n", tcp_header_size);
			
			if(tcp_header_size>5){
				pkt_data = pkt_data + (sizeof(char) *(16+((tcp_header_size-5)*4)));
			}
			else{
				pkt_data = pkt_data + (sizeof(char) *(16));
			}
//jumping tcp to http header with offset size
		}


		if(proto ==2){
//=================================================udp header ==================================
			struct tcp_header *tcp = (struct tcp_header *)pkt_data;

			u_char *sli_tcp = tcp->tcp_info1;
//soure port
			s_port = (sli_tcp[0]*256)+sli_tcp[1];

//destination port
			d_port = (sli_tcp[2]*256)+sli_tcp[3];


			pkt_data = pkt_data + (sizeof(char) *(8));
			tcp_header_size =5;
//jumping udp to http header

		}
//=================================================http header ==================================
		total_header_size = (total_header_size-40)-((tcp_header_size-5)*4);

		if(total_header_size !=0){

			struct http_header *http = (struct http_header *)pkt_data;
			u_char *sli_http = http->http_info;
	
			int boolhttp=0;
//check that contain the word HTTP to figure out the real http header
			for(int a=0;a<total_header_size;a++){
				if(sli_http[a] =='H'){
					if(sli_http[a+1] =='T' && sli_http[a+2] =='T' && sli_http[a+3] =='P'){
						boolhttp=1;
					}
					if(sli_http[a] == '\n' && sli_http[a] =='\r'){
						break;
					}
				}
			}
//if it is real http header print the infomation 
			if(boolhttp==1){
				type++;
				printf("%d ", type);
				printf("%d.%d.%d.%d:",sli_ip2[4],sli_ip2[5],sli_ip2[6],sli_ip2[7]); 	//print the soure ip
				printf("%d ", s_port);		
				printf("%d.%d.%d.%d:",sli_ip2[8],sli_ip2[9],sli_ip2[10],sli_ip2[11]);	//print the destination ip
				printf("%d ", d_port);								//print the destination port
				printf("HTTP ");
				if(type%2 ==1){
					printf("Request\n");
				}
				else{
					printf("Response\n");
				}
//check the body and head with \r\n\r\n\. when \r\n\r\n is appear cut the input
				for(int a=0;a<total_header_size;a++){
				
					printf("%c", sli_http[a]);
					if(sli_http[a] =='\n'){
						if(sli_http[a-1] =='\r' && sli_http[a-2] =='\n' && sli_http[a-3] =='\r'){
							pkt_data = pkt_data + (sizeof(char) *(total_header_size));
							break;
						}
					}
				}
			}
		}
	}
//**************************************************<<<<<<<<<<<<<<<<<<<<< when the DNS get in >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>********************************************
	else{
//=================================================ip header ==================================
		struct ip_header *ip = (struct ip_header *)pkt_data;

		pkt_data = pkt_data + (sizeof(char) *2);

		u_char *sli_size = ip->ip_size;

		total_header_size = (sli_size[0]*256+sli_size[1]);
//printf("%d ip total size\n", total_header_size);	//ip total size

		pkt_data = pkt_data + (sizeof(char) *6);

		u_char *sli_ip2 = ip->ip_info3;

//checking what protocol type (6=tcp 17 =udp)
		if(sli_ip2[1] == 6){
			proto =1;
		}
		else{
			proto =2;
		}
//printf("%d protocol\n",sli_ip2[1]); // 1= icmp 6=tcp 17 =udp

		pkt_data = pkt_data + (sizeof(char) *(12));

		if(proto ==1){

//=================================================tcp header ==================================
			struct tcp_header *tcp = (struct tcp_header *)pkt_data;

			u_char *sli_tcp = tcp->tcp_info1;
//soure port
			s_port = (sli_tcp[0]*256)+sli_tcp[1];

//destination port
			d_port = (sli_tcp[2]*256)+sli_tcp[3];

			pkt_data = pkt_data + (sizeof(char) *(4));

			u_char *sli_tcp2 = tcp->tcp_info2;

//tcp data offset size
			tcp_header_size =(sli_tcp2[8]/16);
//			printf("%d Dataoffset\n", tcp_header_size);
			
			if(tcp_header_size>5){
				pkt_data = pkt_data + (sizeof(char) *(16+((tcp_header_size-5)*4)));
			}
			else{
				pkt_data = pkt_data + (sizeof(char) *(16));
			}
		}
//jump tcp to Dns with data offset size 

		if(proto ==2){
//=================================================udp header ==================================
			struct tcp_header *tcp = (struct tcp_header *)pkt_data;

			u_char *sli_tcp = tcp->tcp_info1;
//soure port
			int s_port = (sli_tcp[0]*256)+sli_tcp[1];

//destination port
			int d_port = (sli_tcp[2]*256)+sli_tcp[3];


			pkt_data = pkt_data + (sizeof(char) *(8));
//jump udp to dns
		}

//=================================================dns header ==================================		
//print the information
		type++;
		printf("%d ", type);
		printf("%d.%d.%d.%d:",sli_ip2[4],sli_ip2[5],sli_ip2[6],sli_ip2[7]); 	//print the soure ip
		printf("%d ", s_port);		
		printf("%d.%d.%d.%d:",sli_ip2[8],sli_ip2[9],sli_ip2[10],sli_ip2[11]);	//print the destination ip
		printf("%d ", d_port);								//print the destination port
		printf("DNS ID : ");

		struct dns_header *dns = (struct dns_header *)pkt_data;
		u_char *sli_dns = dns->dns_info;

//DNS ID print
		printf("%02x%02x\n", sli_dns[0],sli_dns[1]);
		
		int pri =0;
		int num1 =sli_dns[2];
		int num2 =sli_dns[3];
//DNS QR
		printf("%d | ",((num1/16)/8)	);
//DNS OP code
		printf("%d",((num1/16)%8)/4	);
		printf("%d",(((num1/16)%8)%4)/2	);
		printf("%d",(((num1/16)%8)%4)%2	);
		printf("%d | ",((num1%16)/8));
//DNS AA 
		printf("%d | ",((num1%16)%8)/4	);
//DNS TC
		printf("%d | ",(((num1%16)%8)%4)/2	);
//DNS RD
		printf("%d | ",(((num1%16)%8)%4)%2	);
//DNS RA
		printf("%d | ",((num2/16)/8)	);
//DNS Z
		printf("%d",((num2/16)%8)/4	);
		printf("%d",(((num2/16)%8)%4)/2	);
		printf("%d | ",(((num2/16)%8)%4)%2	);
//DNS RCODE
		printf("%d",((num2%16)/8));
		printf("%d",((num2%16)%8)/4	);
		printf("%d",(((num2%16)%8)%4)/2	);
		printf("%d\n",(((num2%16)%8)%4)%2	);
//DNS INFO		
		printf("QDCOUNT : %x \n" , (sli_dns[4]*256)+sli_dns[5]);
		printf("ANCOUNT : %x \n" , (sli_dns[6]*256)+sli_dns[7]);
		printf("NSCOUNT : %x \n" , (sli_dns[8]*256)+sli_dns[9]);
		printf("ARCOUNT : %x \n" , (sli_dns[10]*256)+sli_dns[11]);
		printf("\n");			
	}
}

int main(int argc, char **argv) {
    
	pcap_t *adhandle; //packet capture descriptor
	char errbuf[PCAP_ERRBUF_SIZE]; //error buf

	pcap_if_t *alldevs; //network interface
	pcap_if_t *d;		//network interface

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char *dev;			//device use
	char *net;			//information ipnet
	char *mask;			//information mask
	int ret;

    struct pcap_addr *a;
    int i = 0;
    int no1;		//will use device num
	

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		printf("%s\n",errbuf);
		return 0;
	}
	printf("DEV : %s\n",dev);
//find my using device

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		printf("%s\n",errbuf);
		return -1;
	}		//if it has error 

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return -1;
    }		//if it has error 

    for (d=alldevs; d; d=d->next) {
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }
//show all of then device

    printf("number : ");
    scanf("%d", &no1);
//choose the device
	printf("Http =1 or Dns=2 number : ");
	scanf("%d", &no2);
//coose the HTTP or DNS
    if (!(no1 > 0 && no1 <= i)) {
        printf("number error\n");
        return 1;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no1 == ++i)  break;
    }		//if it has error 
//================================================if we choose http===================================
	if(no2 ==1){		
		if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
		    printf("pcap_open_live error %s\n", d->name);
		    pcap_freealldevs(alldevs);
		    return -1;
		}
//open the choose device
		struct bpf_program  fcode;
		if (pcap_compile(adhandle,  // pcap handle
		            &fcode,  // compiled rule
		            FILTER_RULE1,  // filter rule
		            0,            // optimize
		            netp) < 0){
		    printf("pcap compile failed\n");
		    pcap_freealldevs(alldevs);
		    return -1;
		}
		if (pcap_setfilter(adhandle, &fcode) <0 ){
		    printf("pcap compile failed\n");
		    pcap_freealldevs(alldevs);
		    return -1;
		}
//setting the device what to open (http or dns) and start to get the info
		pcap_freealldevs(alldevs);

		pcap_loop(adhandle, 0, packet_handler, NULL);
//we the packet get in call the packet_handler for infinite loop
		pcap_close(adhandle);
	}

//================================================if we choose DNS===================================
	else if(no2 ==2){

		if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
		    printf("pcap_open_live error %s\n", d->name);
		    pcap_freealldevs(alldevs);
		    return -1;
		}
//open the choose device
		struct bpf_program  fcode;
		if (pcap_compile(adhandle,  // pcap handle
		            &fcode,  // compiled rule
		            FILTER_RULE2,  // filter rule
		            0,            // optimize
		            netp) < 0){
		    printf("pcap compile failed\n");
		    pcap_freealldevs(alldevs);
		    return -1;
		}
		if (pcap_setfilter(adhandle, &fcode) <0 ){
		    printf("pcap compile failed\n");
		    pcap_freealldevs(alldevs);
		    return -1;
		}
//setting the device what to open (http or dns) and start to get the info
		pcap_freealldevs(alldevs);

		pcap_loop(adhandle, 0, packet_handler, NULL);
//we the packet get in call the packet_handler for infinite loop
		pcap_close(adhandle);

	}

    return 0;
} 
