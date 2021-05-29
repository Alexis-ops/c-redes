#include <stdio.h>
#include <stdlib.h>
#include "C:\\Users\\PC\\Downloads\\sdk-ncap\\Include\\pcap\\pcap.h"  /*agregamos la libreria directamente*/
#include <pcap.h>
#define LINE_LEN 16
#define RUTA "C:\\Users\\PC\\Downloads\\paquetes3.pcap" /*El archivo que contiene las tramas*/
#define 	PCAP_OPENFLAG_PROMISCUOUS   1
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *); /* La funcion que hace posible el separar las tramas bit a bit */
int trama_lcc();
int capturar_tramas();
/* Las variable que usaremos para poder almacenar algunos datos que mostraremos en pantalla */
unsigned char tipo;
unsigned char i_g;
unsigned char c_r;
unsigned char c_b1;
unsigned char nsec;
unsigned char nack;
unsigned char cod;
unsigned char cod_1;

typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
	
}ip_header,variable;

int main(int argc, char **argv)
{
	int n=0;
	
	while(n != 5){
		printf("1.- Capturar tramas. \n");
		printf("2.- Capturar trama llc. \n");
		scanf("%i", &n);
		system("cls");
		switch(n){
			case 1:
				capturar_tramas();
			break;
			case 2:
				trama_lcc();
			break;
			
		}
	}

    return 0;
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    u_int i=0;

    /*
     * Unused variable
     */
    (VOID)temp1;

    /* print pkt timestamp and pkt len */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
    
    /* Print the packet */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
        
		
    }
    /* Aqui comenzamos el trabajo de la practica 2*/
    
    /* Para saber si es Ethernet o IEEE debemos dirigirnos al bit 12 y 13 donde si el valor es mayor a 1500 es una trama Ethernet */
    if( tipo = (pkt_data[12]*256)+pkt_data[13] > 1500){/*Aqui hacemos dos cosas a la vez. sacamos el valor del bit 12 y 13,
	* para posteriormente comparar con la cifra de 15000, 
	* para poder decifrar que trama estamos tratando. */
    	printf("\n Es una trama Ethernet");
	}
	else{
		printf("\n Es una trama IEEE");
	}
	
	 if((i_g=pkt_data[14]&0x01) == 0 ){/* Aqui hacemos dos cosas sacar el valor de bit 14 para saber en el campo psap si es 
	  individual o gruop*/
    	printf("\n El campo PSAP es: INDIVIDUAL");
	}else{
		printf("\n El campo PSAP es: GROUP");
	}
	
	if((c_r=pkt_data[15]&0x01) == 0 ){/* Aqui hacemos dos cosas sacar el valor de bit 15 para saber en el campo SSAP si es 
	  Command o Response*/
    	printf("\n El campo SSAP es: COMMAND");
	}else{
		printf("\n El campo SSAP es: RESPONSE");
	}
	/*Aqui verificamos el campo control pero este puede tomar ya sea 1 o 2 bits por lo que requirimos saber el campo lenght para saber el numero de bits*/
	//Control
	if(tipo = (pkt_data[12]*256)+pkt_data[13] <= 3 ){
		//Un bit de campo control
		
		if((c_b1 = pkt_data[16]&0x01) == 0){
			printf("\n Es un campo control I");
			
			printf("\n El pull/final es: %x",(pkt_data[16]>>4)&0x01);
			nsec = (pkt_data[16]>>1)&0x07;
			nack = (pkt_data[16]>>5)&0x07;
			printf("\n send sequence es: %02x",nsec);
			printf("\n receive sequence es: %02x",nack);
		}
		if((c_b1 = pkt_data[16]&0x01) == 1){
			//hay de dos, es S o es U
			unsigned char temp;
			temp = (pkt_data[16]>>1)&0x01;
			if(temp == 0){
				printf("\n Es un campo control S");
				
				
				nack = (pkt_data[16]>>5)&0x07;
				cod = (pkt_data[16]>>2)&0x03;
				printf("\n receive sequence es: %02x",nack);
				printf("\n El pull/final es: %x",(pkt_data[16]>>4)&0x01);
				printf("\n El comando es: %02x",cod);
			}
			else{
				printf("\n Es un campo control U");
				cod = (pkt_data[16]>>2)&0x03;
				cod_1 = (pkt_data[16]>>5)&0x07;
				
				printf("\n El código antes del pull/final es: %02x",cod_1);
				printf("\n El pull/final es: %x",(pkt_data[16]>>4)&0x01);
				printf("\n El código despues del pull/final es: %02x",cod);
			}
		}
		
	}else{
		//Dos bit campo control
		
		if((c_b1 = pkt_data[16]&0x01) == 0){
			printf("\n Es un campo control I");
			
			nsec=(pkt_data[16]>>1)&0x7f;
			nack=(pkt_data[17]>>1)&0x7f;
			printf("\n El pull/final es: %x",pkt_data[17]&0x01);
			printf("\n send sequence es: %02x",nsec);
			printf("\n receive sequence es: %02x",nack);
		}
		if((c_b1 = pkt_data[16]&0x01) == 1){
			//hay de dos, es S o es U
			unsigned char temp;
			temp = (pkt_data[16]>>1)&0x01;
			if(temp == 0){
				printf("\n Es un campo control S");
				
				printf("\n El pull/final es: %x",pkt_data[17]&0x01);
				cod=(pkt_data[16]>>2)&0x03;
				nack=(pkt_data[17]&0x01>>1)&0x7f;
				printf("\n El código es: %02x",cod);
				printf("\n receive sequence es: %02x",nack);
			}
			else{
				printf("\n Es un campo control U");
				
				cod=(pkt_data[16]>>2)&0x03;
				cod_1=(pkt_data[16]>>5)&0x07;
				printf("\n El código antes del pull/final es: %02x",cod_1);
				printf("\n El pull/final es: %x",(pkt_data[16]>>4)&0x01);
				printf("\n El código despues del pull/final es: %02x",cod);
			}
		}
		
	}
	
    printf("\n\n");     
    
   
}

int trama_lcc(){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s\n", source);
        return -1;
    }

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handler, NULL);
    return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
	
	struct tm *ltime;
	char timestr[16]; //Arreglo de bytes que va contener los datos en crudo 
	time_t local_tv_sec;
	int inum; 
	u_int j=0,k=0,l=0,m=0,n=0;
	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
	unsigned short off;
	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	u_int i=0;
    /*
     * Unused variable
     */
    /* print pkt timestamp and pkt len */
    /*printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);  */        
    
    /* Print the packet */
    
	FILE * flujo = fopen("datos.pcap","a");
    if(flujo == NULL){
    	perror("Error en la creacion del archivo \n");
	} else{
	    for (i=1; (i < header->caplen + 1 ) ; i++){
	        fprintf(flujo, "%.2x ", pkt_data[i-1]);
	        if ( (i % LINE_LEN) == 0) fprintf(flujo, "\n");
	    }
		fprintf(flujo, "\n");
	}
	fflush(flujo);
	fclose(flujo);
	
	if (tipo == 2054){
		for (i=1; (i < header->caplen + 1 ) ; i++)
	    {
	        printf("%.2x ", pkt_data[i-1]);
	        if ( (i % LINE_LEN) == 0) printf("\n");
	    }
	    printf("\n");
    	unsigned short h_t = (pkt_data[14]*256)+pkt_data[15];
    	unsigned short p_t = (pkt_data[16]*256)+pkt_data[17];
    	unsigned short o_c = (pkt_data[20]*256)+pkt_data[21];
    	printf("\n Hardware Type: %d   %02X %02X ",h_t,pkt_data[14],pkt_data[15]);
    	switch(h_t){
    		case 1 :
    			printf("Ethernet \n");
    		break;
    		case 6 :
    			printf("IEEE 802 Networks \n");
    		break;
    		case 7 :
    			printf("ARCNET \n");
    		break;
    		case 15 :
    			printf("Frame Relay \n");
    		break;
    		case 16 :
    			printf("Asynchronous Transfer Mode (ATM) \n");
    		break;
    		case 17 :
    			printf("HDLC \n");
    		break;
    		case 18 :
    			printf("Fibre Channel \n");
    		break;
    		case 19 :
    			printf("Asynchronous Transfer Mode (ATM) \n");
    		break;
    		case 20 :
    			printf("Serial Line \n");
    		break;
		}
    	printf("\n Protocol Type: %d   %02X %02X ",p_t,pkt_data[16],pkt_data[17]);
    	printf("\n Hardware Address Length: %d",pkt_data[18]);
    	printf("\n Protocol Address Length: %d",pkt_data[19]);
    	printf("\n OpCode: %d   %02X %02X  ",o_c,pkt_data[20],pkt_data[21]);
    	switch(o_c){
    		case 1 :
    			printf("ARP Request \n");
    		break;
    		case 2 :
    			printf("ARP Reply \n");
    		break;
    		case 3 :
    			printf("RARP Request \n");
    		break;
    		case 4 :
    			printf("RARP Reply \n");
    		break;
    	}
    	printf("\n Sender Hardware Address: ");
		for(l=22;l<28;l++){ //establecemos que bits queremos mostrar
	   		printf("%02X:",pkt_data[l]);   //arreglo que contiene a la trama en crudo
		}
		printf("\n Sender Protocol Address: ");
		for(m=28;m<32;m++){ //establecemos que bits queremos mostrar
	   		printf("%02X:",pkt_data[m]);   //arreglo que contiene a la trama en crudo
		}
		printf("\n Target Ip Address: ");
		for(n=38;n<48;n++){ //establecemos que bits queremos mostrar
	   		printf("%02X:",pkt_data[n]);   //arreglo que contiene a la trama en crudo
		}
		printf("\n");
	}else{
		printf("\n°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°\n");
		int i=0;
		/*IMPRIMIMOS LAS TRAMAS*/
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
	    
	    /* Print the packet */
	    for (i=1; (i < header->caplen + 1 ) ; i++)
	    {
	        printf("%.2x ", pkt_data[i-1]);
	        if ( (i % LINE_LEN) == 0) printf("\n");
	    }
	    printf("\n");
		/*TERMINA LA IMPRESION*/
		
		printf("Paquete IP..\n");
		
		ip_header *ih, ip;
		u_int ip_len;
		ip.ver_ihl = pkt_data[0]>>4;
		printf("Campo versión: %d, \n", ip.ver_ihl);
		if(ip.ver_ihl == 4){
			printf("IPv4\n");
		}else if(ip.ver_ihl == 6){
			printf("IPv6\n");
		}
		ip.ver_ihl = pkt_data[0]&0xf;
		printf("Longitud de encabezado ip: %d\n", ip.ver_ihl);
		ip.tos = (pkt_data[1]>>5)&0x07;
		printf("Servicios Diferenciados: ");
		switch(ip.tos){
			case 0 :
				printf("Routine, default, %03X\n",ip.tos);
			break;
			case 1 :
				printf("Priority, %03X\n",ip.tos);
			break;
			case 2 :
				printf("Inmmediate, %03X\n",ip.tos);
			break;
			case 3 :
				printf("Flash, Call signaling, %03X\n",ip.tos);
			break;
			case 4 :
				printf("Flash override, Vconfig, %03X\n",ip.tos);
			break;
			case 5 :
				printf("CRITIC/ECP, Voz, %03X\n",ip.tos);
			break;
			case 6 :
				printf("Internetwork Control, %03X\n",ip.tos);
			break;
			case 7 :
				printf("Network control, %03X\n",ip.tos);
			break;
		}
		ip.tos = (pkt_data[1])&0x03;
		printf("Notificacion de de congestionamiento explicito: ");
		switch(ip.tos){
			case 0 :
				printf("Sin Capacidad ECN (%02X)\n",ip.tos);
			break;
			case 1 :
				printf("Capacidad de transporte ECN 0 (%02X)\n",ip.tos);
			break;
			case 2 :
				printf("Capacidad de transporte ECN 1 (%02X)\n",ip.tos);
			break;
			case 3 :
				printf("Congestion encontrada, (%02X)\n",ip.tos);
			break;
			}
		ip.tlen=(pkt_data[2])+pkt_data[3];
		printf("Longitud total: %d, %02x %02x\n",ip.tlen,pkt_data[2],pkt_data[3]);
		ip.identification = (pkt_data[4]) + pkt_data[5];
		printf("Campo de Identificacion: %d, %02x %02x\n",ip.identification,pkt_data[4],pkt_data[5]);
		ip.flags_fo=(pkt_data[6]>>5)&0x07;
		printf("flags: ");
		switch(ip.flags_fo){
			case 0:
			break;
			case 1:
				printf("more (%03X)\n",ip.flags_fo);
			break;
			case 2:
				printf("dont fragment (%03X)\n",ip.flags_fo);
			break;
			case 3:
			break;
			case 4:
				printf("Unused (%03X)\n",ip.flags_fo);
		}
		off=(pkt_data[6]&0x1f)+pkt_data[7];
		printf("fragment offset: %d, (%03x %X) \n",off,(pkt_data[6]&0x1f),pkt_data[7]);
		ip.ttl=pkt_data[8];
		printf("TTL: %d \n",ip.ttl);
		ip.proto=pkt_data[9];
		printf("Tipo de protocolo: ");
		if(ip.proto == 1){
			printf("ICMP \n");
		}
		else if(ip.proto == 2){
			printf("IGMP \n");
		}
		else if(ip.proto == 6){
			printf("TCP \n");
		}
		else if(ip.proto == 17){
			printf("UDP \n");
		}else{
			printf("no visto en clase \n");
		}
		ip.crc=pkt_data[10]+pkt_data[11];
		printf("Checksum %d (%02X)\n",ip.crc,ip.crc);
		/* retireve the position of the ip header */
		ih = (ip_header *) (pkt_data + 12); //length of ethernet header
		/* print ip addresses and udp ports */
		printf("(Source) %d.%d.%d.%d (destination)-> %d.%d.%d.%d \n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
		printf("Option: [0]\n");
		printf("\n");		
	}
    
    printf("\n\n"); 
}

int capturar_tramas(){
	int s=0;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);

	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 15, packet_handler, NULL);
	pcap_close(adhandle);
}


