LDLIBS += -lpcap

all: wifi-jammer  

wifi-jammer: wifi-jammer.o
	g++ -o wifi-jammer wifi-jammer.o libiw.so.29 -lm -lpcap -pthread 

wifi-jammer.o: 
	g++ -c wifi-jammer.cpp 

clean:
	rm -f wifi-jammer  *.o
