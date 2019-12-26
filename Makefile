all: web_proxy 

web_proxy: main.o 
	g++ -g -w -o web_proxy main.o -lssl -lcrypto -lpthread

main.o:
	g++ -g -w -c -o main.o main.cpp

clean:
	rm -f web_proxy
	rm -f *.o
