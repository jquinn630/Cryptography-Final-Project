all: client server keygen

client: client.o
	g++ client.o -o client -lcrypto

client.o: client.cpp
	g++ client.cpp -c 

server: server.o
	g++ server.o -o server -lsqlite3 -lcrypto

server.o: server.cpp
	g++ server.cpp -c 

keygen: keygen.o
	g++ keygen.o -o keygen -lcrypto

keygen.o: keygen.cpp
	g++ keygen.cpp -c

clean:
	rm -f *.o client server keygen
