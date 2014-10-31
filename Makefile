all: build

build:
	gcc echoServer.c -o server -lssl -lcrypto
	gcc echoClient.c -o client -lssl -lcrypto

clean:
	rm -rf *~
	rm client
	rm server
