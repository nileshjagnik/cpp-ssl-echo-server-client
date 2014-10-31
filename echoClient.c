#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif  /* INADDR_NONE */

extern int	errno;

int	TCPecho(const char *host, const char *portnum);
int	errexit(const char *format, ...);
int	connectsock(const char *host, const char *portnum);

#define	LINELEN		128

/*------------------------------------------------------------------------
 * main - TCP client for ECHO service
 *------------------------------------------------------------------------
 */
int main(int argc, char *argv[])
{
	char	*host = "localhost";	/* host to use if none supplied	*/
	char	*portnum = "5004";	/* default server port number	*/
    int r;
    
	switch (argc) {
	case 1:
		host = "localhost";
		break;
	case 3:
		portnum = argv[2];
		/* FALL THROUGH */
	case 2:
		host = argv[1];
		break;
	default:
		fprintf(stderr, "usage: ./client [host [port]]\n");
		exit(1);
	}
	
	// ssl method to be used
	const SSL_METHOD *meth;
	
	// ssl context structure
	SSL_CTX *ctx;
	
	// ssl struct
	SSL *ssl;
	
	// BIO struct
	BIO *sbio; 
	
	// load encryption & hash algorithms for SSL
	SSL_library_init();
	
	// load the error strings for good error reporting            
    SSL_load_error_strings();
    
    // create context
    meth = SSLv3_client_method();
    ctx=SSL_CTX_new(meth);
	
	// ca certificate
	if (!SSL_CTX_load_verify_locations(ctx,"cacert.pem",NULL)) { 
	    errexit("Could not load CA cert\n");
	}
	
	SSL_CTX_set_verify_depth(ctx, 1);
	
	//ssl initialize
	ssl = SSL_new(ctx);
	
	// talk to the server
	char	buf[LINELEN+1];		// buffer for one line of text
	int	s, n;			// socket descriptor, read count
	int	outchars, inchars;	// characters sent and received	
    
    //  tcp connection
	s = connectsock(host, portnum);
    
    // enable ssl communication
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    
    
    
    if((r=SSL_connect(ssl))<=0) {
        errexit("SSL connect failed\n%d\n",r);
    }
    
    if(SSL_get_peer_certificate(ssl) != NULL){
        if(SSL_get_verify_result(ssl) != X509_V_OK) {
            errexit("Could not verify peer certificate\n");    
        }
    }
    else {
        errexit("Could not get peer certificate\n");
    }
 
	while (fgets(buf, sizeof(buf), stdin)) {
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		(void) SSL_write(ssl, buf, outchars);

		/* read it back */
		for (inchars = 0; inchars < outchars; inchars+=n ) {
			n = SSL_read(ssl, &buf[inchars], outchars - inchars);
			if (n < 0)  {
			    errexit("socket read failed: %s\n", strerror(errno));
			}
				
		}
		fputs(buf, stdout);
	}
	(void) close(s);
	SSL_shutdown(ssl);
    SSL_free(ssl);
	
	
	exit(0);
}

/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
int errexit(const char *format, ...)
{
        va_list args;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        exit(1);
}

/*------------------------------------------------------------------------
 * connectsock - allocate & connect a socket using TCP 
 *------------------------------------------------------------------------
 */
int connectsock(const char *host, const char *portnum)
/*
 * Arguments:
 *      host      - name of host to which connection is desired
 *      portnum   - server port number
 */
{
        struct hostent  *phe;   /* pointer to host information entry    */
        struct sockaddr_in sin; /* an Internet endpoint address         */
        int     s;              /* socket descriptor                    */


        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Map host name to IP address, allowing for dotted decimal */
        if ( phe = gethostbyname(host) )
                memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
        else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
                errexit("can't get \"%s\" host entry\n", host);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
                errexit("can't create socket: %s\n", strerror(errno));

    /* Connect the socket */
        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't connect to %s.%s: %s\n", host, portnum,
                        strerror(errno));
        return s;
}
