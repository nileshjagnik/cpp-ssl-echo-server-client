
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define	QLEN		  32	/* maximum connection queue length	*/
#define	BUFSIZE		4096
#define MAXCLI      100

extern int	errno;
int		errexit(const char *format, ...);
int		passivesock(const char *portnum, int qlen);
int		echo(SSL *ss);

/*------------------------------------------------------------------------
 * main - Concurrent TCP server for ECHO service
 *------------------------------------------------------------------------
 */
int main(int argc, char *argv[])
{
	char	*portnum = "5004";	/* Standard server port number	*/
	struct sockaddr_in fsin;	/* the from address of a client	*/
	int	msock,r;			/* master server socket		*/
	fd_set	rfds;			/* read file descriptor set	*/
	fd_set	afds;			/* active file descriptor set	*/
	unsigned int	alen;		/* from-address length		*/
	int	fd, nfds,i;
	
	switch (argc) {
	case	1:
		break;
	case	2:
		portnum = argv[1];
		break;
	default:
		errexit("usage: ./server [port]\n");
	}
	// array of ssl structures
	SSL *ssl_arr[MAXCLI];
	
	// array of file descriptors
	int fd_arr[MAXCLI];
	
    // current number of client
    int num_clients=0;
	
    // tcp connection
    msock = passivesock(portnum, QLEN);
    
	nfds = getdtablesize();
	FD_ZERO(&afds);
	FD_SET(msock, &afds);

	while (1) {
		memcpy(&rfds, &afds, sizeof(rfds));

		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0,
				(struct timeval *)0) < 0)
			errexit("select: %s\n", strerror(errno));
		if (FD_ISSET(msock, &rfds)) {
		    // ssl method to be used
	        const SSL_METHOD *meth;
	
		    // ssl context structure
	        SSL_CTX *ctx;
	
	        // ssl struct
	        SSL *ssl;
	
	        // BIO struct
	        BIO *sbio = NULL;
	
	        // load encryption & hash algorithms for SSL
	        SSL_library_init();
	
	        // load the error strings for good error reporting            
            SSL_load_error_strings();
            
            // create context
            meth = SSLv3_server_method();
            ctx=SSL_CTX_new(meth);
            
            // server certificate
            if( SSL_CTX_use_certificate_file(ctx,"server.cert",SSL_FILETYPE_PEM) <= 0) {
                errexit("Unable to load Server certificate\n");
            }
            // server private key
            if (SSL_CTX_use_PrivateKey_file(ctx, "server_priv.key", SSL_FILETYPE_PEM) <= 0) {
                errexit("Unable to load Server Private Key\n");
            }
            // ssl initialize
            ssl = SSL_new(ctx);
			int	ssock;
			alen = sizeof(fsin);
			ssock = accept(msock, (struct sockaddr *)&fsin, &alen);
			sbio = BIO_new_socket(ssock, BIO_NOCLOSE);
            SSL_set_bio(ssl, sbio, sbio);
			if((r=SSL_accept(ssl))<=0) {
                errexit("SSL accept failed\n%d\n",r);
            }
			if (ssock < 0)
				errexit("accept: %s\n",
					strerror(errno));
			FD_SET(ssock, &afds);
			ssl_arr[num_clients]=ssl;
			fd_arr[num_clients]=ssock;
			num_clients++;
			if(num_clients == MAXCLI) {
			    errexit("Cant handle more than 100 clients");
			}
		}
		for (fd=0; fd<nfds; ++fd)
			if (fd != msock && FD_ISSET(fd, &rfds)) {
			    // ssl struct
	            SSL *ssl;
	            int index;
	            // BIO struct
	            BIO *sbio = NULL;
	            for(i=0;i<num_clients;i++) {
	                if (fd_arr[i] == fd) {
	                    ssl = ssl_arr[i];
	                    index = i;
	                    break;
	                }
	            }
			    sbio = BIO_new_socket(fd, BIO_NOCLOSE);
                SSL_set_bio(ssl, sbio, sbio);
				if (echo(ssl) == 0) {
				    fd_arr[index] = -1;
				    SSL_shutdown(ssl);
				    SSL_free(ssl);
				    (void) close(fd);
					FD_CLR(fd, &afds);
				}
			}
	}
}

/*------------------------------------------------------------------------
 * echo - echo one buffer of data, returning byte count
 *------------------------------------------------------------------------
 */
int echo(SSL *ssl)
{
	char	buf[BUFSIZ];
	int	cc;

	cc = SSL_read(ssl, buf, sizeof buf);
	if (cc < 0)
		errexit("echo read: %s\n", strerror(errno));
	if (cc && SSL_write(ssl, buf, cc) < 0)
		errexit("echo write: %s\n", strerror(errno));
	return cc;
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
 * passivesock - allocate & bind a server socket using TCP
 *------------------------------------------------------------------------
 */
int passivesock(const char *portnum, int qlen)
/*
 * Arguments:
 *      portnum   - port number of the server
 *      qlen      - maximum server request queue length
 */
{
        struct sockaddr_in sin; /* an Internet endpoint address  */
        int     s;              /* socket descriptor             */

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;

    /* Map port number (char string) to port number (int) */
        if ((sin.sin_port=htons((unsigned short)atoi(portnum))) == 0)
                errexit("can't get \"%s\" port number\n", portnum);

    /* Allocate a socket */
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0)
            errexit("can't create socket: %s\n", strerror(errno));

    /* Bind the socket */
        if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            fprintf(stderr, "can't bind to %s port: %s; Trying other port\n",
                portnum, strerror(errno));
            sin.sin_port=htons(0); /* request a port number to be allocated
                                   by bind */
            if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                errexit("can't bind: %s\n", strerror(errno));
            else {
                int socklen = sizeof(sin);

                if (getsockname(s, (struct sockaddr *)&sin, &socklen) < 0)
                        errexit("getsockname: %s\n", strerror(errno));
                printf("New server port number is %d\n", ntohs(sin.sin_port));
            }
        }

        if (listen(s, qlen) < 0)
            errexit("can't listen on %s port: %s\n", portnum, strerror(errno));
        return s;
}

