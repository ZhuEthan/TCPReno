#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how 
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t  * sock){
    char buf[9898];
    int read;
    FILE *fp;

    int n;

    cmu_write(sock, "hi there from client", 21);
    cmu_write(sock, "hi there2 from client", 22);
    cmu_write(sock, "hi there3 from client", 22);
    cmu_write(sock, "hi there4 from client", 22);
    cmu_write(sock, "hi there5 from client", 22);
    cmu_write(sock, "hi there6 from client", 22);
    n = cmu_read(sock, buf, 200, NO_FLAG);
    printf("client: n is number %d\n", n);
    for(int i = 0; i < n; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");

    cmu_write(sock, "hi there7 from client", 22);
    n = cmu_read(sock, buf, 200, NO_FLAG);
    //printf("R: %s\n", buf);
    for(int i = 0; i < n; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
    read = cmu_read(sock, buf, 200, NO_WAIT);
    printf("Client Read: %d\n", read);

    fp = fopen("/vagrant/15-441-project-2/src/cmu_tcp.c", "rb");
    read = 1;
    while(read > 0){
        read = fread(buf, 1, 2000, fp);
        if(read > 0) {
            printf("Client reading file\n");
            cmu_write(sock, buf, read);
        }
    }
    
}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample initator for the TCP connection to a
 *  listener.
 *
 */
int main(int argc, char **argv) {
	int portno;
    char *serverip;
    char *serverport;
    cmu_socket_t socket;
    
    serverip = getenv("server15441");
    if (serverip) ;
    else {
        serverip = "10.0.0.1";
    }

    serverport = getenv("serverport15441");
    if (serverport) ;
    else {
        serverport = "15441";
    }
    portno = (unsigned short)atoi(serverport);


    if(cmu_socket(&socket, TCP_INITIATOR, portno, serverip) < 0)
        exit(EXIT_FAILURE);
    
    //TODO: It will forever loop without funcionality
    //sleep(30000);
    functionality(&socket);
    //sleep(5);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}
