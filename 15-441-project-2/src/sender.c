#include "cmu_tcp.h"

void functionality(cmu_socket_t  * sock){
    char buf[2000];
    FILE *fp;
    int read;

    fp = fopen("./test_20MB_file", "rb");
    read = 1;
    while(read > 0){
        read = fread(buf, 1, 1000, fp);
        printf("read %d\n", read);
	if(read > 0) cmu_write(sock, buf, read);
    }

    fclose(fp);
}


int main(int argc, char **argv) {
    int portno;
    char *serverip;
    cmu_socket_t socket;

    if(argc != 2){
        printf("Incorrect number of args\n");
	return EXIT_FAILURE;
    }

    serverip = "10.0.0.1";
    portno = (atoi(argv[1]) == 441) ? 15441 : 15641;


    if(cmu_socket(&socket, TCP_INITATOR, portno, serverip) < 0)
        exit(EXIT_FAILURE);

    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}