#include "cmu_tcp.h"

void functionality(cmu_socket_t  * sock, int portno){
    char buf[9898];
    FILE *fp;
    int n;
    uint32_t file_size = 20971520;

    uint32_t read = 0;

    if(portno == 15441){
        fp = fopen("./15441_output", "w+");
    }
    else{
        fp = fopen("./15641_output", "w+");
    }

    while(read < file_size){
        n = cmu_read(sock, buf, 9898, NO_FLAG);
	read += n;
	fwrite(buf, 1, n, fp);
    }

    fclose(fp);
}


int main(int argc, char **argv) {
    int portno;
    char *serverip;
    cmu_socket_t socket;


    serverip = "10.0.0.1";

    if(argc != 2){
        printf("Incorrect number of args\n");
	exit(EXIT_FAILURE);
    }

    portno = (atoi(argv[1]) == 441) ? 15441 : 15641;

    if(cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) exit(EXIT_FAILURE);

    functionality(&socket, portno);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}