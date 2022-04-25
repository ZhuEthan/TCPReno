#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how 
 *  the sockets will be used.
 * sock: 
 * {socket = 3, thread_id = 140737351677696, my_port = 15441, their_port = 15441, conn = {sin_family = 2,
    sin_port = 20796, sin_addr = {s_addr = 0}, sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0,
  received_len = 0, recv_lock = {__data = {__lock = 1, __count = 0, __owner = 223750, __nusers = 1, __kind = 0,
      __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = "\001\000\000\000\000\000\000\000\006j\003\000\001", '\000' <repeats 26 times>, __align = 1},
  wait_cond = {__data = {{__wseq = 0, __wseq32 = {__low = 0, __high = 0}}, {__g1_start = 0, __g1_start32 = {
          __low = 0, __high = 0}}, __g_refs = {0, 0}, __g_size = {0, 0}, __g1_orig_size = 0, __wrefs = 0,
      __g_signals = {0, 0}}, __size = '\000' <repeats 47 times>, __align = 0}, sending_buf = 0x0,
  sending_len = 0, type = 1, send_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0,
      __kind = 0, __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, dying = 0, death_lock = {__data = {__lock = 0,
      __count = 0, __owner = 0, __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list = {__prev = 0x0,
        __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0}, window = {last_seq_received = 0,
    last_ack_received = 0, ack_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
        __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}}, __size = '\000' <repeats 39 times>,
      __align = 0}}}
 */
void functionality(cmu_socket_t  * sock){
    char buf[9898];
    FILE *fp;
    int n;
    n = cmu_read(sock, buf, 200, NO_FLAG);
    //printf("R: %s\n", buf);
    printf("R: ");
    for(int i = 0; i < n; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
    printf("N: %d\n", n);
    cmu_write(sock, "hi there from server1", 22);
    cmu_read(sock, buf, 200, NO_FLAG);
    cmu_write(sock, "hi there from server2", 22);

    sleep(5);
    n = cmu_read(sock, buf, 9898, NO_FLAG);
    printf("R: ");
    for(int i = 0; i < n; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
    printf("N: %d\n", n);
    fp = fopen("/vagrant/15-441-project-2/tests/file.c", "w+");
    //each item 1 bytes, n items. 
    fwrite(buf, 1, n, fp);

}


/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample listener for the TCP connection.
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


    if(cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
        exit(EXIT_FAILURE);

    functionality(&socket);

    printf("in main thread\n");
    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}
