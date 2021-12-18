#include "grading.h"

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2
#define END 3

#define TRUE 1
#define FALSE 0

#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
	uint32_t last_seq_received;
	uint32_t last_ack_received;
	pthread_mutex_t ack_lock;
} window_t;


typedef struct {
	long estimated_rtt;
	long diviation;
	long timeout;
} tcp_timeout;


typedef struct {
	tcp_timeout timeout;
	int socket;   
	pthread_t thread_id;
	uint16_t my_port;
	uint16_t their_port;
	struct sockaddr_in conn;
	char* received_buf;
	int received_len;
	pthread_mutex_t recv_lock;
	pthread_cond_t wait_cond;
	char* sending_buf;
	int sending_len;
	int type;
	pthread_mutex_t send_lock;
	int dying;
	pthread_mutex_t death_lock;
	int fin_received;
	pthread_mutex_t fin_seq_sent_lock;
	window_t window;
} cmu_socket_t;

#endif