#ifndef _CMU_BACK_H_
#define _CMU_BACK_H_

#include <semaphore.h>
#include "cmu_tcp.h"
#include "global.h"
#include "cmu_packet.h"
#include "handler.h"
#include "util.h"
#include "hashmap.h"

int check_ack(cmu_socket_t * dst, uint32_t seq);
void check_for_data(cmu_socket_t * dst, int flags);
void * begin_backend(void * in);
void deliverSWP(cmu_socket_t *sock, char *pkt);
void sendSWP(cmu_socket_t *sock, char* data, int buf_len);
void printSWP(cmu_socket_t *sock, char* client);

#endif
