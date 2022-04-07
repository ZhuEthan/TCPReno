#include "backend.h"

/*
 * Param: sock - The socket to check for acknowledgements.
 * Param: seq - Sequence number to check
 *
 * Purpose: To tell if a packet (sequence number) has been acknowledged.
 *
 */
int check_ack(cmu_socket_t *sock, uint32_t seq) {
  int result;
  //while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0)
    //;
  if (sock->window.last_ack_received > seq)
    result = TRUE;
  else
    result = FALSE;
  //pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

int check_fin(cmu_socket_t *sock) {
  if (sock->fin_received > 0) {
    return TRUE;
  }
  return FALSE;
}

/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 * LISTEN {socket = 3, thread_id = 140737351677696, my_port = 15441, their_port
 = 15441, conn = {sin_family = 2, sin_port = 20796, sin_addr = {s_addr =
 33554442}, sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0,
 received_len = 0, recv_lock = {
    __data = {__lock = 1, __count = 0, __owner = 297293, __nusers = 2, __kind =
 0, __spins = 0, __elision = 0, __list = {
        __prev = 0x0, __next = 0x0}}, __size =
 "\001\000\000\000\000\000\000\000M\211\004\000\002", '\000' <repeats 26 times>,
    __align = 1}, wait_cond = {__data = {{__wseq = 2, __wseq32 = {__low = 2,
 __high = 0}}, {__g1_start = 0, __g1_start32 = {
          __low = 0, __high = 0}}, __g_refs = {2, 0}, __g_size = {0, 0},
 __g1_orig_size = 0, __wrefs = 8, __g_signals = {0, 0}},
    __size = "\002", '\000' <repeats 15 times>, "\002", '\000' <repeats 19
 times>, "\b\000\000\000\000\000\000\000\000\000\000",
    __align = 2}, sending_buf = 0x0, sending_len = 0, type = 1, send_lock =
 {__data = {__lock = 0, __count = 0, __owner = 0,
      __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list = {__prev =
 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, dying = 0, death_lock =
 {__data = {__lock = 0, __count = 0, __owner = 0,
      __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list = {__prev =
 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, window =
 {last_seq_received = 0, last_ack_received = 0, ack_lock = {
      __data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
 __spins = 0, __elision = 0, __list = {
          __prev = 0x0, __next = 0x0}}, __size = '\000' <repeats 39 times>,
 __align = 0}}} *pkt '\000'
 pkt is the received packet
 // Is to handle message and send back ACK
 */
//void handle_message(cmu_socket_t *sock, char *pkt) {
//  char *rsp;
//  uint8_t flags = get_flags(pkt);
//  //uint32_t data_len, seq;
//  uint32_t seq;
//  socklen_t conn_len = sizeof(sock->conn);
//  switch (flags) {
//  case ACK_FLAG_MASK:
//    printf("received ACK_FLAG_MASK\n");
//    /*if (get_ack(pkt) > sock->window.last_ack_received) {
//      sock->window.last_ack_received = get_ack(pkt);
//    }
//    printf("window last_ack_received becomes %d\n", get_ack(pkt));*/
//    deliverSWP(sock, pkt);
//    break;
//  case FIN_FLAG_MASK:
//    printf("received FIN_FLAG_MASK\n");
//    seq = get_seq(pkt);
//    rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), get_ack(pkt)/*ignore*/,
//                            seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
//                            ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
//    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
//           (struct sockaddr *)&(sock->conn), conn_len);
//    printf("send back ack with number %d\n", seq+1);
//    sock->fin_received = seq;
//    free(rsp);
//    break;
//  case SYN_FLAG_MASK:
//    printf("received SYN_FLAG_MASK\n");
//    seq = get_seq(pkt);
//    rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 500/*random*/,
//                            seq+1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
//                            ACK_FLAG_MASK | SYN_FLAG_MASK, 1, 0, NULL, NULL, 0);
//
//    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
//           (struct sockaddr *)&(sock->conn), conn_len);
//    printf("send back SYN|ACK with %d\n", seq+1);
//    sock->window.last_ack_received = 501;//random
//    sock->window.last_seq_received = seq;
//    free(rsp);
//    break;
//  case SYN_FLAG_MASK | ACK_FLAG_MASK:
//    printf("received SYN_FLAG_MASK/ACK_FLAG_MASK\n");
//    seq = get_seq(pkt);
//    rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 500/*ignore*/, 
//                          seq+1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, 
//                          ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
//    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
//           (struct sockaddr *)&(sock->conn), conn_len);
//    printf("send back ack with %d\n", seq+1);
//    if (get_ack(pkt) > sock->window.last_ack_received) {
//      sock->window.last_ack_received = get_ack(pkt);
//      sock->window.last_seq_received = seq;
//    }
//    free(rsp);
//    break;
//  default: // established state == NO_FLAG
//    printf("received data request\n");
//    //seq = get_seq(pkt);
//    //rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq/*ignore*/,
//    //                        seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
//    //                        ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
//    //sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
//    //       (struct sockaddr *)&(sock->conn), conn_len);
//    deliverSWP(sock, pkt);
//    //printf("send back ack with %d\n", seq+1);
//    //free(rsp);
//    //if (seq > sock->window.last_seq_received ||
//    //    (seq == 0 && sock->window.last_seq_received == 0)) {
//
//    //  sock->window.last_seq_received = seq;
//    //  data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
//    //  if (sock->received_buf == NULL) {
//    //    sock->received_buf = malloc(data_len);
//    //  } else {
//    //    sock->received_buf =
//    //        realloc(sock->received_buf, sock->received_len + data_len);
//    //  }
//    //  memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN,
//    //         data_len);
//    //  sock->received_len += data_len;
//    //}
//
//    //break;
//  }
//}

//min included and max included
int swp_in_window(uint32_t seqno, uint32_t min, uint32_t max) {
  uint32_t diff = seqno - min;
  if (diff < max - min + 1 && diff >= 0) {
    return TRUE;
  }

  return FALSE;
}

//require revist for ack different definition
// data message will be stored in array, either in client side or server side. 
void deliverSWP(cmu_socket_t *sock, char *pkt) {
  window_t* state = &(sock->window);
  uint8_t flags = get_flags(pkt);
  socklen_t conn_len = sizeof(sock->conn);
  //sender of the data
  if (flags == ACK_FLAG_MASK) {
    uint32_t ack_seq = get_ack(pkt);
    printf("received ACK_FLAG_MASK in deliverSWP with ack_seq %d\n", ack_seq);
    if (swp_in_window(ack_seq, state->last_ack_received+1, state->last_seq_sent+2)) {
      printf("in ACK_FLAG_MASK ack_seq %d is between [%d(last_ack_received), %d(last_seq_sent)] the ack_seq should be identical to the upper range\n", 
        ack_seq, state->last_ack_received+1, state->last_seq_sent+2);
      do {
        struct send_q_slot* slot;

        slot = &(state->sendQ[++(state->last_ack_received) % SWS]);
        //cancel timtout TODO;
        message_destroy(&(slot->sending_buf)); 
        //printf("message destroy successfully last_ack_received %d\n", state->last_ack_received);
        sem_post(&state->send_window_not_full); // release lock
      } while (state->last_ack_received != ack_seq);
      printSWP(sock, "sender");
    } else {
      printf("in ACK_FLAG_MASK ack_seq %d is not between [%d(last_ack_received), %d(last_seq_sent)], the ack_seq should be identical to the upper range\n", 
        ack_seq, state->last_ack_received+1, state->last_seq_sent+2);
    }
  } else if (flags == NO_FLAG) {// data
    //receiver of the data
    struct recv_q_slot* slot;

    uint32_t data_seq = get_seq(pkt);
    printf("received data request in deliverSWP, with data_seq %d\n", data_seq);
    slot = &state->recvQ[data_seq % RWS];
    if (!swp_in_window(data_seq, state->next_seq_expected, state->next_seq_expected + RWS - 1)) {
      printf("data seq %d is not in range [%d, %d]\n", data_seq, state->next_seq_expected, state->next_seq_expected+RWS-1);
      return;
    } else {
      printf("data seq %d is in range [%d, %d]\n", data_seq, state->next_seq_expected, state->next_seq_expected+RWS-1);
    }
    message_save_copy(&slot->recv_buf, pkt, get_plen(pkt)); // server side: store the coming message data for furthur reading. 
    slot->received = TRUE;
    if (data_seq == state->next_seq_expected) {
      printf("data_seq %d is equal with state->next_seq_expected in NO_FLAG\n", data_seq);
      while (slot->received) { // loop reading consecutive arrived data as much as possible. 
        uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
        if (sock->received_buf == NULL) {
          sock->received_buf = malloc(data_len);
        } else {
          sock->received_buf =
              realloc(sock->received_buf, sock->received_len + data_len);
        }
        memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN,
               data_len);
        sock->received_len += data_len;

        message_destroy(&(slot->recv_buf));
        slot->received = FALSE;
        slot = &(state->recvQ[++(state->next_seq_expected) % RWS]);
      }

      char* rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), data_seq/*ignore*/,
                              state->next_seq_expected, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                              ACK_FLAG_MASK, 1, 0, NULL, NULL, 0); // the ack is the furthest seq it has received
      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      

      printSWP(sock, "receiver");
      printf("send back ack with %d\n", state->next_seq_expected);
      message_destroy(&rsp);
    } else {
      printf("data_seq %d is not equal with state->next_seq_expected %d\n", data_seq, state->next_seq_expected);
    }
  } else if (flags == SYN_FLAG_MASK) {
    printf("received SYN_FLAG_MASK in deliverSWP\n");
    //receiver of the data
    struct recv_q_slot* slot;

    uint32_t seq = get_seq(pkt);
    slot = &state->recvQ[seq % RWS];

    /*if (!swp_in_window(seq, state->next_seq_expected, state->next_seq_expected + RWS - 1)) {
      return;
    }*/

    //message_save_copy(&slot->recv_buf, pkt, get_plen(pkt));
    slot->received = TRUE;
    state->next_seq_expected = seq + 1;
    state->last_seq_received = seq;
    state->last_seq_sent = 500;

    char* rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 500/*random*/,
                            state->next_seq_expected, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                            ACK_FLAG_MASK | SYN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
           (struct sockaddr *)&(sock->conn), conn_len);
    printSWP(sock, "receiver");
    printf("send back SYN|ACK with %d(SYN), %d(ACK)\n", 500, seq+1);
    free(rsp);
  } else if (flags == (SYN_FLAG_MASK | ACK_FLAG_MASK)) {
    printf("received SYN_FLAG_MASK/ACK_FLAG_MASK in deliverSWP (seq)%d, (ack)%d\n", get_seq(pkt), get_ack(pkt));
    // sender side double check
    uint32_t seq = get_seq(pkt);

    //if (swp_in_window(seq, state->last_ack_received+1, state->last_seq_sent+1)) {
    //printf("seq %d in swp [%d, %d]\n", seq, state->last_ack_received+1, state->last_seq_sent+1);
    //do {
    //  struct send_q_slot* slot;
    //  slot = &(state->sendQ[++(state->last_ack_received) % SWS]);
    //  printf("last_ack_received is %d\n", state->last_ack_received);
    //  //message_destroy(&(slot->sending_buf));
    //  sem_post(&state->send_window_not_full);
    //} while (state->last_ack_received != seq);

    
    char* rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 500/*ignore*/, 
                        seq+1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, 
                        ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(sock->conn), conn_len);
    printf("in SYN_FLAG_MASK/ACK_FLAG_MASK send back ack with %d\n", seq+1);
    //if (get_ack(pkt) > sock->window.last_ack_received) {
    state->last_ack_received = get_ack(pkt);
    state->last_seq_received = seq;
    state->next_seq_expected = seq + 1;
    //}
    printSWP(sock, "sender");
    free(rsp);
    //} else {
      //printf("seq %d is not in swp [%d, %d]\n", seq, state->last_ack_received+1, state->last_seq_sent+1);
    //}
  }

  printf("end of deliverSWP\n");
}

void printSWP(cmu_socket_t *sock, char* clientName) {
  printf("--------------current sliding window of %s is last_ack_received %d, last_seq_received %d, last_seq_sent %d, next_seq_expected %d\n", 
    clientName, sock->window.last_ack_received, sock->window.last_seq_received, sock->window.last_seq_sent, sock->window.next_seq_expected);
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket.
 * LISTEN:
 * {socket = 3, thread_id = 140737351677696, my_port = 15441, their_port =
15441, conn = { sin_family = 2, sin_port = 20796, sin_addr = {s_addr = 0},
    sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0, received_len
= 0, recv_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 1,
__kind = 0,
      __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 12 times>, "\001", '\000' <repeats 26 times>,
__align = 0}, wait_cond = {__data = {{__wseq = 2, __wseq32 = {__low = 2, __high
= 0}}, {__g1_start = 0,
        __g1_start32 = {__low = 0, __high = 0}}, __g_refs = {2, 0}, __g_size =
{0, 0},
      __g1_orig_size = 0, __wrefs = 8, __g_signals = {0, 0}},
    __size = "\002", '\000' <repeats 15 times>, "\002", '\000' <repeats 19
times>, "\b\000\000\0 00\000\000\000\000\000\000\000", __align = 2}, sending_buf
= 0x0, sending_len = 0, type = 1, send_lock = {__data = {__lock = 0, __count =
0, __owner = 0, __nusers = 0, __kind = 0,
      __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, dying = 0, death_lock =
{__data = {
      __lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0, __spins =
0,
      __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, window =
{last_seq_received = 0, last_ack_received = 0, ack_lock = {__data = {__lock = 0,
__count = 0, __owner = 0,
        __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list = {__prev =
0x0,
          __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0}}}
    flags = NO_WAIT

    INIT:
    {socket = 3, thread_id = 140737351677696, my_port = 40739, their_port =
15441, conn = {sin_family = 2, sin_port = 20796, sin_addr = {s_addr = 16777226},
sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0, received_len =
0, recv_lock = {
    __data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
__spins = 0, __elision = 0, __list = {__prev = 0x0,
        __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0},
wait_cond = {__data = {{__wseq = 0, __wseq32 = {
          __low = 0, __high = 0}}, {__g1_start = 0, __g1_start32 = {__low = 0,
__high = 0}}, __g_refs = {0, 0}, __g_size = {0, 0},
      __g1_orig_size = 0, __wrefs = 0, __g_signals = {0, 0}}, __size = '\000'
<repeats 47 times>, __align = 0}, sending_buf = 0x0, sending_len = 0, type = 0,
send_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0,
__kind = 0, __spins = 0,
      __elision = 0, __list = {__prev = 0x0, __next = 0x0}}, __size = '\000'
<repeats 39 times>, __align = 0}, dying = 0, death_lock = {__data = {__lock = 0,
__count = 0, __owner = 0, __nusers = 0, __kind = 0, __spins = 0, __elision = 0,
__list = {
        __prev = 0x0, __next = 0x0}}, __size = '\000' <repeats 39 times>,
__align = 0}, window = {last_seq_received = 0, last_ack_received = 0, ack_lock =
{__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
__spins = 0,
        __elision = 0, __list = {__prev = 0x0, __next = 0x0}}, __size = '\000'
<repeats 39 times>, __align = 0}}}
 */
void check_for_data(cmu_socket_t *sock, int flags) {
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  fd_set ackFD;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
    ;
  switch (flags) {
  case NO_FLAG:
    len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
                   (struct sockaddr *)&(sock->conn), &conn_len);
    break;
  case TIMEOUT:
    FD_ZERO(&ackFD);
    FD_SET(sock->socket, &ackFD);
    int nread = 0;
    
    //printf("estimated RTT is %lu, timeout is %lu, diviation is %lu\n", 
        //(sock->timeout).estimated_rtt, (sock->timeout).timeout, (sock->timeout).diviation);
    struct timeval t_eval = usecs_to_timeval((sock->timeout).timeout);
    //printf("timeout time is %ld us\n", (sock->timeout).timeout);
    if ((nread = select(sock->socket + 1, &ackFD, NULL, NULL, &t_eval) <= 0)) {
      break;
    }
  case NO_WAIT:
    len =
        recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                 (struct sockaddr *)&(sock->conn), &conn_len);
    break;
  default:
    perror("ERROR unknown flag");
  }

  if (len >= DEFAULT_HEADER_LEN) {
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, NO_FLAG,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    //handle_message(sock, pkt);
    deliverSWP(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}


void tcp_teardown_handshake(cmu_socket_t *sock) {
  uint32_t last_ack_received = sock->window.last_ack_received;

  socklen_t conn_len = sizeof(sock->conn);
  char *pkt = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), last_ack_received, 0/*ignore*/,
                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                FIN_FLAG_MASK, 1, 0, NULL, NULL, 0);

  if (sock->fin_received == 0) { // proactively init FIN. expecting ACK alone first, and then FIN from the other side
    printf("actively finish the connection\n");
    while (TRUE) {
      sendto(sock->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(sock->conn), conn_len);
      printf("actively send fin package with seq number %d \n", last_ack_received);
      check_for_data(sock, TIMEOUT);
      //printf("fin_received %d\n", sock->fin_received);
      //printf("last ack received %d, original is %d\n", sock->window.last_ack_received, last_ack_received);
      if (check_fin(sock) && check_ack(sock, last_ack_received)) {
        break;
      }
      //printf("waiting for ack and fin\n");
    }
    struct timeval start_time = get_time_stamp();
    while (TRUE) {
      printf("in the closing phase\n");
      check_for_data(sock, TIMEOUT); // TODO: change to two segment lifetimes. 
      struct timeval cur_time = get_time_stamp();
      struct timeval elapsed_time = elapsed_time_seconds(start_time, cur_time);
      if (timeval_to_usecs(elapsed_time) > 1000000) {
        break;
      }
    }
  } else { // already received fin, right side of the textbook graph. 
    printf("passively finish the connection\n");
    while (TRUE) {
      sendto(sock->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(sock->conn), conn_len);
      printf("passively send fin package with seq number %d, last_ack_received is %d\n", last_ack_received, last_ack_received);
      check_for_data(sock, TIMEOUT);
      if (check_ack(sock, last_ack_received)) {
        break;
      }
    }
  }

  printf("tear down happened\n");
  free(pkt);
}

void tcp_init_handshake(cmu_socket_t *sock) {
  struct timeval send_time = get_time_stamp();
  if (sock->type == TCP_INITIATOR) {
    socklen_t conn_len = sizeof(sock->conn);
    int syn_seq = 1000;
    sock->window.last_seq_sent = syn_seq;
    char *pkt = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), syn_seq/*random*/,
                                0/*ignore*/, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                SYN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    struct send_q_slot* slot = &sock->window.sendQ[syn_seq % SWS];
    message_save_copy(&(slot->sending_buf), pkt, DEFAULT_HEADER_LEN); 
    
    printf("send init syn with number %d\n", 1000);
    int seq = sock->window.last_ack_received;
    while (TRUE) {
      printf("init_handshake loop\n");
      sendto(sock->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr *)&(sock->conn), conn_len);
      check_for_data(sock, TIMEOUT);
      if (check_ack(sock, seq)) {
        struct timeval ack_time = get_time_stamp();
        struct timeval rtt = elapsed_time_seconds(send_time, ack_time);
        sock->timeout = next_wait_time((sock->timeout).estimated_rtt, rtt, (sock->timeout).diviation);
        printf("check_ack successfully\n");
        break;
      }
    }
    free(pkt);
  }
}

/*
 * Param: sock - The socket to use for sending data
 * Param: data - The data to be sent
 * Param: buf_len - the length of the data being sent
 *
 * Purpose: Breaks up the data into packets and sends a single
 *  packet at a time.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
//void single_send(cmu_socket_t *sock, char *data, int buf_len) {
//  printf("single_send\n");
//  char *msg;
//  char *data_offset = data;
//  int sockfd, plen;
//  size_t conn_len = sizeof(sock->conn);
//  uint32_t seq;
//
//  sockfd = sock->socket;
//  if (buf_len > 0) {
//    while (buf_len != 0) {
//      seq = sock->window.last_ack_received;
//      if (buf_len <= MAX_DLEN) {
//        plen = DEFAULT_HEADER_LEN + buf_len;
//        // map to the TCP package:
//        // https://book.systemsapproach.org/e2e/tcp.html#segment-format
//        msg = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
//                                seq/*ignore*/, DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0,
//                                NULL, data_offset, buf_len);
//        buf_len = 0;
//      } else {
//        plen = DEFAULT_HEADER_LEN + MAX_DLEN;
//        msg = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
//                                seq/*ignore*/, DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0,
//                                NULL, data_offset, MAX_DLEN);
//        buf_len -= MAX_DLEN;
//      }
//      struct timeval send_time = get_time_stamp();
//      while (TRUE) {
//        printf("waiting ack in single_send\n");
//        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
//        //sendSWP(sock, msg, plen);
//        printf("send msg with seq number %d\n", seq);
//        check_for_data(sock, TIMEOUT);
//        if (check_ack(sock, seq)) {
//          struct timeval ack_time = get_time_stamp();
//          struct timeval rtt = elapsed_time_seconds(send_time, ack_time);
//          sock->timeout = next_wait_time((sock->timeout).estimated_rtt, rtt, (sock->timeout).diviation);
//          fprintf(sock->debug_file, "rtt is %ld us\n", timeval_to_usecs(rtt));
//          fprintf(sock->debug_file, "timeout time is %ld us, diviation is %ld us, estimated_rtt is %ld us\n", 
//                sock->timeout.timeout, sock->timeout.diviation, sock->timeout.estimated_rtt);
//          break;
//        }
//      }
//      data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
//    }
//  }
//}


// doesn't resend yet
void sendSWP(cmu_socket_t *sock, char* data, int buf_len) {
  window_t* state = &(sock->window);
  struct send_q_slot *slot;
  
  char* data_offset = data;

  //haven't dealt with buf_len greater than MAX_LEN
  uint32_t plen = DEFAULT_HEADER_LEN + buf_len;

  printSWP(sock, "sender in sendSWP1");
  uint32_t seq = ++(state->last_seq_sent);
  printSWP(sock, "sender in sendSWP2");
  slot = &(state->sendQ[seq % SWS]);

  // map to the TCP package:
  // https://book.systemsapproach.org/e2e/tcp.html#segment-format
  char* msg = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                                seq/*ignore*/, DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0,
                                NULL, data_offset, buf_len);

  sem_wait(&(state->send_window_not_full)); //decrease the lock counter
  message_save_copy(&(slot->sending_buf), msg, plen); //every message being sent is also stored
  //haven't dealt with timeout;

  size_t conn_len = sizeof(sock->conn);
  sendto(sock->socket, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
  printf("sendSWP data with seq %d\n", seq);
}



/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side.
 *
 * Listen:
 * {socket = 3, thread_id = 140737351677696, my_port = 15441,
  their_port = 15441, conn = {sin_family = 2, sin_port = 20796, sin_addr = {
      s_addr = 0}, sin_zero = "\000\000\000\000\000\000\000"}, received_buf =
0x0, received_len = 0, recv_lock = {__data = {__lock = 0, __count = 0, __owner =
0,
      __nusers = 1, __kind = 0, __spins = 0, __elision = 0, __list = {
        __prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 12 times>, "\001", '\000' <repeats 26 times>,
    __align = 0}, wait_cond = {__data = {{__wseq = 2, __wseq32 = {__low = 2,
          __high = 0}}, {__g1_start = 0, __g1_start32 = {__low = 0, __high =
0}},
      __g_refs = {2, 0}, __g_size = {0, 0}, __g1_orig_size = 0, __wrefs = 8,
      __g_signals = {0, 0}},
    __size = "\002", '\000' <repeats 15 times>, "\002", '\000' <repeats 19
times>, " \b\000\000\000\000\000\000\000\000\000\000", __align = 2}, sending_buf
= 0x0, sending_len = 0, type = 1, send_lock = {__data = {__lock = 0, __count =
0,
      __owner = 0, __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list
= {
        __prev = 0x0, __next = 0x0}}, __size = '\000' <repeats 39 times>,
    __align = 0}, dying = 0, death_lock = {__data = {__lock = 1, __count = 0,
      __owner = 216574, __nusers = 1, __kind = 0, __spins = 0, __elision = 0,
      __list = {__prev = 0x0, __next = 0x0}},
    __size = "\001\000\000\000\000\000\000\000\376M\003\000\001", '\000'
<repeats 26 times>, __align = 1}, window = {last_seq_received = 0,
last_ack_received = 0, ack_lock = {__data = {__lock = 0, __count = 0, __owner =
0, __nusers = 0,
        __kind = 0, __spins = 0, __elision = 0, __list = {__prev = 0x0,
          __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0}}}
 *  INIT
 * {socket = 3, thread_id = 140737351677696, my_port = 40739, their_port =
15441, conn = {sin_family = 2, sin_port = 20796, sin_addr = {s_addr = 16777226},
sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0, received_len =
0, recv_lock = {
    __data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
__spins = 0, __elision = 0, __list = {__prev = 0x0,
        __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0},
wait_cond = {__data = {{__wseq = 0, __wseq32 = {
          __low = 0, __high = 0}}, {__g1_start = 0, __g1_start32 = {__low = 0,
__high = 0}}, __g_refs = {0, 0}, __g_size = {0, 0},
      __g1_orig_size = 0, __wrefs = 0, __g_signals = {0, 0}}, __size = '\000'
<repeats 47 times>, __align = 0}, sending_buf = 0x0, sending_len = 0, type = 0,
send_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0,
__kind = 0, __spins = 0,
      __elision = 0, __list = {__prev = 0x0, __next = 0x0}}, __size = '\000'
<repeats 39 times>, __align = 0}, dying = 0, death_lock = {__data = {__lock = 0,
__count = 0, __owner = 0, __nusers = 0, __kind = 0, __spins = 0, __elision = 0,
__list = {
        __prev = 0x0, __next = 0x0}}, __size = '\000' <repeats 39 times>,
__align = 0}, window = {last_seq_received = 0, last_ack_received = 0, ack_lock =
{__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
__spins = 0,
        __elision = 0, __list = {__prev = 0x0, __next = 0x0}}, __size = '\000'
<repeats 39 times>, __align = 0}}}
 *
 * Type could be used to distinguish
 *
 */
void *begin_backend(void *in) {
  cmu_socket_t *dst = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  char *data;

  printf("begin_backend\n");

  tcp_init_handshake(in);

  // NOTICE this forever loop.
  while (TRUE) {
    while (pthread_mutex_lock(&(dst->death_lock)) != 0)
      ;
    death = dst->dying;
    pthread_mutex_unlock(&(dst->death_lock));

    while (pthread_mutex_lock(&(dst->send_lock)) != 0)
      ;
    buf_len = dst->sending_len;

    if (death && buf_len == 0)
      break;

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, dst->sending_buf, buf_len);
      dst->sending_len = 0;
      dst->sending_buf = NULL;
      pthread_mutex_unlock(&(dst->send_lock));
      //single_send(dst, data, buf_len);
      sendSWP(dst, data, buf_len);
      free(data);
    } else
      pthread_mutex_unlock(&(dst->send_lock));

    check_for_data(dst, NO_WAIT);

    while (pthread_mutex_lock(&(dst->recv_lock)) != 0)
      ;

    if (dst->received_len > 0)
      send_signal = TRUE;
    else
      send_signal = FALSE;
    pthread_mutex_unlock(&(dst->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(dst->wait_cond));
    }
  }

  tcp_teardown_handshake(dst);

  pthread_exit(NULL);
  return NULL;
}