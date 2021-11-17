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
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0)
    ;
  if (sock->window.last_ack_received > seq)
    result = TRUE;
  else
    result = FALSE;
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void handle_message(cmu_socket_t *sock, char *pkt) {
  char *rsp;
  uint8_t flags = get_flags(pkt);
  uint32_t data_len, seq;
  socklen_t conn_len = sizeof(sock->conn);
  switch (flags) {
  case ACK_FLAG_MASK:
    if (get_ack(pkt) > sock->window.last_ack_received)
      sock->window.last_ack_received = get_ack(pkt);
    //ADDED by zhyisong
    if (get_plen(pkt) > DEFAULT_HEADER_LEN) {
      seq = get_seq(pkt);
      data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
      rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                            seq+data_len, DEFAULT_HEADER_LEN, data_len,
                            ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
           (struct sockaddr *)&(sock->conn), conn_len);
      free(rsp);  
    }
    break;
  default://SYN MASK?
    //zhyisongTODO: Sending ack back to the sock -- checkpoint 1 place
    seq = get_seq(pkt);
    /*rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                            seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                            ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);*/
    rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                            seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                            ACK_FLAG_MASK|SYN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0,
           (struct sockaddr *)&(sock->conn), conn_len);
    free(rsp);

    if (seq > sock->window.last_seq_received ||
        (seq == 0 && sock->window.last_seq_received == 0)) {

      sock->window.last_seq_received = seq;
      data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
      if (sock->received_buf == NULL) {
        sock->received_buf = malloc(data_len);
      } else {
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + data_len);
      }
      memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN,
             data_len);
      sock->received_len += data_len;
    }

    break;
  }
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket.
 * LISTEN:
 * {socket = 3, thread_id = 140737351677696, my_port = 15441, their_port = 15441, conn = {
    sin_family = 2, sin_port = 20796, sin_addr = {s_addr = 0},
    sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0, received_len = 0,
  recv_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 1, __kind = 0,
      __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 12 times>, "\001", '\000' <repeats 26 times>, __align = 0},
  wait_cond = {__data = {{__wseq = 2, __wseq32 = {__low = 2, __high = 0}}, {__g1_start = 0,
        __g1_start32 = {__low = 0, __high = 0}}, __g_refs = {2, 0}, __g_size = {0, 0},
      __g1_orig_size = 0, __wrefs = 8, __g_signals = {0, 0}},
    __size = "\002", '\000' <repeats 15 times>, "\002", '\000' <repeats 19 times>, "\b\000\000\0
00\000\000\000\000\000\000\000", __align = 2}, sending_buf = 0x0, sending_len = 0, type = 1,
  send_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0,
      __spins = 0, __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, dying = 0, death_lock = {__data = {
      __lock = 0, __count = 0, __owner = 0, __nusers = 0, __kind = 0, __spins = 0,
      __elision = 0, __list = {__prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 39 times>, __align = 0}, window = {last_seq_received = 0,
    last_ack_received = 0, ack_lock = {__data = {__lock = 0, __count = 0, __owner = 0,
        __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list = {__prev = 0x0,
          __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0}}}
    flags = NO_WAIT
 */
void check_for_data(cmu_socket_t *sock, int flags) {
  char hdr[DEFAULT_HEADER_LEN];
  char *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  fd_set ackFD;
  struct timeval time_out;
  time_out.tv_sec = 3;
  time_out.tv_usec = 0;

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
    if (select(sock->socket + 1, &ackFD, NULL, NULL, &time_out) <= 0) {
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
    printf("len >= HEADER_LEN\n");
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, NO_FLAG,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
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
void single_send(cmu_socket_t *sock, char *data, int buf_len) {
  char *msg;
  char *data_offset = data;
  int sockfd, plen;
  size_t conn_len = sizeof(sock->conn);
  uint32_t seq;

  sockfd = sock->socket;
  //in Listen mode starting phase, buf_len is 0. 
  if (buf_len > 0) {
    while (buf_len != 0) {
      seq = sock->window.last_ack_received;
      if (buf_len <= MAX_DLEN) {
        plen = DEFAULT_HEADER_LEN + buf_len;
        //map to the TCP package: https://book.systemsapproach.org/e2e/tcp.html#segment-format
        msg = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                                seq, DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0,
                                NULL, data_offset, buf_len);
        buf_len = 0;
      } else {
        plen = DEFAULT_HEADER_LEN + MAX_DLEN;
        msg = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq,
                                seq, DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0,
                                NULL, data_offset, MAX_DLEN);
        buf_len -= MAX_DLEN;
      }
      while (TRUE) {
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (check_ack(sock, seq))
          break;
      }
      data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
    }
  }
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
      s_addr = 0}, sin_zero = "\000\000\000\000\000\000\000"}, received_buf = 0x0,
  received_len = 0, recv_lock = {__data = {__lock = 0, __count = 0, __owner = 0,
      __nusers = 1, __kind = 0, __spins = 0, __elision = 0, __list = {
        __prev = 0x0, __next = 0x0}},
    __size = '\000' <repeats 12 times>, "\001", '\000' <repeats 26 times>,
    __align = 0}, wait_cond = {__data = {{__wseq = 2, __wseq32 = {__low = 2,
          __high = 0}}, {__g1_start = 0, __g1_start32 = {__low = 0, __high = 0}},
      __g_refs = {2, 0}, __g_size = {0, 0}, __g1_orig_size = 0, __wrefs = 8,
      __g_signals = {0, 0}},
    __size = "\002", '\000' <repeats 15 times>, "\002", '\000' <repeats 19 times>, "
\b\000\000\000\000\000\000\000\000\000\000", __align = 2}, sending_buf = 0x0,
  sending_len = 0, type = 1, send_lock = {__data = {__lock = 0, __count = 0,
      __owner = 0, __nusers = 0, __kind = 0, __spins = 0, __elision = 0, __list = {
        __prev = 0x0, __next = 0x0}}, __size = '\000' <repeats 39 times>,
    __align = 0}, dying = 0, death_lock = {__data = {__lock = 1, __count = 0,
      __owner = 216574, __nusers = 1, __kind = 0, __spins = 0, __elision = 0,
      __list = {__prev = 0x0, __next = 0x0}},
    __size = "\001\000\000\000\000\000\000\000\376M\003\000\001", '\000' <repeats 26
 times>, __align = 1}, window = {last_seq_received = 0, last_ack_received = 0,
    ack_lock = {__data = {__lock = 0, __count = 0, __owner = 0, __nusers = 0,
        __kind = 0, __spins = 0, __elision = 0, __list = {__prev = 0x0,
          __next = 0x0}}, __size = '\000' <repeats 39 times>, __align = 0}}}
 * 
 */
void *begin_backend(void *in) {
  cmu_socket_t *dst = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  char *data;

  printf("begin_backend\n");

//NOTICE this forever loop. 
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
      free(dst->sending_buf);
      dst->sending_buf = NULL;
      pthread_mutex_unlock(&(dst->send_lock));
      single_send(dst, data, buf_len);
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

  pthread_exit(NULL);
  return NULL;
}