#ifndef _GRADING_H_
#define _GRADING_H_

//window variables
#define WINDOW_INITIAL_WINDOW_SIZE 1
#define WINDOW_INITIAL_SSTHRESH 64
#define WINDOW_INITIAL_RTT 3000	// ms
#define WINDOW_INITIAL_ADVERTISED 1 //max packet sizes


//packet lengths
#define MAX_DLEN 1373
#define MAX_LEN 1400

//socket types
#define TCP_INITATOR 0
#define TCP_LISTENER 1

//Max TCP Buffer
#define MAX_NETWORK_BUFFER 65535 // 2^16 bytes


#endif