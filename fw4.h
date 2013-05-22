/*
 * fw4.h
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#ifndef FW4_H_
#define FW4_H_

#include "global.h"

// the 3 protocols we will work with
typedef enum {
	PROT_ICMP = 1, PROT_TCP = 6, PROT_UDP = 17,
} prot_t;

// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE = -1,
	REASON_NOT_IPV4 = -2,
	REASON_PROT_NOT_ENFORCED = -3,
	REASON_NO_MATCHING_RULE = -4,
	REASON_OUT_OF_STATE = -5,
	REASON_CONNECTION_TABLE_FULL = -6,
	REASON_XMAS_PACKET = -7,
} reason_t;

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES = 0, MINOR_LOG = 1, MINOR_CONN_TAB = 2,
} minor_t;

// configuration bits
typedef enum {
	FW_CONFIG_ACTIVE = 0x01,
	FW_CONFIG_ICMP = 0x02,
	FW_CONFIG_TCP = 0x04,
	FW_CONFIG_UDP = 0x08,
	FW_CONFIG_CONN_TRACK = 0x10,
	FW_CONFIG_CLEANUP_ACCEPT = 0x20,
} config_t;

// rule base
typedef struct {
	__u8 protocol; // values from: prot_t
	__u8 src_mask; // valid values: 0-32
	__u8 dst_mask; // valid values: 0-32
	__u8 action;   // valid values: NF_ACCEPT, NF_DROP
	__be16 src_port;
	__be16 dst_port;
	__be32 src_ip;
	__be32 dst_ip;
} rule_t;

// auxiliary struct for your convenience.
typedef struct {
	__u8 action;  // valid values: NF_ACCEPT, NF_DROP
	int reason;  // values from: reason_t
} decision_t;

// logging
typedef struct {
	unsigned long modified;     // seconds since epoch
	unsigned char protocol;     // values from: prot_t
	unsigned char action;       // valid values: NF_ACCEPT, NF_DROP
	unsigned char hooknum;      // as received from netfilter hook
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	signed int reason;       // rule#, or values from: reason_t
	unsigned int count;        // counts this line's hits
} log_row_t;

// connection tracking
typedef struct {
	unsigned int cli_ip;      // ip of the side that sent the 1st SYN
	unsigned int ser_ip;      // ip of the other side
	unsigned short cli_port;    // source port of 1st SYN packet
	unsigned short ser_port;    // destination port of 1st SYN packet
	unsigned int expires;     // in seconds from epoch
	unsigned char state;       // values from: tcp_conn_t
} connection_t;

// the four states of a TCP connection (simplified!)
typedef enum {
	// connection states
	TCP_CONN_SYN_SENT = 1,
	TCP_CONN_SYN_ACK = 2,
	TCP_CONN_ESTAB = 3,
	TCP_CONN_CLOSING = 4,
} tcp_conn_t;

struct timeval time;

#endif /* FW4_H_ */
