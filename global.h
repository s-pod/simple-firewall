/*
 * global.h
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#ifndef GLOBAL_H_
#define GLOBAL_H_

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/time.h>


// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES      "fw4_rules"
#define DEVICE_NAME_LOG        "fw4_log"
#define DEVICE_NAME_CONN_TAB   "fw4_conn_tab"
#define CLASS_NAME             "fw4"
// these values represent the number of entries in each mmap()able device,
// they do not represent the size in bytes!
#define RULE_BASE_ENTRIES         0x100
#define LOG_ENTRIES               0x400
#define CONNECTION_TABLE_ENTRIES  0x400

#define MAX_INT_LENGTH 11
#define BASE 10

#define NAME_MAX_COPY 15 //TODO: to check that the random number is correct....
#define PERMISSION 0666
#define DEVICES_NUM 3
#define SUCCESS 0
#define ATTRIBUTES_NUM 6
#define ATTRIBUTE_FUNCTIONS 6
#define DEVICE_RULES 0
#define DEVICE_LOG 1
#define DEVICE_CONN_TAB 2

#define RULES_CONFIG 0
#define RULES_SIZE 1
#define LOG_SIZE 2
#define LOG_CLEAR 3
#define CONN_TAB_SIZE 4
#define CONN_TAB_CLEAR 5
#define BITS_IN_BYTE 8

#define FIVE_MINUTES 300 // five minutes in seconds 5*60 == 300

#endif /* GLOBAL_H_ */
