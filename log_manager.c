/*
 * log_manager.c
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#include "log_manager.h"


static log_row_t *kmalloc_ptr_log = NULL;
static int logEntriesNum = 0;


/*
 * Write the descision the kernel log (with all parameters).
 */
void writeToLog() {
	//TODO: here!!
	//**********;
}

void updateLogEntry(int i) {
	(kmalloc_ptr_log[i].count)++;
}

void writeNewLogEntry(int i, unsigned char protocol, unsigned char action,
		unsigned char hooknum, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port,
					unsigned short dst_port ,int reason) {

	log_row_t *temp = kmalloc_ptr_log;
	do_gettimeofday(&time);
	temp[i].modified = time.tv_sec;
	temp[i].protocol = protocol;
	temp[i].action = action;
	temp[i].hooknum = hooknum;
	temp[i].src_ip = src_ip;
	temp[i].dst_ip = dst_ip;
	temp[i].src_port = src_port;
	temp[i].dst_port = dst_port;
	temp[i].count = 1;

	logEntriesNum++;
}

int getLogSize(void){
	return logEntriesNum * sizeof(log_row_t);
}


void clearLog(void){
	int i;
	log_row_t *temp = kmalloc_ptr_log;
	for (i = 0; i < logEntriesNum; i++){
		temp->protocol = 0;
		temp->modified = 0;
		temp->protocol = 0;
		temp->action = 0;
		temp->hooknum = 0;
		temp->src_ip = 0;
		temp->dst_ip = 0;
		temp->src_port = 0;
		temp->dst_port = 0;
		temp->reason = 0;
		temp->count = 0;
		temp++;
	}
	logEntriesNum = 0;
}
