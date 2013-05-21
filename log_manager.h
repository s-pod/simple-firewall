/*
 * log_manager.h
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#ifndef LOG_MANAGER_H_
#define LOG_MANAGER_H_

#include "global.h"


void updateLogEntry(int i);
void writeNewLogEntry(int i, unsigned char protocol, unsigned char action,
		unsigned char hooknum, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port,
					unsigned short dst_port ,int reason);
int getLogSize(void);
void clearLog(void);

#endif /* LOG_MANAGER_H_ */
