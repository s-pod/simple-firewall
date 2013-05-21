#ifndef CONN_MANAGER_H_
#define CONN_MANAGER_H_

#include "global.h"

void deleteAllConnections(void)
void updateConnection(int i, unsigned char state, int toUpdateExpire,
		int RST);
unsigned char getState(int i);
int getConnectionTableSize(void);
int getSide(int index, int src);
int findConection(unsigned int cli_ip, unsigned int ser_ip,
		unsigned short cli_port, unsigned short ser_port);
void createConnection(int i);
#endif /* CONN_MANAGER_H_ */
