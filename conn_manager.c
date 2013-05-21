/*
 * con_manager.c
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#include "conn_manager.h"


 /*
  * This function returns if src is the client or the server in the conversation
  */
 int getSide(int index, int src) {
 	return index;
 }

 /*
  * This function returns the current state of the conversation.
  */
 unsigned char getState(int i) {
 	connection_t *temp = kmalloc_ptr_connection;
 	return temp[i].state;
 }

/*
 * This function updates the state of the conversation i to the state "state"
 */
void updateConnection(int i, unsigned char state, int toUpdateExpire,
		int RST) {
	connection_t *temp;
	do_gettimeofday(&time);
	temp = kmalloc_ptr_connection;
	temp[i].state = state;
	if (RST == 1) {
		temp[i].expires = 0;
		return;
	}
	if (toUpdateExpire == 1) {
		temp[i].expires = time.tv_sec + FIVE_MINUTES;
	}
}

/*
 * This function returns the next state given the current state, the message
 * and if it is a client or not.
 * Return value:
 *				return value >= 0 it is the next state.
 *				0 = the conversation ended - it will be deleted.
 *				-1 = The command does not fit the current state.
 */
int nextState(/*state_t curr, char *command, int client*/) {
	return 0;

}

// /*
//  *	This function checks to see if there is an active conversation between src and dest.
//  *	Return value:
//  *					The place of the conversation in the conversations array >= 0
//  *					-1 = There is no such conversation.
//  */
int findConection(unsigned int cli_ip, unsigned int ser_ip,
		unsigned short cli_port, unsigned short ser_port) {
	int i;
	int index;
//	struct timeval currTime;
//	gettimeofday(&currTime, NULL );
//	printf(
//			"The time it took to execute all the trace file is: %ld miliseconds\n",
//			currTime.tv_usec);

	connection_t *temp = kmalloc_ptr_connection;
	index = -1;
	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++) {
		if (temp != NULL) {
			//*******;
			//TODO: here!!
		}
	}
	// conversation_t *temp = conversationsHead;
	// while (temp != NULL ) {
	// 	if ((temp->client_id == src && temp->server_id == dest)
	// 			|| (temp->client_id == dest && temp->server_id == src)) {
	// 		return temp;
	// 	}
	// 	temp = temp->next;
	// }
	// return NULL ;
	return index;

}


/*
 * This function deletes all the conections in the connection table.
 * I'm assuming the delete == expires time is zero.
 */

void deleteAllConnections(void) {
	int i;
	connection_t *temp;
	if (kmalloc_ptr_connection == NULL )
		return;
	temp = kmalloc_ptr_connection;
	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++) {
		temp->expires = 0;
		temp++;
	}
}

int getConnectionTableSize(void){
	int i;
	int count = 0;
	connection_t *temp = kmalloc_ptr_connection;

	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++){
		do_gettimeofday(&time);
		if (time.tv_sec <= temp->expires)
			count++;
	}
	if (count == 0)
		return 0;
	return count * sizeof(connection_t);

}

/*
 * This functions creates the conversation with src dest and seq as parameters.
 */
void createConnection(int i) {


}
