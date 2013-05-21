/*
 * rule_manager.c
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#include "rule_manager.h"


void loadInitRules(void){
	//*******;
}

/*
 * This function checks if the src and dest are according to the rules
 * (By checking each rule until we find the one that deals with src and dest)
 * Return value:
 *				0 = src and dest are allowed to converse.
 *				1 = src and dest are *NOT* allowed to converse.
 *				-1 = christmas egg?
 */
int checkRules(int active) {
	rule_t *temp;
	int i;
	__u8 protocol, src_mask, dst_mask, action;
	__be16 src_port, dst_port;
	__be32 src_ip, dst_ip;

	if (active == 0) { // TODO: to delete this?
		// The default rule accept rule is enables - also if we're here then we are in legal range.
		return 0;
	}

	// We have rules to check! Woohoo!
	temp = kmalloc_ptr_rule;
	i = 0;
	do {

		protocol = temp->protocol;
		src_mask = temp->src_mask;
		dst_mask = temp->dst_mask;
		action = temp->action;
		src_port = temp->src_port;
		dst_port = temp->dst_port;
		src_ip = temp->src_ip;
		dst_ip = temp->dst_ip;
		temp++;

		if ((protocol == PROT_TCP && tcp == 0)
				|| (protocol == PROT_UDP && udp == 0)
				|| (protocol == PROT_ICMP && icmp == 0)) {
			return 0;
		}

		// TODO: to continue here!!!!
		//*********;

	} while (protocol != 255);

	return i;
}

int getRulesSize(void) {
	int i = 0;
	int count = 0;
	rule_t *temp = kmalloc_ptr_rule;
	while (temp->protocol != 255 && i < RULE_BASE_ENTRIES) {
		count++;
		temp++;
		i++;
	}
	if (count == 0)
		return 0;

	return count * sizeof(rule_t);
}
