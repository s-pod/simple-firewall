/*
 * rule_manager.h
 *
 *  Created on: May 22, 2013
 *      Author: stas
 */

#ifndef RULE_MANAGER_H_
#define RULE_MANAGER_H_
#include "global.h"

int getRulesSize(void);
void loadInitRules(void);
int checkRules(int active, int tcp, int udp, int icmp);

#endif /* RULE_MANAGER_H_ */
