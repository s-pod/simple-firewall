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
#define FIVE_MINUTES 300 // five minutes in seconds 5*60 == 300
#define BITS_IN_BYTE 8

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

/* The structure to represent 'fw_dev' devices.
 *  data - data buffer;
 *  buffer_size - size of the data buffer;
 *  block_size - maximum number of bytes that can be read or written
 *    in one call;
 *  cdev - character device structure.
 */
static struct fw_dev {
	unsigned char *data;
	unsigned long buffer_size;
	unsigned long block_size;
//	struct mutex fw_mutex;
	struct cdev cdev;
	struct device *dev;
};

MODULE_LICENSE("GPL")
;


static void deleteAllConversations(void);
static void updateLogEntry(int i);
static unsigned char getState(int i);
static void updateConversation(int i, unsigned char state, int toUpdateExpire,
		int RST);
static int getRulesSize(void);
static int getLogSize(void);
static int getConnectionTableSize(void);
static int returnBit(long flag, int i);
static void loadInitialRules(void);
static int showConfigurationBits(void);
static unsigned int shiftBitToPlaceIAndBitwiseOR(int a, int i);

static ssize_t rules_config_show(struct device *dev,
		struct device_attribute *attr, char *buf);
static ssize_t rules_config_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t rules_size_show(struct device *dev,
		struct device_attribute *attr, char *buf);
static ssize_t rules_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t log_size_show(struct device *dev, struct device_attribute *attr,
		char *buf);
static ssize_t log_size_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count);
static ssize_t log_clear_show(struct device *dev, struct device_attribute *attr,
		char *buf);
static ssize_t log_clear_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t conn_tab_size_show(struct device *dev,
		struct device_attribute *attr, char *buf);
static ssize_t conn_tab_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);
static ssize_t conn_tab_clear_show(struct device *dev,
		struct device_attribute *attr, char *buf);
static ssize_t conn_tab_clear_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static int fw4_rules_mmap(struct file *file, struct vm_area_struct *vma);
static int fw4_log_mmap(struct file *file, struct vm_area_struct *vma);
static int fw4_conn_tab_mmap(struct file *file, struct vm_area_struct *vma);

static int rules_open(struct inode *inode, struct file *filp);
static int log_open(struct inode *inode, struct file *filp);
static int conn_tab_open(struct inode *inode, struct file *filp);
static int rules_release(struct inode *inode, struct file *filp);
static int log_release(struct inode *inode, struct file *filp);
static int conn_tab_release(struct inode *inode, struct file *filp);

static int newMmapInit(void);
static void newMmapCleanup(void);
static int construct_device(struct fw_dev *dev, int minor, struct class *class,
		char *name, struct file_operations *fops);
static void destroy_device(struct fw_dev *dev, int minor, struct class *class);
static void classCleanUp(void);
static void classAndDevicesStructCleanUp(void);
static void classAndDevicesCleanUP(void);
static void classAndDevicesAndAttributesCleanUP(void);

static int run(/*char *msg*/void);


/* parameters */
// pointer to the kmalloc'd areas, rounded up to a page boundary
static rule_t *kmalloc_ptr_rule = NULL; // TODO: to make sure it's okay to start to NULL...
static connection_t *kmalloc_ptr_connection = NULL; // TODO: to make sure it's okay to start to NULL...
static log_row_t *kmalloc_ptr_log = NULL; // TODO: to make sure it's okay to start to NULL...

// Defining the needed fops files
static struct file_operations rules_fops = { .owner = THIS_MODULE, .mmap =
		fw4_rules_mmap, .open = rules_open, .release = rules_release, };
static struct file_operations log_fops = { .owner = THIS_MODULE, .mmap =
		fw4_log_mmap, .open = log_open, .release = log_release, };
static struct file_operations conn_tab_fops = { .owner = THIS_MODULE, .mmap =
		fw4_conn_tab_mmap, .open = conn_tab_open, .release = conn_tab_release, };

static struct timeval time;
static ssize_t configBitsAsNumber;

static unsigned long buffer_size = 4000;
static unsigned long block_size = 512;
static int devices_to_destroy = 0;
static int attributes_to_destroy = 0;

//static int connectionsSize = 0;
//static int rulesSize = 0;
static int logEntriesNum = 0;

static struct class *fw_class = NULL;
static struct fw_dev *devices = NULL;
static unsigned int major = 0;

// These are control the flags to update...
static int active = 0;
static int icmp = 0;
static int tcp = 0;
static int udp = 0;
static int conn_track = 0;
static int cleanup_accept = 0;


static int Rules_Device_Open = 0;
static int Log_Device_Open = 0;
static int Conn_Tab_Device_Open = 0;

//netfilter variables
struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct udphdr *udp_header;
struct rpmphdr *rpmp_header;
static struct nf_hook_ops nfho;

static const char *REASONS[] = { "FW_CONFIG_ACTIVE", "FW_CONFIG_ICMP",
		"FW_CONFIG_TCP", "FW_CONFIG_UDP", "FW_CONFIG_CONN_TRACK",
		"FW_CONFIG_CLEANUP_ACCEPT", };
static /*const*/char *attr_names[] = { "config", "rules_size", "log_size",
		"log_clear", "conn_tab_size", "conn_tab_clear", };

/*
 * These are the permissions for the attributes as we should define
 * according to the instructions  // TODO: do we need execute permissions for all?????
 * 0X00 - X is the use bit
 * 00X0 - X is the group bit
 * 000X - X is the others bit
 * 7 == read, write, & execute
 * 6 == read & write
 * 5 == read & execute
 * 4 == read
 * 3 == write & execute
 * 2 == write
 * 1 == execute
 * 0 == no permissions
 */
static const int PERMISSIONS[] = { 0766, 0755, 0755, 0733, 0755, 0733 };

//**** ATTRIBUTES *****

static struct device_attribute *dev_attr = NULL;
static struct attribute *attr = NULL;

typedef ssize_t (*attribute_functions_show)(struct device *dev,
		struct device_attribute *attr, char *buf);

typedef ssize_t (*attribute_functions_store)(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count);

static attribute_functions_show show_funcs[ATTRIBUTES_NUM] = {
		rules_config_show, rules_size_show, log_size_show, log_clear_show,
		conn_tab_size_show, conn_tab_clear_show };

static attribute_functions_store store_funcs[ATTRIBUTES_NUM] = {
		rules_config_store, rules_size_store, log_size_store, log_clear_store,
		conn_tab_size_store, conn_tab_clear_store };


/*
 * *************************************************************************
 * ************************** PACKET FUNCTIONS *****************************
 * *************************************************************************
 */

/*
 * This function decides the fate of the packet + log's out the verdict
 * and calls all the proper update functions
 * Return value:
 * 				0 = The packet was dropped
 *				1 = The packet was accepted.
 */
static int decidePacketFate(void) {

	return 0;

}

/*
 * This function checks to see if a string str is a number that is unsigned int
 * If True it returns the value in *num.
 * Return Value:
 * 				 0 = all good - the number is in unsigned int range
 * 				-1 = There was an error in the parsing
 */
static int checkUInt(const char *str, long *num) {
	long result, status;
	if (strlen(str) > MAX_INT_LENGTH) {
		return -1;
	}
	status = kstrtol(str, BASE, &result);
	if (status == -ERANGE || status == -EINVAL) {
		*num = 0;
		return -1;
	}
	*num = result;
	return 0;
}

// /*
//  * This function checks to see if a string str is a number that *int*
//  * If True it returns the value in *num.
//  * Return Value:
//  * 				 0 = all good - the number is in unsigned int range
//  * 				-1 = There was an error in the parsing
//  */
// static int checkInt(char *str, int *num) {
// 	// long result, status;
// 	// if (strlen(str) > MAX_INT_LENGTH) {
// 	// 	return -1;
// 	// }
// 	// status = kstrtol(str, BASE, &result);
// 	// if (status == -ERANGE || status == -EINVAL) {
// 	// 	*num = 0;
// 	// 	return -1;
// 	// }
// 	// *num = (int) result;
// 	return 0;
// }

/*
 * Write the descision the kernel log (with all parameters).
 */
static void writeToLog() {
	//TODO: here!!
	//**********;
}

static void updateLogEntry(int i) {
	(kmalloc_ptr_log[i].count)++;
}

static void writeNewLogEntry() {

	log_row_t *temp = kmalloc_ptr_log;
//	do_gettimeofday(&time);
//	temp[i].modified = time.tv_sec;
//	temp[i].protocol = protocol;
//	temp[i].action = action;
//	temp[i].hooknum = hooknum;
//	temp[i].src_ip = src_ip;
//	temp[i].dst_ip = dst_ip;
//	temp[i].src_port = src_port;
//	temp[i].dst_port = dst_port;
//	temp[i].count = 1;

	logEntriesNum++;
}

// /*
//  * This function returns the next state given the current state, the message
//  * and if it is a client or not.
//  * Return value:
//  *				return value >= 0 it is the next state.
//  *				0 = the conversation ended - it will be deleted.
//  *				-1 = The command does not fit the current state.
//  */
// static int nextState(/*state_t curr, char *command, int client*/) {
// 	return 0;

// }

/*
 * This function checks if the src and dest are according to the rules
 * (By checking each rule until we find the one that deals with src and dest)
 * Return value:
 *				0 = src and dest are allowed to converse.
 *				1 = src and dest are *NOT* allowed to converse.
 *				-1 = christmas egg?
 */
static int checkRules() {
	rule_t *temp;
	int i;
//	__u8 protocol, src_mask, dst_mask, action;
//	__be16 src_port, dst_port;
//	__be32 src_ip, dst_ip;

	if (active == 0) {
		// The default rule accept rule is enables - also if we're here then we are in legal range.
		return 0;
	}

	// We have rules to check! Woohoo!
	temp = kmalloc_ptr_rule;
//	i = 0;
//	do {
//
//		protocol = temp->protocol;
//		src_mask = temp->src_mask;
//		dst_mask = temp->dst_mask;
//		action = temp->action;
//		src_port = temp->src_port;
//		dst_port = temp->dst_port;
//		src_ip = temp->src_ip;
//		dst_ip = temp->dst_ip;
//		temp++;
//
//		if ((protocol == PROT_TCP && tcp == 0)
//				|| (protocol == PROT_UDP && udp == 0)
//				|| (protocol == PROT_ICMP && icmp == 0)) {
//			return 0;
//		}
//
//		// TODO: to continue here!!!!
//		//*********;
//
//	} while (protocol != 255);

	return i;
}

//  * This function deletes the conversation i from the conversations linked list.
//  * (Also it releases the memory that was allocated fot it)
//  * Also it updates the number of current conversation. (No return value).

// static void deleteConversation(int index) {
// 	// if i is the Head of the conversations list
// 	// conversation_t *before, *tmp;

// 	// if (i == conversationsHead) {
// 	// 	if (conversationsTail == i) {
// 	// 		kfree(i);
// 	// 		conversationsTail = NULL;
// 	// 		conversationsHead = NULL;
// 	// 	} else {
// 	// 		conversationsHead = i->next;
// 	// 		kfree(i);
// 	// 	}
// 	// } else if (i == conversationsTail) {
// 	// 	//if we deleting last tail should be changed
// 	// 	before = conversationsHead;
// 	// 	while (before->next != i) {
// 	// 		before = before->next;
// 	// 	}
// 	// 	conversationsTail = before;
// 	// 	conversationsTail->next = NULL;
// 	// 	kfree(i);
// 	// } else {
// 	// 	if (i->next == conversationsTail) {
// 	// 		conversationsTail = i;
// 	// 	}
// 	// 	//delete in O(1) by copying next to current and deleting next
// 	// 	i->client_id = i->next->client_id;
// 	// 	i->state = i->next->state;
// 	// 	i->server_id = i->next->server_id;
// 	// 	i->seq = i->next->seq;
// 	// 	tmp = i->next;
// 	// 	i->next = i->next->next;
// 	// 	kfree(tmp);
// 	// }
// 	//coversationsNum--;
// }

// /*
//  * This function returns if src is the client or the server in the conversation
//  */
// static int getSide(int index, int src) {
// 	return index;
// }

/*
 * This function returns the current state of the conversation.
 */
static unsigned char getState(int i) {
	connection_t *temp = kmalloc_ptr_connection;
	return temp[i].state;
}

/*
 * This function updates the state of the conversation i to the state "state"
 */
static void updateConversation(int i, unsigned char state, int toUpdateExpire,
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

// /*
//  *	This function checks to see if there is an active conversation between src and dest.
//  *	Return value:
//  *					The place of the conversation in the conversations array >= 0
//  *					-1 = There is no such conversation.
//  */
static int findConversation() {
	int i;
	int index;
//	struct timeval currTime;
//	gettimeofday(&currTime, NULL );
//	printf(
//			"The time it took to execute all the trace file is: %ld miliseconds\n",
//			currTime.tv_usec);

	connection_t *temp = kmalloc_ptr_connection;
	index = -1;
//	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++) {
//		if (temp != NULL) {
//			*******;
//			//TODO: here!!
//		}
//	}
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

static void deleteAllConversations(void) {
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

static int getRulesSize(void) {
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

static int getLogSize(void) {
	return logEntriesNum * sizeof(log_row_t);
}

static int getConnectionTableSize(void) {
	int i;
	int count = 0;
	connection_t *temp = kmalloc_ptr_connection;

	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++) {
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
static void createConversation(int i) {

	//*****;
	// conversation_t *temp;
	// // Creating a new conversation between src and dest with the given seq
	// temp = (conversation_t *) kzalloc(sizeof(conversation_t), GFP_KERNEL);
	// if (!temp) {
	// 	printk("allocation error");
	// 	reset();
	// }
	// temp->client_id = src;
	// temp->server_id = dest;
	// temp->seq = seq;
	// temp->state = 1;
	// temp->next = NULL;
	// if (conversationsTail == NULL ) {
	// 	conversationsHead = temp;
	// 	conversationsTail = temp;
	// } else {
	// 	conversationsTail->next = temp;
	// 	conversationsTail = temp;
	// }
	// coversationsNum++;

}

static int getConfigBits(char *config) {
	long temp;
	unsigned int result;
	int status = checkUInt(config, &temp);
	if (status != 0) {
		return -1;
	}
	active = returnBit(temp, FW_CONFIG_ACTIVE);
	icmp = returnBit(temp, FW_CONFIG_ICMP);
	tcp = returnBit(temp, FW_CONFIG_TCP);
	udp = returnBit(temp, FW_CONFIG_UDP);
	conn_track = returnBit(temp, FW_CONFIG_CONN_TRACK);
	cleanup_accept = returnBit(temp, FW_CONFIG_CLEANUP_ACCEPT);

	result = 0;
	if (active)
		result = shiftBitToPlaceIAndBitwiseOR(result ,FW_CONFIG_ACTIVE);
	if (icmp)
		result = shiftBitToPlaceIAndBitwiseOR(result ,FW_CONFIG_ICMP);
	if (tcp)
		result = shiftBitToPlaceIAndBitwiseOR(result ,FW_CONFIG_TCP);
	if (udp)
		result = shiftBitToPlaceIAndBitwiseOR(result ,FW_CONFIG_UDP);
	if (conn_track)
		result = shiftBitToPlaceIAndBitwiseOR(result ,FW_CONFIG_CONN_TRACK);
	if (cleanup_accept)
		result = shiftBitToPlaceIAndBitwiseOR(result ,FW_CONFIG_CLEANUP_ACCEPT);
	configBitsAsNumber = result;

	return 0;
}

static int returnBit(long flag, int i) {
	int shift = sizeof(long) * BITS_IN_BYTE;
	int temp = (flag << (shift - i)) >> (shift - 1);
	return temp;

}

static int showConfigurationBits(void) {
	return configBitsAsNumber;
}

static unsigned int shiftBitToPlaceIAndBitwiseOR(int a, int i){
	unsigned int temp = 1;
	temp = (temp << (i - 1));
	return temp & a;
}

static void clearLog(void) {
	int i;
	log_row_t *temp = kmalloc_ptr_log;
	for (i = 0; i < logEntriesNum; i++) {
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

static void loadInitialRules(void){
	//*******; //TODO: to add here!
}

// ****************************************************************************
// ***************  ATTRIBUTE DUNCTIONS: SHOW AND STORE   *********************
// ****************************************************************************

static ssize_t rules_config_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	return showConfigurationBits();
}

static ssize_t rules_config_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {

	int status;
	char *config = (char *) kmalloc(sizeof(char) * (count + 1), GFP_KERNEL);
	if (config == NULL ) {
		// malloc failed
		return count;
	}
	strncpy(config, buf, count);
	config[count] = '\0';
	status = getConfigBits(config);
	if (status != 0) {
		// bad input to configuration - we ignore it.
	}

	return count;
}

static ssize_t rules_size_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	return getRulesSize();
}

static ssize_t rules_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {
	return count;
}

static ssize_t log_size_show(struct device *dev, struct device_attribute *attr,
		char *buf) {
	return getLogSize();
}

static ssize_t log_size_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count) {
	return count;
}

static ssize_t log_clear_show(struct device *dev, struct device_attribute *attr,
		char *buf) {
	return sprintf(buf, "%d", major);
}

static ssize_t log_clear_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {
	if (count  ==2 )
		clearLog();
	return count;
}

static ssize_t conn_tab_size_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	return getConnectionTableSize();
}

static ssize_t conn_tab_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {
	return count;
}

static ssize_t conn_tab_clear_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	return sprintf(buf, "%d", major);
}

static ssize_t conn_tab_clear_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {

	if (count == 2)
		deleteAllConversations();
	return count;
}

// *********************    MMAP FUNCTIONS     ******************************

/*
 * Rules mmap: 
 * This function replaces the regular function of mmap.
 * It uses remap_pfn_range to let the user write to the allocated kernel space.
 */
static int fw4_rules_mmap(struct file *file, struct vm_area_struct *vma) {
	int ret = 1;
	long length = vma->vm_end - vma->vm_start;

	/* remap the whole physically contiguous area in one piece */
	if ((ret = remap_pfn_range(vma, vma->vm_start,
			__pa(kmalloc_ptr_rule) >> PAGE_SHIFT, length, vma->vm_page_prot))
			< 0) {
		return ret;
	}
	return 0;
}

/*
 * Log mmap: 
 * This function replaces the regular function of mmap.
 * It uses remap_pfn_range to let the user write to the allocated kernel space.
 */
static int fw4_log_mmap(struct file *file, struct vm_area_struct *vma) {
	int ret = 1;
	long length = vma->vm_end - vma->vm_start;

	/* remap the whole physically contiguous area in one piece */
	if ((ret = remap_pfn_range(vma, vma->vm_start,
			__pa(kmalloc_ptr_log) >> PAGE_SHIFT, length, vma->vm_page_prot))
			< 0) {
		return ret;
	}
	return 0;
}

/*
 * Connection Table mmap: 
 * This function replaces the regular function of mmap.
 * It uses remap_pfn_range to let the user write to the allocated kernel space.
 */
static int fw4_conn_tab_mmap(struct file *file, struct vm_area_struct *vma) {
	int ret = 1;
	long length = vma->vm_end - vma->vm_start;

	/* remap the whole physically contiguous area in one piece */
	if ((ret = remap_pfn_range(vma, vma->vm_start,
			__pa(kmalloc_ptr_connection) >> PAGE_SHIFT, length,
			vma->vm_page_prot)) < 0) {
		return ret;
	}
	return 0;
}

// ******************    OPEN AND RELEASE FUNCTIONS     ****************************

static int rules_open(struct inode *inode, struct file *filp) {
	if (Rules_Device_Open)
		return -EBUSY;

	Rules_Device_Open++;
	try_module_get(THIS_MODULE );

	return SUCCESS;
}

static int log_open(struct inode *inode, struct file *filp) {
	if (Log_Device_Open)
		return -EBUSY;

	Log_Device_Open++;
	try_module_get(THIS_MODULE );

	return SUCCESS;
}

static int conn_tab_open(struct inode *inode, struct file *filp) {
	if (Conn_Tab_Device_Open)
		return -EBUSY;

	Conn_Tab_Device_Open++;
	try_module_get(THIS_MODULE );

	return SUCCESS;
}

static int rules_release(struct inode *inode, struct file *filp) {
	Rules_Device_Open--;
	module_put(THIS_MODULE );

	return 0;
}

static int log_release(struct inode *inode, struct file *filp) {
	Log_Device_Open--;
	module_put(THIS_MODULE );

	return 0;
}

static int conn_tab_release(struct inode *inode, struct file *filp) {
	Conn_Tab_Device_Open--;
	module_put(THIS_MODULE );

	return 0;
}

/*
 * This function initializes the pointers: 
 *  kmalloc_ptr_rule
 *  kmalloc_ptr_log
 *  kmalloc_ptr_connection
 * (that we need to re-mmap later with the new mmap functions)
 */
static int newMmapInit(void) {
	int ret = 0;

	/* allocate a memory area with kmalloc */
	if ((kmalloc_ptr_rule = (rule_t *) kzalloc(
			sizeof(rule_t) * RULE_BASE_ENTRIES, GFP_KERNEL)) == NULL ) {
		ret = -ENOMEM;
		return ret;
	}

	if ((kmalloc_ptr_log = (log_row_t *) kzalloc(
			sizeof(log_row_t) * LOG_ENTRIES, GFP_KERNEL)) == NULL ) {
		ret = -ENOMEM;
		return ret;
	}

	if ((kmalloc_ptr_connection = (connection_t *) kzalloc(
			sizeof(connection_t) * CONNECTION_TABLE_ENTRIES, GFP_KERNEL))
			== NULL ) {
		ret = -ENOMEM;
		return ret;
	}

	return ret;
}

/*
 * This function releases the kmalloc_ptr pointer that we needed in order to remap
 * with the new mmap function.
 */
static void newMmapCleanup(void) {
	if (kmalloc_ptr_rule)
		kfree(kmalloc_ptr_rule);
	if (kmalloc_ptr_log)
		kfree(kmalloc_ptr_log);
	if (kmalloc_ptr_connection)
		kfree(kmalloc_ptr_connection);
}

/* ================================================================ */
/* Setup and register the device with specific index (the index is also
 * the minor number of the device).
 * Device class should be created beforehand.
 */
static int construct_device(struct fw_dev *dev, int minor, struct class *class,
		char *name, struct file_operations *fops) {
	int err = 0;
	dev_t devno = MKDEV(major, minor);

	/* Memory is to be allocated when the device is opened the first time */
	dev->data = NULL;
	dev->buffer_size = buffer_size;
	dev->block_size = block_size;
	//mutex_init(&dev->fw_mutex);

	dev->dev = device_create(class, NULL, /* no parent device */
	devno, NULL, /* no additional data */
	name, minor);

	cdev_init(&dev->cdev, fops);
	dev->cdev.owner = THIS_MODULE;

	err = cdev_add(&dev->cdev, devno, 1);
	if (err) {
		printk(KERN_WARNING "[target] Error %d while trying to add %s%d", err,
				CLASS_NAME, minor);
		return err;
	}

	if (IS_ERR(dev->dev)) {
		err = PTR_ERR(dev->dev);
		printk(KERN_WARNING "[target] Error %d while trying to create %s%d",
				err, CLASS_NAME, minor);
		cdev_del(&dev->cdev);
		return err;
	}
	return 0;
}

/* This function destroys the given device and free's its buffer */
static void destroy_device(struct fw_dev *dev, int minor, struct class *class) {
	device_destroy(class, MKDEV(major, minor));
	cdev_del(&dev->cdev);
	kfree(dev->data);
	return;
}

static void classCleanUp(void) {
	if (fw_class)
		class_destroy(fw_class);
	unregister_chrdev_region(MKDEV(major, 0), DEVICES_NUM);
}

static void classAndDevicesStructCleanUp(void) {
	if (devices)
		kfree(devices);
	classCleanUp();
}

static void classAndDevicesCleanUP(void) {
	int i;
	for (i = 0; i < devices_to_destroy; ++i) {
		destroy_device(&devices[i], i, fw_class);
	}
	classAndDevicesStructCleanUp();
}

static void classAndDevicesAndAttrubuteStructCleanUP(void) {
	if (dev_attr)
		kfree(dev_attr);
	if (attr)
		kfree(attr);
	classAndDevicesCleanUP();
}

static void classAndDevicesAndAttributesCleanUP(void) {
	int i;
	int j = -1;
	for (i = 0; i < attributes_to_destroy; i++) {
		if (i % 2 == 0)
			j++;
		device_remove_file(devices[j].dev, &dev_attr[i]);
		kfree(attr[i].name);
	}
	classAndDevicesAndAttrubuteStructCleanUP();
}

static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	sock_buff = skb;
	struct iphdr* iph = ip_hdr(skb);
	struct tcphdr* tcph = tcp_hdr(skb);
	struct udphdr* udph = udp_hdr(skb);
	printk("Woohoo a packet src: %d dst: %d!\n", iph->saddr, iph->daddr);
	return NF_ACCEPT;
}

/*
 * loader - This is the initial loader function that creates the class, devices, attributes and all the other stuff.
 */
static int hello_init(void) {
	int i;
	int j;
	int err = 0;
	dev_t dev = 0;

	nfho.hook = hook_func;
	nfho.hooknum = 0;
	nfho.pf = PF_INET;
	nfho.priority = 0;
	nf_register_hook(&nfho);

	alloc_chrdev_region(&dev, 0, DEVICES_NUM, CLASS_NAME);
	major = MAJOR(dev);
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fw_class)) {
		err = PTR_ERR(fw_class);
		printk("FW4: Failed to create the class\n");
		return 1;
	}

	/* Allocate the array of devices */
	devices = (struct fw_dev *) kzalloc(DEVICES_NUM * sizeof(struct fw_dev),
			GFP_KERNEL);
	if (devices == NULL ) {
		err = -ENOMEM;
		printk("FW4: Failed to kmalloc the devices shell\n");
		classCleanUp();
		return 1;
	}

	/* Construct devices */
	err = construct_device(&devices[DEVICE_RULES], MINOR_RULES, fw_class,
			DEVICE_NAME_RULES, &rules_fops);
	if (err) {
		printk("FW4: Failed to create the first device\n");
		classAndDevicesStructCleanUp();
		return 1;
	}
	devices_to_destroy++;

	err = construct_device(&devices[DEVICE_LOG], MINOR_LOG, fw_class,
			DEVICE_NAME_LOG, &log_fops);
	if (err) {
		printk("FW4: Failed to create the second device\n");
		classAndDevicesCleanUP();
		return 1;
	}
	devices_to_destroy++;

	err = construct_device(&devices[DEVICE_CONN_TAB], MINOR_CONN_TAB, fw_class,
			DEVICE_NAME_CONN_TAB, &conn_tab_fops);
	if (err) {
		printk("FW4: Failed to create the third device\n");
		classAndDevicesCleanUP();
		return 1;
	}
	devices_to_destroy++;

	dev_attr = (struct device_attribute *) kzalloc(
			ATTRIBUTES_NUM * sizeof(struct device_attribute), GFP_KERNEL);
	if (dev_attr == NULL ) {
		err = -ENOMEM;
		printk("FW4: Failed to kmalloc the dev_attr array\n");
		classAndDevicesAndAttrubuteStructCleanUP();
		return 1;
	}

	// TODO: to add attrubute structs cleanup!!!!
	attr = (struct attribute *) kzalloc(
			ATTRIBUTES_NUM * sizeof(struct attribute), GFP_KERNEL);
	if (attr == NULL ) {
		err = -ENOMEM;
		printk("FW4: Failed to kmalloc the attr array\n");
		classAndDevicesAndAttrubuteStructCleanUP();
		return 1;
	}

	j = -1;
	//creatint the attribute files
	for (i = 0; i < ATTRIBUTES_NUM; i++) {
		memset(&dev_attr[i], 0, sizeof(struct device_attribute));
		attr[i].mode = PERMISSIONS[i] /*PERMISSION*/;
		attr[i].name = (char *) kmalloc(sizeof(char) * NAME_MAX_COPY,
				GFP_KERNEL);
		if (attr[i].name == NULL ) {
			// kmalloc failed...
			printk("FW4: kmalloc'ing the %d name has failed\n", i);
			classAndDevicesAndAttributesCleanUP();
			return 1;
		}

		if (i % 2 == 0) {
			j++;
		}

		strncpy(attr[i].name, attr_names[i], NAME_MAX_COPY);
		dev_attr[i].attr = attr[i];
		dev_attr[i].show = show_funcs[i];
		dev_attr[i].store = store_funcs[i];
		err = device_create_file(devices[j].dev, &(dev_attr[i]));
		if (err) {
			printk("FW4: attribute creation failed\n");
			classAndDevicesAndAttributesCleanUP();
			return 1;
		}
		attributes_to_destroy++;

	}

	if (newMmapInit() != 0) {
		printk("FW4: mmap initialization failed\n");
		classAndDevicesAndAttributesCleanUP();
		newMmapCleanup();
		return 1;
	}

	return 0;
}

/* unloader - This function releases all the allocated memory if we remove the module. */
static void hello_cleanup(void) {
	//reset();
	nf_unregister_hook(&nfho);
	classAndDevicesAndAttributesCleanUP();
	newMmapCleanup();
	return;
}

/* This function runs the firewall on a packet.
 * Return value:
 *				0 = The packet was dropped or the numbers were not numbers or there was an error in the strings like From or To...
 *				1 = All good - the packet was accepted.
 */
static int run(/*char *msg*/void) {
	// char command[MAX_LINE_LENGTH];
	//int check;
	// int src_id, dest_id, seq_num;
	//decode the packet
	// check = decodeLine(msg, &src_id, &dest_id, &seq_num, command);
	// if (check == 1) {
	// 	return 0;

	return /*decidePacketFate()*/0;
}

module_init(hello_init)
;
module_exit(hello_cleanup)
;
