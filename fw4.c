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
#include <linux/icmp.h>
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
#define E 1
#define LOG_SIZE 2
#define LOG_CLEAR 3
#define CONN_TAB_SIZE 4
#define CONN_TAB_CLEAR 5
#define FIVE_MINUTES 300 // five minutes in seconds 5*60 == 300
#define BITS_IN_BYTE 8

#define LOCALHOST 16777343
#define FIVE_SECONDS 5
#define FIVE_MINUTES 300
#define IPV4 4
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
static int cmprMask(unsigned int src_ip, unsigned int dst_ip,
		unsigned char src_mask);
static void deleteAllConversations(void);
static int findConversation(void);
static void updateLogEntry(int i);
static void writeNewLogEntry(int i, unsigned char packet_hooknum,
		unsigned char packet_action, int packet_reason);
static int updateConversation(int i);
static int returnBit(__u8 flag, int i);
static void loadInitialRules(void);
static unsigned int showConfigurationBits(void);

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
static unsigned int configBitsAsNumber;

static unsigned long buffer_size = 4000;
static unsigned long block_size = 512;
static int devices_to_destroy = 0;
static int attributes_to_destroy = 0;

//static int connectionsSize = 0;
//static int rulesSize = 0;

static int rule_num = 0;
static int logEntriesNum = 0;

static struct class *fw_class = NULL;
static struct fw_dev *devices = NULL;
static unsigned int major = 0;

// These are control the flags to update...
static int active = 0;
static int icmp = 0;
static int tcp_active = 0;
static int udp = 0;
static int conn_track = 0;
static int cleanup_accept = 0;

static int Rules_Device_Open = 0;
static int Log_Device_Open = 0;
static int Conn_Tab_Device_Open = 0;

//netfilter variables
struct sk_buff *sock_buff;
static struct nf_hook_ops nfho_forward;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static struct tcphdr *tcp_header;
static struct iphdr *ip_header;
static struct udphdr *udp_header;
static int hook_num;

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
 * This function checks to see if a string str is a number that is unsigned int
 * If True it returns the value in *num.
 * Return Value:
 * 				 0 = all good - the number is in unsigned int range
 * 				-1 = There was an error in the parsing
 */
static __u8 checkUInt(const char *str, __u8 *num) {
	__u8 result, status;
	if (strlen(str) > 4) {
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

/*
 * Write the descision the kernel log (with all parameters).
 */
static void writeToLog(unsigned char packet_hooknum,
		unsigned char packet_action, int packet_reason) {
	int i;
	__u16 packet_src_port = 0, packet_dst_port = 0;
	if (ip_header->saddr == LOCALHOST && ip_header->daddr == LOCALHOST) {
		// self conversation - localhost - are not logged.
		return;
	}
	if (ip_header->protocol == PROT_TCP) {
		packet_src_port = ntohs(tcp_header->source);
		packet_dst_port = ntohs(tcp_header->dest);
	} else if (ip_header->protocol == PROT_UDP) {
		packet_src_port = ntohs(udp_header->source);
		packet_dst_port = ntohs(udp_header->dest);
	}
	log_row_t *temp = kmalloc_ptr_log;
	for (i = 0; i < logEntriesNum; i++) {
		if (htonl(temp->src_ip) == ip_header->saddr
				&& htonl(temp->dst_ip) == ip_header->daddr
				&& temp->protocol == ip_header->protocol
				&& temp->hooknum == packet_hooknum
				&& temp->action == packet_action
				&& temp->reason == packet_reason
				&& temp->src_port == packet_src_port
				&& temp->dst_port == packet_dst_port) {
			updateLogEntry(i);
			return;
		}
		temp++;
	}
	if (i < LOG_ENTRIES) {
		writeNewLogEntry(i, packet_hooknum, packet_action, packet_reason);
	}
}

static void updateLogEntry(int i) {
	(kmalloc_ptr_log[i].count)++;
	do_gettimeofday(&time);
	kmalloc_ptr_log[i].modified = time.tv_sec;
}

static void writeNewLogEntry(int i, unsigned char packet_hooknum,
		unsigned char packet_action, int packet_reason) {
	log_row_t *temp = kmalloc_ptr_log;
	__u16 packet_src_port = 0, packet_dst_port = 0;
	if (ip_header->protocol == PROT_TCP) {
		packet_src_port = ntohs(tcp_header->source);
		packet_dst_port = ntohs(tcp_header->dest);
	} else if (ip_header->protocol == PROT_UDP) {
		packet_src_port = ntohs(udp_header->source);
		packet_dst_port = ntohs(udp_header->dest);
	} else {
		packet_src_port = 0;
		packet_dst_port = 0;
	}
	do_gettimeofday(&time);
	temp[i].modified = time.tv_sec;
	temp[i].protocol = ip_header->protocol;
	temp[i].action = packet_action;
	temp[i].hooknum = packet_hooknum;
	temp[i].reason = packet_reason;
	temp[i].src_ip = ntohl(ip_header->saddr); // from big endian to little
	temp[i].dst_ip = ntohl(ip_header->daddr); // from big endian to little

	temp[i].src_port = (unsigned short) packet_src_port; // from big endian to little
	temp[i].dst_port = (unsigned short) packet_dst_port; // from big endian to little

	temp[i].count = 1;
	logEntriesNum++;
}

/*
 * This function updates the state of the conversation i to the state "state"
 * 0 == all good
 */
static int updateConversation(int i) {
	connection_t *temp;
	temp = kmalloc_ptr_connection;
	do_gettimeofday(&time);

	if (tcp_header->rst == 1) {
		temp[i].expires = 0;
		return 0;
	}

	if (tcp_header->fin == 1) {
		if (temp[i].state != TCP_CONN_CLOSING) {
			temp[i].state = TCP_CONN_CLOSING;
			temp[i].expires = time.tv_sec + FIVE_SECONDS;
			return 0;
		}
	}

	if (temp[i].state == TCP_CONN_SYN_SENT) {
		if (ip_header->saddr == htonl(temp[i].ser_ip)
				&& tcp_header->dest == htons(temp[i].cli_port)
				&& tcp_header->syn == 1 && tcp_header->ack == 1) {
			temp[i].state = TCP_CONN_SYN_ACK;
			temp[i].expires = time.tv_sec + FIVE_SECONDS;
			return 0;
		}
		return 1;
	}

	if (temp[i].state == TCP_CONN_SYN_ACK) {
		temp[i].state = TCP_CONN_ESTAB;
		temp[i].expires = time.tv_sec + FIVE_MINUTES;
		return 0;
	}

	if (temp[i].state == TCP_CONN_ESTAB) {
		temp[i].expires = time.tv_sec + FIVE_MINUTES;
		return 0;
	}

	if (temp[i].state == TCP_CONN_CLOSING) {
		if (tcp_header->fin == 1 || tcp_header->ack == 1) {
			return 0;
		}
		return 1;
	}
	return 0;
}

// /*
//  *	This function checks to see if there is an active conversation between src and dest.
//  *	Return value:
//  *					The place of the conversation in the conversations array >= 0
//  *					-1 = There is no such conversation.
//  */
static int findConversation(void) {
	int i;
	int index = -1;
	do_gettimeofday(&time);

	connection_t *temp = kmalloc_ptr_connection;
	index = -1;
	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++) {
		if (time.tv_sec <= temp->expires) {
			if ((temp->cli_ip == ntohl(ip_header->saddr)
					&& temp->ser_ip == ntohl(ip_header->daddr)
					&& temp->cli_port == ntohs(tcp_header->source)
					&& temp->ser_port == ntohs(tcp_header->dest))
			|| (temp->cli_ip == ntohl(ip_header->daddr)
					&& temp->ser_ip == ntohl(ip_header->saddr)
					&& temp->cli_port == ntohs(tcp_header->dest)
					&& temp->ser_port == ntohs(tcp_header->source))){
			index = i;
			return index;
		}
	}
	temp++;
}

	return index;

}

static int christmas(void) {
	if (tcp_header->ack && tcp_header->syn && tcp_header->fin && tcp_header->psh
			&& tcp_header->rst && tcp_header->urg && tcp_header->cwr
			&& tcp_header->ece) {
		return 1;
	}
	return 0;
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

/*
 * This functions creates the conversation with src dest and seq as parameters.
 * 0 == all good
 * 1 == no space in the table
 * 2 == not right flag
 */
static int createConversation(void) {
	int i;
	connection_t *temp = kmalloc_ptr_connection;
	do_gettimeofday(&time);

	for (i = 0; i < CONNECTION_TABLE_ENTRIES; i++) {
		if (time.tv_sec > temp[i].expires) {
			temp[i].expires = time.tv_sec + FIVE_SECONDS;
			temp[i].cli_ip = ntohl(ip_header->saddr);
			temp[i].cli_port = ntohs(tcp_header->source);
			temp[i].ser_ip = ntohl(ip_header->daddr);
			temp[i].ser_port = ntohs(tcp_header->dest);
			temp[i].state = TCP_CONN_SYN_SENT;
			return 0;
		}
		temp++;
	}
	return 1;
}

static int cmprMask(unsigned int src_ip, unsigned int dst_ip,
		unsigned char src_mask) {
	if (src_mask == 0) {
		return 1;
	}
	unsigned int m = 0xFFFFFFFF << (32 - src_mask);
	if ((src_ip & m) == (dst_ip & m)) {
		return 1;
	} else {
		return 0;
	}
	return 0;
}

/*
 * This function checks if the src and dest are according to the rules
 * (By checking each rule until we find the one that deals with src and dest)
 * Return value:
 *				0 = src and dest are allowed to converse.
 *				1 = src and dest are *NOT* allowed to converse.
 *				-1 = christmas egg?
 */
static int checkRules(char zeroe_ports) {
	rule_t *temp;
	rule_num = 0;
	__u8 protocol = 0, src_mask, dst_mask, action;
	__be16 src_port, dst_port, packet_src_port = 0, packet_dst_port = 0;
	__be32 src_ip, dst_ip;
	if (ip_header->protocol == PROT_TCP) {
		packet_src_port = tcp_header->source;
		packet_dst_port = tcp_header->dest;
	} else if (ip_header->protocol == PROT_UDP) {
		packet_src_port = udp_header->source;
		packet_dst_port = udp_header->dest;
	}

	// We have rules to check! Woohoo!
	temp = kmalloc_ptr_rule;
	while (protocol != 255) {
		protocol = temp->protocol;
		src_mask = temp->src_mask;
		dst_mask = temp->dst_mask;
		action = temp->action;
		src_port = temp->src_port;
		dst_port = temp->dst_port;
		src_ip = temp->src_ip;
		dst_ip = temp->dst_ip;
		temp++;

		if (ip_header->protocol == PROT_TCP
				|| ip_header->protocol == PROT_UDP) {
			if (src_port != 0 && dst_port != 0) {
				if (packet_src_port != src_port
						|| packet_dst_port != dst_port) {
					rule_num++;
					continue;
				}
			} else if (src_port == 0 && dst_port == 0) {
				//ignore ports and proceed
			} else if (src_port == 0) {
				if (packet_dst_port != dst_port) {
					rule_num++;
					continue;
				}
			} else {
				if (packet_src_port != src_port) {
					rule_num++;
					continue;
				}
			}
			if (!cmprMask(src_ip, ip_header->saddr, src_mask)
					|| !cmprMask(dst_ip, ip_header->daddr, dst_mask)) {
				rule_num++;
				continue;
			}

			return action;
		} else if (ip_header->protocol == PROT_ICMP || zeroe_ports) {
			if (!cmprMask(src_ip, ip_header->saddr, src_mask)
					|| !cmprMask(dst_ip, ip_header->daddr, dst_mask)) {
				rule_num++;
				continue;
			}
			return action;
		}
		rule_num++;
	}
	rule_num = -1;
	return 2;
}

static unsigned int setConfigBits(char *config) {
	__u8 temp;
	unsigned int result;
	int status = checkUInt(config, &temp);
	if (status != 0) {
		return -1;
	}
	active = returnBit(temp, FW_CONFIG_ACTIVE);
	icmp = returnBit(temp, FW_CONFIG_ICMP);
	tcp_active = returnBit(temp, FW_CONFIG_TCP);
	udp = returnBit(temp, FW_CONFIG_UDP);
	conn_track = returnBit(temp, FW_CONFIG_CONN_TRACK);
	cleanup_accept = returnBit(temp, FW_CONFIG_CLEANUP_ACCEPT);

	result = 0;
	if (active)
		result |= FW_CONFIG_ACTIVE;
	if (icmp)
		result |= FW_CONFIG_ICMP;
	if (tcp_active)
		result |= FW_CONFIG_TCP;
	if (udp)
		result |= FW_CONFIG_UDP;
	if (conn_track)
		result |= FW_CONFIG_CONN_TRACK;
	if (cleanup_accept)
		result |= FW_CONFIG_CLEANUP_ACCEPT;
	configBitsAsNumber = result;

	return 0;
}

static int returnBit(__u8 flag, int i) {
	if ((flag & i) == i) {
		return 1;
	}
	return 0;
}

static unsigned int showConfigurationBits(void) {
	return configBitsAsNumber;
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

// ****************************************************************************
// ***************  ATTRIBUTE DUNCTIONS: SHOW AND STORE   *********************
// ****************************************************************************

static ssize_t rules_config_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	__u8 result = showConfigurationBits();
	return sprintf(buf, "%u", result);
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
	status = setConfigBits(config);
	if (status != 0) {
		// bad input to configuration - we ignore it.
		printk("wTf\n");
	}
	kfree(config);
	return count;
}

static ssize_t rules_size_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	int size = RULE_BASE_ENTRIES * sizeof(rule_t);
	return sprintf(buf, "%d", size);
}

static ssize_t rules_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {
	return count;
}

static ssize_t log_size_show(struct device *dev, struct device_attribute *attr,
		char *buf) {
	int size = LOG_ENTRIES * sizeof(log_row_t);
	return sprintf(buf, "%d", size);
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
	if (count == 1)
		clearLog();
	return count;
}

static ssize_t conn_tab_size_show(struct device *dev,
		struct device_attribute *attr, char *buf) {
	int size = CONNECTION_TABLE_ENTRIES * sizeof(connection_t);
	return sprintf(buf, "%d", size);
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

static void loadInitialRules(void) {
	int i;
	__u8 prot[] = { PROT_ICMP, PROT_TCP, PROT_UDP, 255 };

	for (i = 0; i < 4; i++) {
		kmalloc_ptr_rule[i].protocol = prot[i];
		kmalloc_ptr_rule[i].src_mask = (__u8 ) 32;
		kmalloc_ptr_rule[i].dst_mask = (__u8 ) 32;
		kmalloc_ptr_rule[i].action = (__u8 ) NF_ACCEPT;
		kmalloc_ptr_rule[i].src_port = htons(0);
		kmalloc_ptr_rule[i].dst_port = htons(0);
		kmalloc_ptr_rule[i].src_ip = LOCALHOST;
		kmalloc_ptr_rule[i].dst_ip = LOCALHOST;
	}
}

static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)) {
	int result = 0;
	sock_buff = skb;
	hook_num = hooknum;
	ip_header = ip_hdr(sock_buff);

	if (ip_header->version != IPV4) {
		writeToLog(hooknum, NF_ACCEPT, REASON_NOT_IPV4);
		return NF_DROP;
	}
	if (ip_header->protocol == PROT_TCP) {
		tcp_header =
				(struct tcphdr*) ((char*) ip_header + (ip_header->ihl * 4));
	} else if (ip_header->protocol == PROT_UDP) {
		udp_header =
				(struct udphdr*) ((char*) ip_header + (ip_header->ihl * 4));
		//udp_header = udp_hdr(sock_buff);
	}
	if (active == 0) {
		writeToLog(hooknum, NF_ACCEPT, REASON_FW_INACTIVE);
		return NF_ACCEPT;
	}
	if (ip_header->saddr == LOCALHOST) {
		return NF_ACCEPT;
	}

	if (ip_header->protocol == PROT_TCP && tcp_active) {
		//check rules
		result = checkRules(0);
		if (result == NF_DROP) {
			writeToLog(hooknum, NF_DROP, rule_num);
			return NF_DROP;
		} else if (result == 2) {
			if (cleanup_accept == 0) {
				writeToLog(hooknum, NF_DROP, REASON_NO_MATCHING_RULE);
				return NF_DROP;
			}
		}
		//check christmas paket
		if (christmas()) {
			writeToLog(hooknum, NF_DROP, REASON_XMAS_PACKET);
			return NF_DROP;
		}
		if (conn_track) {
			int conn = findConversation();
			printk("found conversation: %d\n", conn);
			if (conn == -1) {
				//create connection
				printk("create conversation: syn %u ack %u fin %u rst %u\n",
						tcp_header->syn, tcp_header->ack, tcp_header->fin,
						tcp_header->rst);
				if (tcp_header->syn == 1 && tcp_header->ack == 0) {
					result = createConversation();
					printk("create conversation: result %d\n", result);
					if (result == 1) {
						writeToLog(hooknum, NF_DROP,
								REASON_CONNECTION_TABLE_FULL);
						return NF_DROP;
					}
				} else {
					//out of connection
					printk("TCP out of connection\n");
					writeToLog(hooknum, NF_DROP, REASON_OUT_OF_STATE);
					return NF_DROP;
				}
			} else {
				//connection exists
				result = updateConversation(conn);
				if (result == 1) {
					writeToLog(hooknum, NF_DROP, REASON_OUT_OF_STATE);
					return NF_DROP;
				}
			}

		}

	} else if (ip_header->protocol == PROT_TCP && !tcp_active) {
		writeToLog(hooknum, NF_ACCEPT, REASON_PROT_NOT_ENFORCED);
		return NF_ACCEPT;

	} else if (ip_header->protocol == PROT_UDP && udp) {
		//check rules
		result = checkRules(0);
		if (result == 0) {
			writeToLog(hooknum, NF_DROP, rule_num);
			return NF_DROP;
		} else if (result == 2) {
			if (cleanup_accept == 0) {
				writeToLog(hooknum, NF_DROP, REASON_NO_MATCHING_RULE);
				return NF_DROP;
			}
		}
	} else if (ip_header->protocol == PROT_UDP && !udp) {
		writeToLog(hooknum, NF_ACCEPT, REASON_PROT_NOT_ENFORCED);
		return NF_ACCEPT;
	} else if (ip_header->protocol == PROT_ICMP && icmp) {
		//check rules
		result = checkRules(0);
		if (result == 0) {
			writeToLog(hooknum, NF_DROP, rule_num);
			return NF_DROP;
		} else if (result == 2) {
			if (cleanup_accept == 0) {
				writeToLog(hooknum, NF_DROP, REASON_NO_MATCHING_RULE);
				return NF_DROP;
			}
		}
	} else if (ip_header->protocol == PROT_ICMP && !icmp) {
		writeToLog(hooknum, NF_ACCEPT, REASON_PROT_NOT_ENFORCED);
		return NF_ACCEPT;
	} else {
		//check rules with zeroed ports
		result = checkRules(1);
		if (result == 0) {
			writeToLog(hooknum, NF_DROP, rule_num);
			return NF_DROP;
		} else if (result == 2) {
			if (cleanup_accept == 0) {
				writeToLog(hooknum, NF_DROP, REASON_NO_MATCHING_RULE);
				return NF_DROP;
			}
		}
	}

	if (rule_num == -1) {
		writeToLog(hooknum, NF_ACCEPT, REASON_NO_MATCHING_RULE);
		return NF_ACCEPT;
	} else {
		writeToLog(hooknum, NF_ACCEPT, rule_num);
		return NF_ACCEPT;
	}
}
/*
 * loader - This is the initial loader function that creates the class, devices, attributes and all the other stuff.
 */
static int hello_init(void) {
	int i;
	int j;
	int err = 0;
	dev_t dev = 0;
// TODO: check not ipv4

	nfho_forward.hook = hook_func;
	nfho_forward.hooknum = NF_INET_FORWARD;
	nfho_forward.pf = PF_INET;
	nfho_forward.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_forward);
	nfho_in.hook = hook_func;
	nfho_in.hooknum = NF_INET_LOCAL_IN;
	nfho_in.pf = PF_INET;
	nfho_in.priority = 0;
	nf_register_hook(&nfho_in);
	nfho_out.hook = hook_func;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);

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

	char *rules[] = { "/bin/bash", "-c", "/bin/chmod 666 /dev/fw4_rules", NULL };
	call_usermodehelper(rules[0], rules, 0, UMH_WAIT_PROC);

	err = construct_device(&devices[DEVICE_LOG], MINOR_LOG, fw_class,
			DEVICE_NAME_LOG, &log_fops);
	if (err) {
		printk("FW4: Failed to create the second device\n");
		classAndDevicesCleanUP();
		return 1;
	}
	devices_to_destroy++;
	char *log[] = { "/bin/bash", "-c", "/bin/chmod 644 /dev/fw4_log", NULL };
	call_usermodehelper(log[0], log, 0, UMH_WAIT_PROC);

	err = construct_device(&devices[DEVICE_CONN_TAB], MINOR_CONN_TAB, fw_class,
			DEVICE_NAME_CONN_TAB, &conn_tab_fops);
	if (err) {
		printk("FW4: Failed to create the third device\n");
		classAndDevicesCleanUP();
		return 1;
	}
	devices_to_destroy++;
	char *conn[] =
			{ "/bin/bash", "-c", "/bin/chmod 644 /dev/fw4_conn_tab", NULL };
	call_usermodehelper(conn[0], conn, 0, UMH_WAIT_PROC);

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
	loadInitialRules();
	return 0;
}

/* unloader - This function releases all the allocated memory if we remove the module. */
static void hello_cleanup(void) {
	nf_unregister_hook(&nfho_forward);
	nf_unregister_hook(&nfho_in);
	nf_unregister_hook(&nfho_out);
	classAndDevicesAndAttributesCleanUP();
	newMmapCleanup();
	return;
}

module_init(hello_init)
;
module_exit(hello_cleanup)
;
