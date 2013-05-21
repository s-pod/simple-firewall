#include "fw4.h"
#include "conn_manager.h"
#include "log_manager.h"
#include "rule_manager.h"

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
	struct cdev cdev;
	struct device *dev;
};

MODULE_LICENSE("GPL")
;

//static int newMmapInit(void);
//static void newMmapCleanup(void);
//static int construct_device(struct fw_dev *dev, int minor, struct class *class,
//		char *name, struct file_operations *fops);
//static void destroy_device(struct fw_dev *dev, int minor, struct class *class);
//static void classCleanUp(void);
//static void classAndDevicesStructCleanUp(void);
//static void classAndDevicesCleanUP(void);
//static void classAndDevicesAndAttributesCleanUP(void);
//static int returnBit(long flag, int i);
//
//
//static ssize_t rules_config_show(struct device *dev,
//		struct device_attribute *attr, char *buf);
//static ssize_t rules_config_store(struct device *dev,
//		struct device_attribute *attr, const char *buf, size_t count);
//static ssize_t rules_size_show(struct device *dev,
//		struct device_attribute *attr, char *buf);
//static ssize_t rules_size_store(struct device *dev,
//		struct device_attribute *attr, const char *buf, size_t count);
//static ssize_t log_size_show(struct device *dev, struct device_attribute *attr,
//		char *buf);
//static ssize_t log_size_store(struct device *dev, struct device_attribute *attr,
//		const char *buf, size_t count);
//static ssize_t log_clear_show(struct device *dev, struct device_attribute *attr,
//		char *buf);
//static ssize_t log_clear_store(struct device *dev,
//		struct device_attribute *attr, const char *buf, size_t count);
//static ssize_t conn_tab_size_show(struct device *dev,
//		struct device_attribute *attr, char *buf);
//static ssize_t conn_tab_size_store(struct device *dev,
//		struct device_attribute *attr, const char *buf, size_t count);
//static ssize_t conn_tab_clear_show(struct device *dev,
//		struct device_attribute *attr, char *buf);
//static ssize_t conn_tab_clear_store(struct device *dev,
//		struct device_attribute *attr, const char *buf, size_t count);
//
//static int fw4_rules_mmap(struct file *file, struct vm_area_struct *vma);
//static int fw4_log_mmap(struct file *file, struct vm_area_struct *vma);
//static int fw4_conn_tab_mmap(struct file *file, struct vm_area_struct *vma);
//
//static int rules_open(struct inode *inode, struct file *filp);
//static int log_open(struct inode *inode, struct file *filp);
//static int conn_tab_open(struct inode *inode, struct file *filp);
//static int rules_release(struct inode *inode, struct file *filp);
//static int log_release(struct inode *inode, struct file *filp);
//static int conn_tab_release(struct inode *inode, struct file *filp);


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

struct timeval time;
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

 /*
  * This function checks to see if a string str is a number that *int*
  * If True it returns the value in *num.
  * Return Value:
  * 				 0 = all good - the number is in unsigned int range
  * 				-1 = There was an error in the parsing
  */
 static int checkInt(char *str, int *num) {
 	// long result, status;
 	// if (strlen(str) > MAX_INT_LENGTH) {
 	// 	return -1;
 	// }
 	// status = kstrtol(str, BASE, &result);
 	// if (status == -ERANGE || status == -EINVAL) {
 	// 	*num = 0;
 	// 	return -1;
 	// }
 	// *num = (int) result;
 	return 0;
 }



static int getConfigBits(char *config){
	long temp;
	int status = checkUInt(config, &temp);
	if (status != 0){
		return -1;
	}
	active = returnBit(temp, FW_CONFIG_ACTIVE);
	icmp = returnBit(temp, FW_CONFIG_ICMP);
	tcp = returnBit(temp, FW_CONFIG_TCP);
	udp = returnBit(temp, FW_CONFIG_UDP);
	conn_track = returnBit(temp, FW_CONFIG_CONN_TRACK);
	cleanup_accept = returnBit(temp, FW_CONFIG_CLEANUP_ACCEPT);

	return 0;
}

static int returnBit(long flag, int i){
	int shift = sizeof(long)*BITS_IN_BYTE;
	int temp = (flag << (shift - i)) >> (shift -1);
	return temp;

}

static int showConfigurationBits(void){
	//******;
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
	if (status != 0){
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
	// TODO: to add here protection agains strings and long numbers?!
	if (count > 0)
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

	// TODO: to add here protection against strings  and long numbers?
	if (count > 0)
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

static unsigned int hook_func(unsigned int hooknum,
                        struct sk_buff *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn)(struct sk_buff *))
{
        sock_buff = skb;
        printk("Woohoo a packet!\n");
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

	nfho.hook     = hook_func;
	nfho.hooknum  = 0;
	nfho.pf       = PF_INET;
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

module_init(hello_init)
;
module_exit(hello_cleanup)
;
