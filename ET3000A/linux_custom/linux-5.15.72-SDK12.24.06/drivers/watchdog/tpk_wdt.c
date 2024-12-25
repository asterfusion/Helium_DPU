#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/miscdevice.h>
#include <linux/watchdog.h>
#include <linux/fs.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>   
#include <linux/wait.h>
#include <linux/ioport.h>
#include <linux/completion.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/version.h>

#define DRV_NAME	"tera_wdt"
#define DRV_VERSION	"1.1"

//#define GHC83N
#define GHC96N
//#define ET2500

#ifdef GHC83N
    #define GPIO_BASE_ADDR 432
    #define ET1528_WDT_GPIO (GPIO_BASE_ADDR+34)
    #define ET1528_WDT_FEED_GPIO (GPIO_BASE_ADDR+16)
#elif defined(GHC96N)
    #define GPIO_BASE_ADDR 448
    #define ET1528_WDT_GPIO (GPIO_BASE_ADDR+32)
    #define ET1528_WDT_FEED_GPIO (GPIO_BASE_ADDR+33)
#elif defined(ET2500)
	#if LINUX_VERSION_CODE == KERNEL_VERSION(6, 6, 58)
		#define GPIO_BASE_ADDR 512  //yocto
	#else
		#define GPIO_BASE_ADDR 464
	#endif
    #define ET1528_WDT_FEED_GPIO (GPIO_BASE_ADDR+45) //gpio 45
#endif
int dog_start;


#define TIMER_MARGIN	60		/* Default is 60 seconds */
static int soft_margin = TIMER_MARGIN;	/* in seconds */
module_param(soft_margin, int, 0);
MODULE_PARM_DESC(soft_margin,
	"Watchdog soft_margin in seconds. (0 < soft_margin < 65536, default="
					__MODULE_STRING(TIMER_MARGIN) ")");

static int nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, int, 0);
MODULE_PARM_DESC(nowayout,
		"Watchdog cannot be stopped once started (default="
				__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

#ifdef ONLY_TESTING
static int soft_noboot = 1;
#else
static int soft_noboot = 0;
#endif  /* ONLY_TESTING */

module_param(soft_noboot, int, 0);
MODULE_PARM_DESC(soft_noboot,
	"Asterfusion_WatchDog action, set to 1 to ignore reboots, 0 to reboot "
					"(default depends on ONLY_TESTING)");

static int soft_panic;
module_param(soft_panic, int, 0);
MODULE_PARM_DESC(soft_panic,
	"Softdog action, set to 1 to panic, 0 to reboot (default=0)");

static char *soft_reboot_cmd;
module_param(soft_reboot_cmd, charp, 0000);
MODULE_PARM_DESC(soft_reboot_cmd,
	"Set reboot command. Emergency reboot takes place if unset");

static struct task_struct *task_tpk;
/*
 *	Our timer
 */

static struct hrtimer watchdog_ticktock;


/*
 *	If the timer expires..
 */
static int reboot_kthread_fn(void *data)
{
	kernel_restart(soft_reboot_cmd);
	return -EPERM; /* Should not reach here */
}

static void reboot_work_fn(struct work_struct *unused)
{
	kthread_run(reboot_kthread_fn, NULL, "watchdog_reboot");
}


static enum hrtimer_restart watchdog_fire(struct hrtimer *timer)
{
	static bool soft_reboot_fired;

	module_put(THIS_MODULE);
	if (soft_noboot) {
		pr_crit("Triggered - Reboot ignored\n");
	} else if (soft_panic) {
		pr_crit("Initiating panic\n");
		panic("Software Watchdog Timer expired");
	} else {
		pr_crit("Initiating system reboot\n");
		if (!soft_reboot_fired && soft_reboot_cmd != NULL) {
			static DECLARE_WORK(reboot_work, reboot_work_fn);
			/*
			 * The 'kernel_restart' is a 'might-sleep' operation.
			 * Also, executing it in system-wide workqueues blocks
			 * any driver from using the same workqueue in its
			 * shutdown callback function. Thus, we should execute
			 * the 'kernel_restart' in a standalone kernel thread.
			 * But since starting a kernel thread is also a
			 * 'might-sleep' operation, so the 'reboot_work' is
			 * required as a launcher of the kernel thread.
			 *
			 * After request the reboot, restart the timer to
			 * schedule an 'emergency_restart' reboot after
			 * 'TIMER_MARGIN' seconds. It's because if the softdog
			 * hangs, it might be because of scheduling issues. And
			 * if that is the case, both 'schedule_work' and
			 * 'kernel_restart' may possibly be malfunctional at the
			 * same time.
			 */
			soft_reboot_fired = true;
			schedule_work(&reboot_work);
			hrtimer_add_expires_ns(timer,
					(u64)TIMER_MARGIN * NSEC_PER_SEC);

			return HRTIMER_RESTART;
		}
		emergency_restart();
		pr_crit("Reboot didn't ?????\n");
	}

	return HRTIMER_NORESTART;
}

/*
 *	Softdog operations
 */


static int softdog_stop(void)
{
    if(!IS_ERR(task_tpk) && dog_start){
        kthread_stop(task_tpk);
    }
	if (hrtimer_cancel(&watchdog_ticktock))
		module_put(THIS_MODULE);

	return 0;
}

static int tpk_wdt_kick(void)
{
    gpio_direction_output(ET1528_WDT_FEED_GPIO, 1);
    msleep(700);
    gpio_direction_output(ET1528_WDT_FEED_GPIO, 0);
    msleep(300);
    return 0;
}


static int  thread_feed_dog(void *data)
{
    do{
        gpio_direction_output(ET1528_WDT_FEED_GPIO, 1);
        msleep(700);
        gpio_direction_output(ET1528_WDT_FEED_GPIO, 0);
        msleep(300);

    }while(!kthread_should_stop());

	return 0;
}
/*
 *	/dev/watchdog handling
 */

static int softdog_open(struct inode *inode, struct file *file)
{
    return nonseekable_open(inode, file);
}

static int softdog_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t softdog_write(struct file *file, const char __user *data,
						size_t len, loff_t *ppos)
{
	return len;
}

static long softdog_ioctl(struct file *file, unsigned int cmd,
							unsigned long arg)
{
    int new_options, retval = -EINVAL;
    int __user *argp = (void __user *)arg;

    //pr_info( " cmd is %d\n", cmd);
	switch(cmd){
        case WDIOC_SETOPTIONS:
            if (get_user(new_options, argp))
                return -EFAULT;
            if (new_options & WDIOS_DISABLECARD) {
                pr_info( "stop watchdog\n");
#ifdef ET2500
    //start gpio from cpld control, to do
#else
                gpio_direction_output(ET1528_WDT_GPIO, 1); //stop watchdog
#endif
            }
            if (new_options & WDIOS_ENABLECARD) {
                pr_info( "start watchdog\n");
                tpk_wdt_kick();
#ifdef ET2500
    //start gpio from cpld control, to do
#else
                gpio_direction_output(ET1528_WDT_GPIO, 0); //start watchdog
#endif
                tpk_wdt_kick();
            }
            return 0;

        case WDIOC_KEEPALIVE:
            tpk_wdt_kick();
            //pr_info( "kick watchdog once\n");
            return 0;

		case 0:
			if(!IS_ERR(task_tpk) && dog_start){
#ifdef ET2500
    //start gpio from cpld control, to do
#else
                gpio_direction_output(ET1528_WDT_GPIO, 1); //stop watchdog
#endif
                msleep(1000);
                kthread_stop(task_tpk);
				pr_info( "stop kthread and watchdog\n");
				dog_start = 0;
			}
			return 1;
	}
	return 0;
}

/*
 *	Notifier for system down
 */

static int softdog_notify_sys(struct notifier_block *this, unsigned long code,
	void *unused)
{
    pr_err( "tera_wdt get notify code %ld\n", code);
	if (code == SYS_DOWN || code == SYS_HALT)
		softdog_stop();
	return NOTIFY_DONE;
}

/*
 *	Kernel Interfaces
 */

static const struct file_operations softdog_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.write		= softdog_write,
	.unlocked_ioctl	= softdog_ioctl,
	.open		= softdog_open,
	.release	= softdog_release,
};

static struct miscdevice softdog_miscdev = {
	.minor	    = WATCHDOG_MINOR,
	.name		= "watchdog",
	.fops		= &softdog_fops,
};

static struct notifier_block softdog_notifier = {
	.notifier_call	= softdog_notify_sys,
};


static int __init watchdog_init(void)
{
	int ret = 0;
	dog_start = 0;

	ret = misc_register(&softdog_miscdev);
	if (ret) {
		pr_err( "cannot register miscdev on minor=%d (err=%d)\n",
						softdog_miscdev.minor, ret);
		return ret;
	}
    register_reboot_notifier(&softdog_notifier);
    register_restart_handler(&softdog_notifier);

	hrtimer_init(&watchdog_ticktock, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	watchdog_ticktock.function = watchdog_fire;

    task_tpk = kthread_run(thread_feed_dog, NULL, DRV_NAME"_thread");
    msleep(1000);

#ifdef ET2500
    //start gpio from cpld control, to do
#else
	gpio_direction_output(ET1528_WDT_GPIO, 0); //start watchdog
#endif
    dog_start = 1;

	pr_info("Asterfusion initialized. soft_noboot=%d soft_margin=%d sec soft_panic=%d (nowayout=%d)\n",
		soft_noboot, soft_margin, soft_panic, nowayout);
	pr_info("             soft_reboot_cmd=%s \n", soft_reboot_cmd ?: "<not set>");

	return 0;
}

static void __exit watchdog_exit(void)
{
    pr_info( "tera_wdt exit\n");
    misc_deregister(&softdog_miscdev);
	unregister_reboot_notifier(&softdog_notifier);
    unregister_restart_handler(&softdog_notifier);
    softdog_stop();
}

module_init(watchdog_init);
module_exit(watchdog_exit);

MODULE_AUTHOR("marvin");
MODULE_DESCRIPTION("Asterfusion Watchdog Device Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_ALIAS_MISCDEV(WATCHDOG_MINOR);
MODULE_ALIAS(DRV_NAME);
