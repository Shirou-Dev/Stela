// SPDX-License-Identifier: GPL-2.0-or-later
/* Linux's kernel messages, each delivered formatted to the running owner's
 * log at its level. Messages longer than Linux's 1024-byte records are cut
 * as Linux cuts them. */
#include <linux/device.h>
#include <linux/irqflags.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/sprintf.h>
#include <stela/linux.h>

/* The level a message's prefixes give, after which its text starts. */
static int level_of(const char **fmt)
{
	int level = MESSAGE_LOGLEVEL_DEFAULT;
	for (int kind; (kind = printk_get_level(*fmt)); *fmt += 2)
		if (kind >= '0' && kind <= '7')
			level = kind - '0';
	return level;
}

/* The selected Linux CPU is serialized. Buffer a bounded prefix while the
 * caller holds source locks; the next safe drain reports any dropped tail.
 * Lockup reports such as show_all_workqueues print dozens of lines under a
 * pool lock, so keep 64 KiB, half of Linux's default 128 KiB ring. */
#define DEFERRED_RECORDS 64
struct log_record {
	int level;
	char text[1024];
};
static struct log_record deferred[DEFERRED_RECORDS];
static unsigned int deferred_depth, deferred_count, deferred_dropped;
static const struct stela_linux_owner *deferred_owner;
static bool flushing;

void __printk_deferred_enter(void)
{
	(void)stela_linux_owner();
	if (!irqs_disabled() || deferred_depth == UINT_MAX)
		return;
	deferred_depth++;
}

void __printk_deferred_exit(void)
{
	(void)stela_linux_owner();
	if (!irqs_disabled() || !deferred_depth)
		return;
	deferred_depth--;
}

void stela_linux_printk_flush(void)
{
	if (flushing || (!deferred_owner && !deferred_depth) || !stela_linux_quiescent())
		return;
	if (deferred_depth)
		return; /* The original scope must end before IRQ restoration. */
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (owner != deferred_owner)
		return;
	flushing = true;
	for (unsigned int i = 0; i < deferred_count; i++)
		owner->services->log(owner->context, deferred[i].level, deferred[i].text);
	if (deferred_dropped) {
		char warning[64];
		scnprintf(warning, sizeof(warning), "printk: dropped %u deferred records\n",
			  deferred_dropped);
		owner->services->log(owner->context, LOGLEVEL_WARNING, warning);
	}
	deferred_count = 0;
	deferred_dropped = 0;
	deferred_owner = NULL;
	flushing = false;
}

static int emit_record(int level, const char *fmt, va_list args, bool force_deferred)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	static char message[1024];
	if (flushing)
		return 0; /* The native log sink must not reenter Linux. */
	stela_linux_printk_flush();
	if (owner->services->log &&
	    (deferred_depth || deferred_owner || (force_deferred && !stela_linux_quiescent()))) {
		if (deferred_owner && deferred_owner != owner)
			return 0;
		deferred_owner = owner;
		if (deferred_count < DEFERRED_RECORDS) {
			struct log_record *record = &deferred[deferred_count++];
			record->level = level;
			return vscnprintf(record->text, sizeof(record->text), fmt, args);
		}
		if (deferred_dropped != UINT_MAX)
			deferred_dropped++;
		return vscnprintf(message, sizeof(message), fmt, args);
	}
	int length = vscnprintf(message, sizeof(message), fmt, args);
	if (owner->services->log)
		owner->services->log(owner->context, level, message);
	return length;
}

static int emit(int level, const char *fmt, va_list args)
{
	return emit_record(level, fmt, args, false);
}

static __printf(2, 3) void emitf(int level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	emit(level, fmt, args);
	va_end(args);
}

int vprintk(const char *fmt, va_list args)
{
	int level = level_of(&fmt);
	return emit(level, fmt, args);
}

int _printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int length = vprintk(fmt, args);
	va_end(args);
	return length;
}

int vprintk_deferred(const char *fmt, va_list args)
{
	int level = level_of(&fmt);
	return emit_record(level, fmt, args, true);
}

int _printk_deferred(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int length = vprintk_deferred(fmt, args);
	va_end(args);
	return length;
}

const char *dev_driver_string(const struct device *dev)
{
	struct device_driver *driver = READ_ONCE(dev->driver);
	return driver ? driver->name : dev_bus_name(dev);
}

/* A device's messages carry its driver and name, as Linux's do. */
static void dev_vprintk(const char *level, const struct device *dev, const char *fmt,
			va_list args)
{
	va_list copy;
	va_copy(copy, args);
	struct va_format vaf = {.fmt = fmt, .va = &copy};
	int number = level_of(&level);
	if (dev)
		emitf(number, "%s %s: %pV", dev_driver_string(dev), dev_name(dev), &vaf);
	else
		emitf(number, "(NULL device *): %pV", &vaf);
	va_end(copy);
}

void _dev_printk(const char *level, const struct device *dev, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	dev_vprintk(level, dev, fmt, args);
	va_end(args);
}

#define DEV_PRINTK(name, level)							\
void name(const struct device *dev, const char *fmt, ...)			\
{										\
	va_list args;								\
	va_start(args, fmt);							\
	dev_vprintk(level, dev, fmt, args);					\
	va_end(args);								\
}

DEV_PRINTK(_dev_emerg, KERN_EMERG)
DEV_PRINTK(_dev_alert, KERN_ALERT)
DEV_PRINTK(_dev_crit, KERN_CRIT)
DEV_PRINTK(_dev_err, KERN_ERR)
DEV_PRINTK(_dev_warn, KERN_WARNING)
DEV_PRINTK(_dev_notice, KERN_NOTICE)
DEV_PRINTK(_dev_info, KERN_INFO)

/* A WARN's message, which precedes the WARN itself. */
void __warn_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

/* Only the current function's saved return address is compiler-defined here.
 * Reading a caller's frame chain needs a retained native stack and its bounds.
 * The diagnostic precedes the unsupported report, which an owner may stop at. */
static void dump_caller(const char *level, const void *caller)
{
	const char *prefix = level;
	int number = level_of(&prefix);
	emitf(number, "Call trace incomplete: caller %px; stack unwinding unavailable\n", caller);
	stela_linux_unsupported("native stack unwinding");
}

noinline void dump_stack_lvl(const char *log_lvl)
{
	dump_caller(log_lvl, __builtin_extract_return_addr(__builtin_return_address(0)));
}

noinline void dump_stack(void)
{
	dump_caller(KERN_DEFAULT, __builtin_extract_return_addr(__builtin_return_address(0)));
}

#ifdef STELA_LINUX_PRINTK_TEST
#include <linux/string.h>
#include <stela/test.h>

static unsigned int messages;
static unsigned int missing;
static int observed_level;
static char observed[256];

static void test_log(void *context, int level, const char *message)
{
	assert(context == &messages);
	messages++;
	observed_level = level;
	size_t length = strlen(message);
	assert(length < sizeof(observed));
	memcpy(observed, message, length + 1);
}

static void test_missing(void *context, const char *operation)
{
	assert(context == &messages && messages == missing + 1);
	assert(!strcmp(operation, "native stack unwinding"));
	assert(strstr(observed, "Call trace incomplete: caller ") == observed);
	assert(strstr(observed, "; stack unwinding unavailable\n"));
	missing++;
}

static void trapping_missing(void *context, const char *operation)
{
	test_missing(context, operation);
	__builtin_trap();
}

static void trapping_trace(void)
{
	const struct stela_linux_services services = {.log = test_log, .unsupported = trapping_missing};
	const struct stela_linux_owner owner = {.services = &services, .context = &messages};
	stela_linux_enter(&owner);
	dump_stack();
}

static void deferred_records(void)
{
	unsigned int before = messages;
	unsigned long irq = arch_local_irq_save();
	printk_deferred_enter();
	printk_deferred_enter();
	pr_info("one");
	printk_deferred_exit();
	pr_info("two");
	printk_deferred_exit();
	for (int record = 2; record < DEFERRED_RECORDS; record++)
		printk_deferred(KERN_INFO "more");
	printk_deferred(KERN_INFO "dropped");
	assert(messages == before);
	arch_local_irq_restore(irq);
	assert(messages == before + DEFERRED_RECORDS + 1);
	assert(observed_level == LOGLEVEL_WARNING &&
	       !strcmp(observed, "printk: dropped 1 deferred records\n"));
	messages = before;
}

static void outside_owner(void)
{
	dump_stack();
}

int main(void)
{
	const struct stela_linux_services services = {.log = test_log, .unsupported = test_missing};
	const struct stela_linux_owner owner = {.services = &services, .context = &messages};
	stela_linux_enter(&owner);
	/* A known address checks the actual formatter and diagnostic ordering;
	 * the public entry points below capture a real, nonzero saved caller. */
	dump_caller(KERN_ERR, (const void *)0x1234UL);
	assert(observed_level == LOGLEVEL_ERR && strstr(observed, "0000000000001234;"));
	dump_stack_lvl(KERN_WARNING);
	assert(observed_level == LOGLEVEL_WARNING && !strstr(observed, "0000000000000000;"));
	dump_stack();
	assert(observed_level == MESSAGE_LOGLEVEL_DEFAULT && missing == 3);
	deferred_records();
	stela_linux_exit();
	assert(stela_test_traps(trapping_trace));
	assert(stela_test_traps(outside_owner));
	printf("Linux stack diagnostic: caller, severity, missing-unwinder policy passed\n");
	return 0;
}
#endif
