// SPDX-License-Identifier: GPL-2.0-or-later
/* Synchronous firmware requests route only through their actual enrolled
 * device authority. Each result owns a complete independent immutable copy. */
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <stela/catalogue.h>
#include <stela/firmware.h>
#include <stela/linux.h>
#include <stela/task.h>

/* Keep the exact heap layout private: public firmware metadata is immutable to
 * consumers, and freeing does not need either that size or a borrowed owner.
 * The first member permits converting a public handle back to its allocation. */
struct snapshot {
	struct firmware firmware;
	size_t allocation_bytes;
};

#ifdef STELA_LINUX_FIRMWARE_TEST
#include <stela/test.h>
static bool fail_snapshot_allocation;
static size_t live_snapshots, allocated_bytes, released_bytes, allocation_calls;
#endif

static struct snapshot *allocate_snapshot(size_t bytes)
{
#ifdef STELA_LINUX_FIRMWARE_TEST
	/* Bounded failure at the sole acquisition; no production allocator swap. */
	if (fail_snapshot_allocation)
		return NULL;
	allocation_calls++;
#endif
	struct snapshot *snapshot = stela_linux_heap_alloc(bytes, __alignof__(struct snapshot));
#ifdef STELA_LINUX_FIRMWARE_TEST
	if (snapshot) {
		live_snapshots++;
		allocated_bytes += bytes;
	}
#endif
	return snapshot;
}

static void check_scope(const struct stela_linux_lease *scope)
{
	/* Saved immutable identity only, not an entered/config borrow. A real
	 * task park/resume preserves it; full exit/reentry cannot substitute. */
	if (!stela_linux_lease_matches(scope) || !stela_linux_quiescent())
		__builtin_trap();
}
static int copy_snapshot(const struct firmware **out, const char *name,
                         const void *authority, const struct stela_linux_lease *scope,
                         bool *provider_refused)
{
	const u8 *data = NULL;
	size_t size = 0;
	int status = stela_linux_firmware_image(authority, name, &data, &size);
	check_scope(scope);
	if (status) {
		*provider_refused = true;
		return status;
	}
	if (!size)
		return -ENOENT;
	if (!data)
		return -EBADMSG;
	size_t maximum = (size_t)SSIZE_MAX & ~((size_t)__alignof__(struct snapshot) - 1);
	if (size > maximum - sizeof(struct snapshot) ||
	    (unsigned long)data > ULONG_MAX - size)
		return -EOVERFLOW;
	/* Real acquired device/root refs retain the exact source/configuration,
	 * code queue and immutable Catalog until this copy finishes. */
	size_t bytes = sizeof(struct snapshot) + size;
	struct snapshot *snapshot = allocate_snapshot(bytes);
	check_scope(scope);
	if (!snapshot)
		return -ENOMEM;
	snapshot->allocation_bytes = bytes;
	snapshot->firmware.size = size;
	u8 *payload = (u8 *)(snapshot + 1);
	snapshot->firmware.data = payload;
	memcpy(payload, data, size);
	*out = &snapshot->firmware;
	return 0;
}
static int load(const struct firmware **out, const char *name, struct device *device, bool warn)
{
	(void)stela_linux_owner();
	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!name || !*name)
		return -EINVAL;
	if (!stela_linux_quiescent()) {
		stela_linux_unsupported("firmware request context");
		return -EOPNOTSUPP;
	}
	struct stela_linux_lease scope;
	stela_linux_lease_snapshot(&scope);
	struct stela_linux_device_lease source;
	int status = stela_linux_device_acquire(device, &source);
	bool acquired = !status, provider_refused = false;
	const struct firmware *result = NULL;
	if (acquired)
		status = copy_snapshot(&result, name, source.authority, &scope, &provider_refused);
	check_scope(&scope);
	if (status && warn && (!acquired || provider_refused))
		dev_warn(device, "Direct firmware load for %s failed with error %d\n", name, status);
	check_scope(&scope);
	/* No catalogue mutable borrow survives provider/copy/diagnostic/release.
	 * Final put may self-unbind/free the original device; never touch it next. */
	if (acquired && stela_linux_device_release(&source))
		__builtin_trap();
	check_scope(&scope);
	if (!status)
		*out = result;
	dev_info(device, "request_firmware: %s (status=%d)\n", name, status);
	return status;
}
int request_firmware(const struct firmware **fw, const char *name, struct device *device)
{
	return load(fw, name, device, true);
}
int firmware_request_nowarn(const struct firmware **fw, const char *name, struct device *device)
{
	return load(fw, name, device, false);
}
int request_firmware_direct(const struct firmware **fw, const char *name, struct device *device)
{
	return load(fw, name, device, false);
}

void release_firmware(const struct firmware *fw)
{
	if (!fw)
		return;
	const struct snapshot *snapshot = (const struct snapshot *)fw;
#ifdef STELA_LINUX_FIRMWARE_TEST
	assert(live_snapshots);
	live_snapshots--;
	released_bytes += snapshot->allocation_bytes;
#endif
	stela_linux_heap_free((void *)snapshot, snapshot->allocation_bytes,
			      __alignof__(struct snapshot));
}

#ifdef STELA_LINUX_FIRMWARE_TEST
#include <stela/firmware_test.c>
#endif
