// SPDX-License-Identifier: GPL-2.0-only
/* Linux's PCI core. Stela's own PCI owners enumerate, power and map
 * functions; Linux drivers match against their tables and reach the function
 * through the pci_ops the owner gives its bus. */
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <stela/device.h>
#include <stela/linux.h>
#include <stela/pci.h>
#include <stela/catalogue.h>
#include <unsupported.h>

/* An ID field matches its value or, as PCI_ANY_ID, any value. */
static bool id_matches(u32 id, u32 value)
{
	return id == (u32)PCI_ANY_ID || id == value;
}

/* The first entry before the table's all-zero terminator that matches. */
const struct pci_device_id *pci_match_id(const struct pci_device_id *ids, struct pci_dev *dev)
{
	for (; ids && (ids->vendor || ids->subvendor || ids->class_mask); ids++)
		if (id_matches(ids->vendor, dev->vendor) && id_matches(ids->device, dev->device) &&
		    id_matches(ids->subvendor, dev->subsystem_vendor) &&
		    id_matches(ids->subdevice, dev->subsystem_device) &&
		    !((ids->class ^ dev->class) & ids->class_mask))
			return ids;
	return NULL;
}

/* Managed enabling and wake configuration, which no selected driver uses. */
STELA_UNSUPPORTED(int, pcim_enable_device, struct pci_dev *)
STELA_UNSUPPORTED(int, pci_wait_for_pending_transaction, struct pci_dev *)
STELA_UNSUPPORTED(int, pci_wake_from_d3, struct pci_dev *, bool)

/* Configuration space, through the bus's pci_ops, following
 * drivers/pci/access.c. Linux code runs in one context at a time, so
 * Linux's pci_lock has nothing to exclude. */
#define PCI_OP_READ(size, type, length, bad)                                                     \
	int pci_bus_read_config_##size(struct pci_bus *bus, unsigned int devfn, int pos,         \
				       type *value)                                               \
	{                                                                                        \
		u32 data = 0;                                                                    \
		if ((bad) || pos < 0 || pos > PCI_CFG_SPACE_EXP_SIZE - length)                                                                         \
			return PCIBIOS_BAD_REGISTER_NUMBER;                                      \
		int error = bus->ops->read(bus, devfn, pos, length, &data);                      \
		if (error)                                                                       \
			PCI_SET_ERROR_RESPONSE(value);                                           \
		else                                                                             \
			*value = (type)data;                                                     \
		return error;                                                                    \
	}                                                                                        \
	int pci_read_config_##size(const struct pci_dev *dev, int where, type *value)            \
	{                                                                                        \
		if (pci_dev_is_disconnected(dev)) {                                              \
			PCI_SET_ERROR_RESPONSE(value);                                           \
			return PCIBIOS_DEVICE_NOT_FOUND;                                         \
		}                                                                                \
		return pci_bus_read_config_##size(dev->bus, dev->devfn, where, value);           \
	}

#define PCI_OP_WRITE(size, type, length, bad)                                                    \
	int pci_bus_write_config_##size(struct pci_bus *bus, unsigned int devfn, int pos,        \
					type value)                                               \
	{                                                                                        \
		if ((bad) || pos < 0 || pos > PCI_CFG_SPACE_EXP_SIZE - length)                                                                         \
			return PCIBIOS_BAD_REGISTER_NUMBER;                                      \
		return bus->ops->write(bus, devfn, pos, length, value);                          \
	}                                                                                        \
	int pci_write_config_##size(const struct pci_dev *dev, int where, type value)            \
	{                                                                                        \
		if (pci_dev_is_disconnected(dev))                                                \
			return PCIBIOS_DEVICE_NOT_FOUND;                                         \
		return pci_bus_write_config_##size(dev->bus, dev->devfn, where, value);          \
	}

PCI_OP_READ(byte, u8, 1, false)
PCI_OP_READ(word, u16, 2, pos & 1)
PCI_OP_READ(dword, u32, 4, pos & 3)
PCI_OP_WRITE(byte, u8, 1, false)
PCI_OP_WRITE(word, u16, 2, pos & 1)
PCI_OP_WRITE(dword, u32, 4, pos & 3)

/* The standard capability list's entry for cap, or 0, as drivers/pci/pci.c
 * finds it; the bound stops a looped list. */
int stela_linux_pci_find_capability(struct pci_dev *dev, int cap, u8 *found)
{
    u16 status, entry;
    u8 pos;
    int error;
    *found = 0;
    error = pci_read_config_word(dev, PCI_STATUS, &status);
    if (error)
        return error;
    if (!(status & PCI_STATUS_CAP_LIST))
        return PCIBIOS_SUCCESSFUL;
    switch (dev->hdr_type) {
    case PCI_HEADER_TYPE_NORMAL:
    case PCI_HEADER_TYPE_BRIDGE:
        pos = PCI_CAPABILITY_LIST;
        break;
    case PCI_HEADER_TYPE_CARDBUS:
        pos = PCI_CB_CAPABILITY_LIST;
        break;
    default:
        return PCIBIOS_SUCCESSFUL;
    }
    error = pci_read_config_byte(dev, pos, &pos);
    if (error)
        return error;
    for (unsigned int bound = 48; bound && pos >= 0x40; bound--) {
        pos &= ~3;
        error = pci_read_config_word(dev, pos, &entry);
        if (error)
            return error;
        if ((entry & 0xff) == 0xff)
            break;
        if ((entry & 0xff) == cap) {
            *found = pos;
            break;
        }
        pos = (u8)(entry >> 8);
    }
    return PCIBIOS_SUCCESSFUL;
}

u8 pci_find_capability(struct pci_dev *dev, int cap)
{
    u8 found;
    if (stela_linux_pci_find_capability(dev, cap, &found))
        stela_linux_fatal("PCI capability access failed without a result");
    return found;
}

const struct bus_type pci_bus_type = {.name = "pci"};

/* The devices their owners registered and the drivers bound to them, as
 * drivers/pci/pci-driver.c matches and probes. */
struct registered_driver {
	struct list_head node;
	struct pci_driver *driver;
};

static LIST_HEAD(devices);
static LIST_HEAD(drivers);

static void bind(struct pci_driver *driver, struct pci_dev *dev)
{
	const struct pci_device_id *id = pci_match_id(driver->id_table, dev);

	if (dev->driver || !id)
		return;
	dev->driver = driver;
	dev->dev.driver = &driver->driver;
	dev_info(&dev->dev, "%s: probe starting\n", driver->name);
	int error = driver->probe(dev, id);
	dev_info(&dev->dev, "%s: probe returned %d\n", driver->name, error);

	if (!error)
		return;
	if (error != -ENODEV)
		dev_err(&dev->dev, "%s: probe failed: %pe\n", driver->name, ERR_PTR(error));
	stela_linux_devres_release(&dev->dev);
	dev->dev.driver = NULL;
	dev->driver = NULL;
}

static void unbind(struct pci_dev *dev)
{
	struct pci_driver *driver = dev->driver;

	if (!driver)
		return;
	if (driver->remove)
		driver->remove(dev);
	stela_linux_devres_release(&dev->dev);
	dev->dev.driver = NULL;
	dev->driver = NULL;
}

bool stela_linux_pci_devices_present(void)
{
	return !list_empty(&devices);
}

int stela_linux_pci_publish_device(struct pci_dev *dev)
{
	struct registered_driver *registered;
	if (!stela_linux_device_publish_allowed(&dev->dev))
		return -EPERM;

	dev->dev.bus = &pci_bus_type;
	list_add_tail(&dev->bus_list, &devices);
	list_for_each_entry(registered, &drivers, node)
		bind(registered->driver, dev);
	return 0;
}

bool stela_linux_pci_bound(const struct pci_dev *device)
{
	return device->dev.driver;
}

/* What the kernel's shutdown does of a device: its driver stops the hardware. */
void stela_linux_pci_shutdown(struct pci_dev *dev)
{
	if (dev->driver && dev->driver->shutdown)
		dev->driver->shutdown(dev);
}

void stela_linux_pci_remove_device(struct pci_dev *dev)
{
	stela_linux_device_close(&dev->dev);
	unbind(dev);
	list_del(&dev->bus_list);
	put_device(&dev->dev);
}

int __pci_register_driver(struct pci_driver *driver, struct module *owner, const char *name)
{
	struct registered_driver *registered = kmalloc_obj(*registered);
	struct pci_dev *dev;

	(void)owner;
	if (!registered)
		return -ENOMEM;
	driver->driver.name = driver->name;
	driver->driver.mod_name = name;
	registered->driver = driver;
	list_add_tail(&registered->node, &drivers);
	list_for_each_entry(dev, &devices, bus_list)
		bind(driver, dev);
	return 0;
}

void pci_unregister_driver(struct pci_driver *driver)
{
	struct registered_driver *registered;
	struct pci_dev *dev;

	list_for_each_entry(registered, &drivers, node)
		if (registered->driver == driver) {
			list_del(&registered->node);
			kfree(registered);
			break;
		}
	list_for_each_entry(dev, &devices, bus_list)
		if (dev->driver == driver)
			unbind(dev);
}

/* Owners keep their bridges' hotplug slots out of a driver's power cycles. */
void pci_ignore_hotplug(struct pci_dev *dev)
{
	dev->ignore_hotplug = 1;
}

/* The standard header, which is what a function loses in D3, following
 * drivers/pci/pci.c. */
int pci_save_state(struct pci_dev *dev)
{
    enum { SAVED_DWORDS = 16 };
    u32 saved[SAVED_DWORDS];
    int error;
    for (int i = 0; i < SAVED_DWORDS; i++) {
        error = pci_read_config_dword(dev, i * 4, &saved[i]);
        if (error)
            return pcibios_err_to_errno(error);
    }
    memcpy(dev->saved_config_space, saved, sizeof(saved));
    dev->state_saved = true;
    return 0;
}

void pci_restore_state(struct pci_dev *dev)
{
    if (!dev->state_saved)
        return;
    for (int i = 15; i >= 0; i--)
        if (pci_write_config_dword(dev, i * 4, dev->saved_config_space[i]))
            stela_linux_fatal("PCI state restore failed without completion");
    dev->state_saved = false;
}

/* The power management capability's D-state, with the settling time D3hot
 * transitions need. A function without the capability stays in D0. */
int pci_set_power_state(struct pci_dev *dev, pci_power_t state)
{
    u8 pm;
    u16 control;
    int error;
    if (state < PCI_D0 || state > PCI_D3hot)
        return -EINVAL;
    error = stela_linux_pci_find_capability(dev, PCI_CAP_ID_PM, &pm);
    if (error)
        return pcibios_err_to_errno(error);
    if (!pm)
        return state == PCI_D0 ? 0 : -EIO;
    error = pci_read_config_word(dev, pm + PCI_PM_CTRL, &control);
    if (error)
        return pcibios_err_to_errno(error);
    u16 current_state = control & PCI_PM_CTRL_STATE_MASK;
    u16 target = (__force u16)state;
    if (current_state == target)
        return 0;
    control = (control & (u16)~PCI_PM_CTRL_STATE_MASK) | target;
    error = pci_write_config_word(dev, pm + PCI_PM_CTRL, control);
    if (error)
        return pcibios_err_to_errno(error);
    if (current_state == (__force u16)PCI_D3hot || target == (__force u16)PCI_D3hot)
        msleep(10);
    dev->current_state = state;
    return 0;
}

struct pci_dev *pci_dev_get(struct pci_dev *dev)
{
	if (dev)
		get_device(&dev->dev);
	return dev;
}

void pci_dev_put(struct pci_dev *dev)
{
	if (dev)
		put_device(&dev->dev);
}

struct pci_dev *pci_get_domain_bus_and_slot(int domain, unsigned int bus, unsigned int devfn)
{
	struct pci_dev *dev;

	list_for_each_entry(dev, &devices, bus_list)
		if (pci_domain_nr(dev->bus) == domain && dev->bus->number == bus &&
		    dev->devfn == devfn)
			return pci_dev_get(dev);
	return NULL;
}

/* Enabling, following drivers/pci/pci.c. The owner has powered the function
 * and assigned its resources; this turns on their decoding. */
int pci_enable_device(struct pci_dev *dev)
{
    dev_info(&dev->dev, "pci_enable_device (cnt=%d)\n", atomic_read(&dev->enable_cnt));
    int error;
    u16 old, command;
    if (atomic_inc_return(&dev->enable_cnt) > 1)
        return 0;
    error = pci_read_config_word(dev, PCI_COMMAND, &old);
    if (error)
        goto refused;
    command = old;
    for (int bar = 0; bar < PCI_ROM_RESOURCE; bar++) {
        unsigned long flags = pci_resource_flags(dev, bar);
        if (flags & IORESOURCE_IO)
            command |= PCI_COMMAND_IO;
        else if (flags & IORESOURCE_MEM)
            command |= PCI_COMMAND_MEMORY;
    }
    if (command != old) {
        error = pci_write_config_word(dev, PCI_COMMAND, command);
        if (error)
            goto refused;
    }
    return 0;
refused:
    /* A possibly applied write traps at the actual Rust boundary. This only
     * restores metadata after a before-write PCIBIOS refusal; no hardware RMW. */
    atomic_dec(&dev->enable_cnt);
    return pcibios_err_to_errno(error);
}

void pci_disable_device(struct pci_dev *dev)
{
    WARN_ON_ONCE(atomic_read(&dev->enable_cnt) <= 0);
    if (atomic_dec_return(&dev->enable_cnt))
        return;
    if (dev->is_busmaster) {
        u16 command;
        if (pci_read_config_word(dev, PCI_COMMAND, &command) ||
            pci_write_config_word(dev, PCI_COMMAND, command & (u16)~PCI_COMMAND_MASTER))
            stela_linux_fatal("PCI disable failed without completion");
        dev->is_busmaster = 0;
    }
}

void pci_set_master(struct pci_dev *dev)
{
    dev_info(&dev->dev, "pci_set_master called\n");
    u16 command;
    if (pci_read_config_word(dev, PCI_COMMAND, &command))
        stela_linux_fatal("PCI bus-master access failed without completion");
    if (!(command & PCI_COMMAND_MASTER) &&
        pci_write_config_word(dev, PCI_COMMAND, command | PCI_COMMAND_MASTER))
        stela_linux_fatal("PCI bus-master access failed without completion");
    dev->is_busmaster = 1;
}

/* Option ROMs, following drivers/pci/rom.c. The owner assigned the ROM
 * resource, whose CPU and bus addresses are one on x86. */
int pci_enable_rom(struct pci_dev *pdev)
{
    struct resource *res = &pdev->resource[PCI_ROM_RESOURCE];
    u32 address;
    int error;
    if (!res->flags)
        return -1;
    if (res->flags & IORESOURCE_ROM_SHADOW)
        return 0;
    error = pci_read_config_dword(pdev, pdev->rom_base_reg, &address);
    if (error)
        return pcibios_err_to_errno(error);
    address &= ~PCI_ROM_ADDRESS_MASK;
    address |= (u32)res->start | PCI_ROM_ADDRESS_ENABLE;
    error = pci_write_config_dword(pdev, pdev->rom_base_reg, address);
    return pcibios_err_to_errno(error);
}

void pci_disable_rom(struct pci_dev *pdev)
{
    struct resource *res = &pdev->resource[PCI_ROM_RESOURCE];
    u32 address;
    if (res->flags & IORESOURCE_ROM_SHADOW)
        return;
    if (pci_read_config_dword(pdev, pdev->rom_base_reg, &address))
        stela_linux_fatal("PCI ROM disable failed without completion");
    address &= (u32)~PCI_ROM_ADDRESS_ENABLE;
    if (pci_write_config_dword(pdev, pdev->rom_base_reg, address))
        stela_linux_fatal("PCI ROM disable failed without completion");
}

/* The bytes the ROM's images span, never more than its window: real ROMs
 * have windows far larger than their contents, and some misreport. */
static size_t rom_size(struct pci_dev *pdev, void __iomem *rom, size_t size)
{
	void __iomem *image = rom;
	unsigned int length;
	int last_image;

	do {
		if (readw(image) != 0xaa55) {
			pci_info(pdev, "Invalid PCI ROM header signature: got %#06x\n",
				 readw(image));
			break;
		}
		void __iomem *data = image + readw(image + 24);
		if (readl(data) != 0x52494350) {
			pci_info(pdev, "Invalid PCI ROM data signature: got %#010x\n",
				 readl(data));
			break;
		}
		last_image = readb(data + 21) & 0x80;
		length = readw(data + 16);
		image += length * 512;
		if (image >= rom + size)
			break;
		if (!last_image && readw(image) != 0xaa55)
			break;
	} while (length && !last_image);
	return min((size_t)(image - rom), size);
}

void __iomem *pci_map_rom(struct pci_dev *pdev, size_t *size)
{
	resource_size_t start = pci_resource_start(pdev, PCI_ROM_RESOURCE);

	*size = (size_t)pci_resource_len(pdev, PCI_ROM_RESOURCE);
	if (!*size || pci_enable_rom(pdev))
		return NULL;
	void __iomem *rom = ioremap(start, *size);
	if (rom) {
		*size = rom_size(pdev, rom, *size);
		if (*size)
			return rom;
		iounmap(rom);
	}
	pci_disable_rom(pdev);
	return NULL;
}

void pci_unmap_rom(struct pci_dev *pdev, void __iomem *rom)
{
	iounmap(rom);
	pci_disable_rom(pdev);
}

#ifdef STELA_LINUX_PCI_TEST
#include <stela/linux.h>
#include <stela/test.h>

static u8 config[256];
static int config_error;
static u8 rom_window[0x1000] __aligned(PAGE_SIZE);

static int read_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *value)
{
	(void)bus;
	if (devfn != PCI_DEVFN(1, 0))
		return PCIBIOS_DEVICE_NOT_FOUND;
	if (config_error)
		return config_error;
	*value = 0;
	memcpy(value, &config[where], (size_t)size);
	return 0;
}

static int write_config(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 value)
{
	(void)bus;
	(void)devfn;
	memcpy(&config[where], &value, (size_t)size);
	return 0;
}

static struct pci_ops ops = {.read = read_config, .write = write_config};

static void *map_device(void *context, u64 physical, size_t size,
			bool write_combining)
{
	(void)context;
	(void)write_combining;
	assert(physical == 0xc0000000 && size == sizeof(rom_window));
	return rom_window;
}

static void unmap_device(void *context, void *address)
{
	(void)context;
	assert(address == rom_window);
}

static const struct stela_linux_services services = {
	.map_device = map_device,
	.unmap_device = unmap_device,
};
static const struct stela_linux_owner owner = {.services = &services};

static void one_image(u8 *image, unsigned int blocks, bool last)
{
	image[0] = 0x55;
	image[1] = 0xaa;
	image[24] = 0x40;
	memcpy(image + 0x40, "PCIR", 4);
	image[0x40 + 16] = (u8)blocks;
	image[0x40 + 21] = last ? 0x80 : 0;
}

static struct pci_dev dev, absent;

int main(void)
{
	stela_linux_enter(&owner);
	struct pci_bus bus = {.ops = &ops, .number = 3};
	dev.bus = &bus;
	dev.devfn = PCI_DEVFN(1, 0);
	dev.hdr_type = PCI_HEADER_TYPE_NORMAL;
	dev.rom_base_reg = PCI_ROM_ADDRESS;

	u32 value;
	config[PCI_VENDOR_ID] = 0xde;
	config[PCI_VENDOR_ID + 1] = 0x10;
	assert(!pci_read_config_dword(&dev, 0, &value) && value == 0x10de);
	assert(pci_read_config_dword(&dev, 2, &value) == PCIBIOS_BAD_REGISTER_NUMBER);
	absent.bus = &bus;
	absent.devfn = PCI_DEVFN(2, 0);
	assert(pci_read_config_dword(&absent, 0, &value) == PCIBIOS_DEVICE_NOT_FOUND &&
	       value == ~0U);

	/* Capabilities at 0x50 then 0x60; a list that loops stops. */
	config[PCI_STATUS] = PCI_STATUS_CAP_LIST;
	config[PCI_CAPABILITY_LIST] = 0x50;
	config[0x50] = PCI_CAP_ID_PM;
	config[0x51] = 0x60;
	config[0x60] = PCI_CAP_ID_EXP;
    u8 checked_capability = 0xaa;
    config_error = PCIBIOS_SET_FAILED;
    assert(pci_read_config_dword(&dev, 0, &value) == PCIBIOS_SET_FAILED && value == ~0U);
    assert(stela_linux_pci_find_capability(&dev, PCI_CAP_ID_EXP, &checked_capability) == PCIBIOS_SET_FAILED && !checked_capability);
    dev.saved_config_space[0] = 0x12345678;
    assert(pci_save_state(&dev) == -EIO && !dev.state_saved && dev.saved_config_space[0] == 0x12345678);
    assert(pci_enable_device(&dev) == -EIO && !atomic_read(&dev.enable_cnt));
    assert(pci_set_power_state(&dev, PCI_D0) == -EIO);
    config_error = 0;
	assert(pci_find_capability(&dev, PCI_CAP_ID_EXP) == 0x60);
	assert(!pci_find_capability(&dev, PCI_CAP_ID_AGP));
	config[0x61] = 0x50;
	assert(!pci_find_capability(&dev, PCI_CAP_ID_AGP));

	dev.resource[0].flags = IORESOURCE_MEM;
	assert(!pci_enable_device(&dev) && !pci_enable_device(&dev));
	pci_set_master(&dev);
	assert(config[PCI_COMMAND] == (PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER));
	pci_disable_device(&dev);
	assert(config[PCI_COMMAND] & PCI_COMMAND_MASTER);
	pci_disable_device(&dev);
	assert(config[PCI_COMMAND] == PCI_COMMAND_MEMORY && !dev.is_busmaster);

	device_initialize(&dev.dev);
	assert(!stela_linux_pci_publish_device(&dev));
	assert(pci_get_domain_bus_and_slot(0, 3, PCI_DEVFN(1, 0)) == &dev);
	pci_dev_put(&dev);
	assert(!pci_get_domain_bus_and_slot(0, 4, PCI_DEVFN(1, 0)));
	list_del(&dev.bus_list);

	/* Two images of a block each in a window of eight: the size is theirs. */
	dev.resource[PCI_ROM_RESOURCE].start = 0xc0000000;
	dev.resource[PCI_ROM_RESOURCE].end = 0xc0000fff;
	dev.resource[PCI_ROM_RESOURCE].flags = IORESOURCE_MEM;
	one_image(rom_window, 1, false);
	one_image(rom_window + 512, 1, true);
	size_t size;
	void __iomem *rom = pci_map_rom(&dev, &size);
	assert(rom == (void __iomem *)rom_window && size == 1024);
	assert(*(u32 *)&config[PCI_ROM_ADDRESS] == (0xc0000000 | PCI_ROM_ADDRESS_ENABLE));
	pci_unmap_rom(&dev, rom);
	assert(*(u32 *)&config[PCI_ROM_ADDRESS] == 0xc0000000);

	/* No ROM signature: nothing maps and decoding goes back off. */
	rom_window[0] = 0;
	assert(!pci_map_rom(&dev, &size) && *(u32 *)&config[PCI_ROM_ADDRESS] == 0xc0000000);
	stela_linux_exit();
	printf("Linux PCI configuration, enabling and option ROMs passed\n");
	return 0;
}
#endif
