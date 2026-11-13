/*
 * The StelaGPU user client's interface, shared by the kext and the Metal
 * bundle.
 *
 * A task opens one user client per Metal device (`IOServiceOpen` with
 * kStelaGPUUserClientType), which opens its gate connection, and maps the
 * gate page (`IOConnectMapMemory64` with kStelaGPUGateMemory). Calls go from
 * the task straight to the page: a 64-bit store of a call record's address
 * to its STELA_GATE_CALL register runs the call. The kernel is entered only
 * to wait for GPU completions.
 */
#pragma once

/*
 * The accelerator's property a plugin that fails before its gate connection
 * opens sets to a short printable string naming the failed step, which the
 * kext logs to the kernel console once.
 */
#define kStelaGPUPluginReportKey "StelaPluginReport"

enum {
	/* The `IOServiceOpen` type. */
	kStelaGPUUserClientType = 0,
	/* The `clientMemoryForType` type of the connection's gate page. */
	kStelaGPUGateMemory = 0,
};

enum {
	/*
	 * Async: scalar input the completion count the caller has seen. Once
	 * the count differs, the kext sends the async result kIOReturnSuccess
	 * with one argument, the count now. One notification is armed per
	 * client; arming again replaces it.
	 */
	kStelaGPUNotifyCompletion = 0,
	/*
	 * Scalar input a page-aligned address and length of the task's memory,
	 * which the kext wires; scalar output the memory's handle, which goes in
	 * a buffer or heap call through the gate, or in Release. The memory
	 * stays wired, whatever becomes of the task's mapping, until the GPU no
	 * longer reaches it.
	 */
	kStelaGPUImportMemory = 1,
	kStelaGPUSelectorCount,
};
