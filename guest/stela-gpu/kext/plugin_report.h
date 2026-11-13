/*
 * What reaches the kernel console of the Metal plugin's opens, in C without a
 * library, so the kext (StelaGPU.cpp) and the host's tests
 * (tests/plugin_report.c) run the same code.
 *
 * A plugin that fails before its gate connection is open has no gate to report
 * through, and its own log is not on the console. It names the failed step in
 * the accelerator's kStelaGPUPluginReportKey property instead, and the kext
 * logs each accelerator open's result. Each distinct line is logged once, and
 * a bounded number of them, since any task may set the property.
 */
#pragma once

/* Distinct lines logged; then one line says the rest are dropped. */
#define STELA_PLUGIN_REPORT_LINES 32
/* A line's bytes, NUL included: the process name and the event. */
#define STELA_PLUGIN_REPORT_BYTES 128

struct stela_plugin_reports {
	unsigned count;
	int full;
	char seen[STELA_PLUGIN_REPORT_LINES][STELA_PLUGIN_REPORT_BYTES];
};

enum stela_plugin_verdict {
	/* New: log the line. */
	STELA_PLUGIN_REPORT_LOG,
	/* Logged before. */
	STELA_PLUGIN_REPORT_SEEN,
	/* The first line past the bound: log that further lines are dropped. */
	STELA_PLUGIN_REPORT_FULL,
	/* Past the bound, or not a line: nothing is logged. */
	STELA_PLUGIN_REPORT_DROP,
};

/* Whether `text` is 1 to `limit` printable ASCII bytes before its NUL. */
static inline int
stela_plugin_report_printable(const char *text, unsigned long limit)
{
	unsigned long length = 0;
	for (; text[length]; length++) {
		if (length == limit || text[length] < 0x20 || text[length] > 0x7e) {
			return 0;
		}
	}
	return length != 0;
}

/*
 * Builds "process: event" in `line`, the process name cut to fit, and answers
 * whether `event` is printable and leaves room for at least a byte of the
 * name. A non-printable process name byte becomes '?'.
 */
static inline int
stela_plugin_report_line(char line[STELA_PLUGIN_REPORT_BYTES], const char *process, const char *event)
{
	unsigned long event_length = 0;
	while (event[event_length] && event_length < STELA_PLUGIN_REPORT_BYTES) {
		event_length++;
	}
	/* The separator, a byte of the name and the NUL. */
	if (event_length + 4 > STELA_PLUGIN_REPORT_BYTES
	    || !stela_plugin_report_printable(event, STELA_PLUGIN_REPORT_BYTES)) {
		line[0] = 0;
		return 0;
	}
	unsigned long room = STELA_PLUGIN_REPORT_BYTES - 3 - event_length;
	unsigned long at = 0;
	for (; process[at] && at < room; at++) {
		char byte = process[at];
		line[at] = byte < 0x20 || byte > 0x7e ? '?' : byte;
	}
	if (at == 0) {
		line[at++] = '?';
	}
	line[at++] = ':';
	line[at++] = ' ';
	for (unsigned long i = 0; i < event_length; i++) {
		line[at++] = event[i];
	}
	line[at] = 0;
	return 1;
}

static inline int
stela_plugin_report_same(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

/* Records `line` and answers whether to log it; the caller serializes. */
static inline enum stela_plugin_verdict
stela_plugin_report_admit(struct stela_plugin_reports *reports, const char *line)
{
	if (!stela_plugin_report_printable(line, STELA_PLUGIN_REPORT_BYTES - 1)) {
		return STELA_PLUGIN_REPORT_DROP;
	}
	for (unsigned i = 0; i < reports->count; i++) {
		if (stela_plugin_report_same(reports->seen[i], line)) {
			return STELA_PLUGIN_REPORT_SEEN;
		}
	}
	if (reports->count == STELA_PLUGIN_REPORT_LINES) {
		if (reports->full) {
			return STELA_PLUGIN_REPORT_DROP;
		}
		reports->full = 1;
		return STELA_PLUGIN_REPORT_FULL;
	}
	char *slot = reports->seen[reports->count++];
	unsigned long at = 0;
	for (; line[at]; at++) {
		slot[at] = line[at];
	}
	slot[at] = 0;
	return STELA_PLUGIN_REPORT_LOG;
}
