/*
 * Host tests of plugin_report.h, which the kext compiles unchanged. xtask's
 * `guest::app::tests::the_kext_c_code_passes_its_host_tests` builds and runs
 * this with the host's clang; it prints each failing check.
 */
#include <stdio.h>
#include <string.h>

#include "../plugin_report.h"

static int failures;

#define CHECK(condition)                                                       \
	do {                                                                   \
		if (!(condition)) {                                            \
			printf("%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			failures++;                                            \
		}                                                              \
	} while (0)

static void
lines(void)
{
	char line[STELA_PLUGIN_REPORT_BYTES];
	CHECK(stela_plugin_report_line(line, "WindowServer", "IOServiceOpen 0xe00002c7"));
	CHECK(!strcmp(line, "WindowServer: IOServiceOpen 0xe00002c7"));
	/* A name with control bytes is shown, not trusted. */
	CHECK(stela_plugin_report_line(line, "a\nb", "x"));
	CHECK(!strcmp(line, "a?b: x"));
	CHECK(stela_plugin_report_line(line, "", "x"));
	CHECK(!strcmp(line, "?: x"));
	/* The event must be printable and short enough for a byte of the name. */
	CHECK(!stela_plugin_report_line(line, "p", "") && !line[0]);
	CHECK(!stela_plugin_report_line(line, "p", "bad\x1b[2J") && !line[0]);
	char event[STELA_PLUGIN_REPORT_BYTES + 8];
	memset(event, 'e', sizeof event - 1);
	event[sizeof event - 1] = 0;
	CHECK(!stela_plugin_report_line(line, "p", event));
	event[STELA_PLUGIN_REPORT_BYTES - 3] = 0;
	CHECK(!stela_plugin_report_line(line, "p", event));
	event[STELA_PLUGIN_REPORT_BYTES - 4] = 0;
	CHECK(stela_plugin_report_line(line, "process", event));
	CHECK(strlen(line) == STELA_PLUGIN_REPORT_BYTES - 1 && !strncmp(line, "p: eee", 6));
	/* A long name is cut to what the event leaves. */
	char name[300];
	memset(name, 'n', sizeof name - 1);
	name[sizeof name - 1] = 0;
	CHECK(stela_plugin_report_line(line, name, "event"));
	CHECK(strlen(line) == STELA_PLUGIN_REPORT_BYTES - 1);
	CHECK(!strcmp(line + strlen(line) - 7, ": event"));
}

static void
admission(void)
{
	static struct stela_plugin_reports reports;
	CHECK(stela_plugin_report_admit(&reports, "WindowServer: opened") == STELA_PLUGIN_REPORT_LOG);
	/* Each respawn's same result is not logged again. */
	CHECK(stela_plugin_report_admit(&reports, "WindowServer: opened") == STELA_PLUGIN_REPORT_SEEN);
	CHECK(stela_plugin_report_admit(&reports, "Dock: opened") == STELA_PLUGIN_REPORT_LOG);
	CHECK(stela_plugin_report_admit(&reports, "") == STELA_PLUGIN_REPORT_DROP);
	CHECK(stela_plugin_report_admit(&reports, "a\tb") == STELA_PLUGIN_REPORT_DROP);
	for (unsigned i = 2; i < STELA_PLUGIN_REPORT_LINES; i++) {
		char line[32];
		snprintf(line, sizeof line, "p%u: e", i);
		CHECK(stela_plugin_report_admit(&reports, line) == STELA_PLUGIN_REPORT_LOG);
	}
	CHECK(reports.count == STELA_PLUGIN_REPORT_LINES);
	/* Past the bound: one line says so, then nothing new is logged. */
	CHECK(stela_plugin_report_admit(&reports, "late: e") == STELA_PLUGIN_REPORT_FULL);
	CHECK(stela_plugin_report_admit(&reports, "later: e") == STELA_PLUGIN_REPORT_DROP);
	CHECK(stela_plugin_report_admit(&reports, "Dock: opened") == STELA_PLUGIN_REPORT_SEEN);
}

int
main(void)
{
	lines();
	admission();
	printf("%s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
