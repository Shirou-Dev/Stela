/*
 * Whole-file reads, digests and in-place writes through the vnode KPI, shared
 * by the Metal plugin's installer (install.cpp) and Stela.app's (app.cpp).
 *
 * The kernel exports vnode_open, vn_rdwr and vnode_lookup to kexts, but
 * nothing that creates, renames or removes a directory or a name: a kext can
 * create a file in an existing directory and rewrite one in place, no more.
 * VNOP_MKDIR, VNOP_CREATE, VNOP_RENAME, VNOP_REMOVE and VNOP_SYMLINK are
 * XNU_KERNEL_PRIVATE in sys/vnode_if.h and absent from com.apple.kernel's
 * symbol table, which the auxiliary collection binds a kext's undefined
 * symbols against (stela-loader's aux_kc `imports`): its only VNOP_ wrappers
 * are BWRITE, FSYNC, GETXATTR, IOCTL, READ, SETXATTR, STRATEGY and WRITE.
 * Their vnop_*_desc descriptors are exported, for stacking file systems, but
 * calling through one needs the vnode's private operation vector.
 */
#pragma once

#include <libkern/crypto/sha2.h>
#include <sys/types.h>
#include <sys/vnode.h>

/* The bytes read or written at a time; every buffer given here is this long. */
static const int kStelaChunk = 64 * 1024;

/*
 * Every function here opens only regular files, never following the last
 * component, and answers EFTYPE for anything else at `path`.
 */

/* The SHA-256 and length of `path`'s bytes, through `buffer`. */
int stelaDigestFile(const char *path, vfs_context_t context, char *buffer,
    unsigned char digest[SHA256_DIGEST_LENGTH], off_t *length);

/*
 * Whether `path` holds `length` bytes whose SHA-256 is `sha256`, through
 * `buffer`. `same` is false whenever the answer is an error.
 */
int stelaMatches(const char *path, const unsigned char sha256[SHA256_DIGEST_LENGTH], unsigned long length,
    vfs_context_t context, char *buffer, bool *same);

/* Writes `length` bytes to `path` in place, creating it with `mode` if absent. */
int stelaWriteFile(const char *path, const unsigned char *bytes, unsigned long length, unsigned mode,
    vfs_context_t context);

/*
 * Reads all of `path` into `buffer` of `capacity` bytes, answering EFBIG
 * when it holds more. The final component is never followed.
 */
int stelaReadFile(const char *path, char *buffer, int capacity, int *length, vfs_context_t context);
