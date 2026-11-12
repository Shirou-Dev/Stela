/* SPDX-License-Identifier: GPL-2.0-or-later */
#define STELA_AIR_METADATA_INTERNAL
#include "air_metadata.h"
#include "air_calls.h"
#include "air_constants.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/DebugInfo.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAX2(a, b) ((a) > (b) ? (a) : (b))
#define MIN2(a,b) ((a) < (b) ? (a) : (b))
static bool
fail(struct stela_air_metadata *t, enum stela_air_error_kind kind, const char *fmt, ...)
{
   if (t->error->kind == STELA_AIR_OK) {
      t->error->kind = kind;
      va_list args;
      va_start(args, fmt);
      vsnprintf(t->error->detail, sizeof(t->error->detail), fmt, args);
      va_end(args);
   }
   return false;
}

bool
stela_air_md_string(LLVMValueRef value, const char *expected)
{
   if (!value || !LLVMIsAMDString(value))
      return false;
   unsigned length;
   const char *string = LLVMGetMDString(value, &length);
   return length == strlen(expected) && !memcmp(string, expected, length);
}

/* Whether a module flag's name is in AIR's namespace. */
static bool
air_flag(LLVMValueRef value)
{
   if (!value || !LLVMIsAMDString(value))
      return true;
   unsigned length;
   const char *string = LLVMGetMDString(value, &length);
   return length >= 4 && !memcmp(string, "air.", 4);
}

/* A metadata string for a refusal to name: its text, or "?" for another
 * value. */
static const char *
md_text(LLVMValueRef value, unsigned *length)
{
   if (!value || !LLVMIsAMDString(value))
      return *length = 1, "?";
   const char *text = LLVMGetMDString(value, length);
   *length = MIN2(*length, 120);
   return text;
}

bool
stela_air_md_uint(LLVMValueRef value, unsigned *number)
{
   if (!value || !LLVMIsAConstantInt(value) ||
       LLVMGetIntTypeWidth(LLVMTypeOf(value)) > 32)
      return false;
   *number = LLVMConstIntGetZExtValue(value);
   return true;
}

bool
stela_air_md_node(struct stela_air_metadata *t, LLVMValueRef node, LLVMValueRef *operands,
        unsigned *count)
{
   if (!node || !LLVMIsAMDNode(node))
      return fail(t, STELA_AIR_METADATA, "expected AIR metadata node");
   *count = LLVMGetMDNodeNumOperands(node);
   if (*count > AIR_MAX_METADATA_OPERANDS)
      return fail(t, STELA_AIR_LIMIT, "AIR metadata operand budget exceeded");
   LLVMGetMDNodeOperands(node, operands);
   return true;
}

bool
stela_air_named_md(struct stela_air_metadata *t, const char *name, LLVMValueRef *operands,
         unsigned *count)
{
   *count = LLVMGetNamedMetadataNumOperands(t->module, name);
   if (*count > AIR_MAX_METADATA_OPERANDS)
      return fail(t, STELA_AIR_LIMIT, "%s metadata budget exceeded", name);
   LLVMGetNamedMetadataOperands(t->module, name, operands);
   return true;
}

bool
stela_air_metadata_shared_profile(struct stela_air_metadata *t)
{
   if (LLVMPointerSizeForAS(t->layout, 3) != 8)
      return fail(t, STELA_AIR_TARGET, "shared-memory AIR pointers require 64-bit layout");
   return true;
}

/* Fixed storage of integer and floating scalars, 2-4 lane vectors, arrays and
 * structs, at most UINT32_MAX bytes. */
static bool
storage_size(struct stela_air_metadata *t, LLVMTypeRef type, unsigned depth, unsigned *budget,
             uint64_t *size)
{
   if (depth == 32 || !*budget)
      return fail(t, STELA_AIR_LIMIT, "global storage type budget exceeded");
   (*budget)--;
   bool valid;
   switch (LLVMGetTypeKind(type)) {
   case LLVMArrayTypeKind: {
      uint64_t element;
      if (!storage_size(t, LLVMGetElementType(type), depth + 1, budget, &element))
         return false;
      if (element && LLVMGetArrayLength2(type) > UINT32_MAX / element)
         return fail(t, STELA_AIR_LIMIT, "global storage size exceeded");
      valid = true;
      break;
   }
   case LLVMStructTypeKind:
      if (LLVMIsOpaqueStruct(type))
         return fail(t, STELA_AIR_TYPE, "globals require fixed integer or floating storage");
      for (unsigned i = 0; i < LLVMCountStructElementTypes(type); i++) {
         uint64_t field;
         if (!storage_size(t, LLVMStructGetTypeAtIndex(type, i), depth + 1, budget, &field))
            return false;
      }
      valid = true;
      break;
   case LLVMVectorTypeKind: {
      LLVMTypeKind element = LLVMGetTypeKind(LLVMGetElementType(type));
      unsigned components = LLVMGetVectorSize(type);
      uint64_t bytes;
      valid = components >= 2 && components <= 4 && element != LLVMArrayTypeKind &&
              element != LLVMStructTypeKind && element != LLVMVectorTypeKind;
      if (valid && !storage_size(t, LLVMGetElementType(type), depth + 1, budget, &bytes))
         return false;
      break;
   }
   case LLVMIntegerTypeKind: {
      unsigned bits = LLVMGetIntTypeWidth(type);
      valid = bits == 8 || bits == 16 || bits == 32 || bits == 64;
      break;
   }
   case LLVMHalfTypeKind:
   case LLVMFloatTypeKind:
      valid = true;
      break;
   default:
      valid = false;
      break;
   }
   if (!valid)
      return fail(t, STELA_AIR_TYPE, "globals require fixed integer or floating storage");
   /* Extents were bounded before invoking fixed-size LLVM queries. */
   *size = LLVMABISizeOfType(t->layout, type);
   return *size <= UINT32_MAX || fail(t, STELA_AIR_LIMIT, "global storage size exceeded");
}

/* An internal function of section air.static_init. */
static bool
static_init(LLVMValueRef fn)
{
   const char *section = fn && LLVMIsAFunction(fn) ? LLVMGetSection(fn) : NULL;
   return section && !strcmp(section, "air.static_init") && !LLVMIsDeclaration(fn) &&
          LLVMGetLinkage(fn) == LLVMInternalLinkage;
}

LLVMValueRef
stela_air_metadata_constructors(LLVMModuleRef module)
{
   LLVMValueRef list = LLVMGetNamedGlobal(module, "llvm.global_ctors");
   LLVMValueRef entries = list ? LLVMGetInitializer(list) : NULL;
   LLVMTypeRef type = entries ? LLVMTypeOf(entries) : NULL;
   if (!type || LLVMGetLinkage(list) != LLVMAppendingLinkage ||
       LLVMGetTypeKind(type) != LLVMArrayTypeKind)
      return NULL;
   for (unsigned i = 0; i < LLVMGetArrayLength2(type); i++) {
      LLVMValueRef entry = LLVMGetAggregateElement(entries, i);
      if (!entry || LLVMGetNumOperands(entry) != 3 || !LLVMIsAConstantInt(LLVMGetOperand(entry, 0)) ||
          !static_init(LLVMGetOperand(entry, 1)))
         return NULL;
   }
   return list;
}

/* An os_log looks like one, but its strings are read while compiling. */
bool
stela_air_metadata_constructed(LLVMValueRef global)
{
   return LLVMGetPointerAddressSpace(LLVMTypeOf(global)) == 2 && !LLVMIsGlobalConstant(global) &&
          LLVMGetLinkage(global) == LLVMInternalLinkage && LLVMGetInitializer(global) &&
          !stela_air_log_only(global);
}

/* Threadgroup memory is an internal AS3 global, undefined or zeroed as
 * Apple's compiler gives atomics, which Metal never initializes; constant
 * data is an initialized internal or private AS2 constant, or a global
 * constructors compute. An initialized internal or private constant of the
 * thread address space, such as a C++ template parameter object Apple's
 * compiler copies from, is constant data too: nothing can write it. */
bool
stela_air_metadata_global(struct stela_air_metadata *t, LLVMValueRef global,
                          struct stela_air_global *info)
{
   const char *section = LLVMGetSection(global);
   LLVMValueRef initializer = LLVMGetInitializer(global);
   unsigned space = LLVMGetPointerAddressSpace(LLVMTypeOf(global));
   LLVMLinkage linkage = LLVMGetLinkage(global);
   bool constant = LLVMIsGlobalConstant(global);
   bool threadgroup = space == 3 && !constant && linkage == LLVMInternalLinkage && initializer &&
                      ((LLVMIsUndef(initializer) && !LLVMIsPoison(initializer)) ||
                       LLVMIsNull(initializer));
   bool data = ((space == 2 || space == 0) && constant && initializer &&
                (linkage == LLVMInternalLinkage || linkage == LLVMPrivateLinkage)) ||
               (t->constructed && stela_air_metadata_constructed(global));
   if ((!threadgroup && !data) || LLVMIsThreadLocal(global) || LLVMIsExternallyInitialized(global) ||
       (section && *section))
      return fail(t, STELA_AIR_TARGET, "unsupported global storage or initializer ABI");
   size_t metadata_count;
   LLVMValueMetadataEntry *metadata = LLVMGlobalCopyAllMetadata(global, &metadata_count);
   LLVMDisposeValueMetadataEntries(metadata);
   if (metadata_count)
      return fail(t, STELA_AIR_TARGET, "unsupported global metadata");
   if (LLVMPointerSizeForAS(t->layout, space) != 8)
      return fail(t, STELA_AIR_TARGET, "global pointers require 64-bit layout");
   LLVMTypeRef type = LLVMGlobalGetValueType(global);
   unsigned budget = 4096;
   *info = (struct stela_air_global){.constant = data};
   if (!storage_size(t, type, 0, &budget, &info->size))
      return false;
   if (!info->size)
      return fail(t, STELA_AIR_TYPE, "globals require nonempty storage");
   info->alignment = LLVMGetAlignment(global);
   if (!info->alignment)
      info->alignment = LLVMABIAlignmentOfType(t->layout, type);
   return (info->alignment && !(info->alignment & (info->alignment - 1))) ||
      fail(t, STELA_AIR_TYPE, "unsupported global alignment");
}

/* llvm.used or llvm.compiler.used: an appending list of globals the
 * optimizer keeps, such as [[function_constant]] arguments' predicates. */
static bool
retention_list(LLVMValueRef global)
{
   size_t bytes;
   const char *name = LLVMGetValueName2(global, &bytes);
   const char *section = LLVMGetSection(global);
   return LLVMGetLinkage(global) == LLVMAppendingLinkage && section &&
          !strcmp(section, "llvm.metadata") &&
          ((bytes == strlen("llvm.used") && !memcmp(name, "llvm.used", bytes)) ||
           (bytes == strlen("llvm.compiler.used") && !memcmp(name, "llvm.compiler.used", bytes)));
}

/* A dynamic library user's tables of the libraries it loads and the
 * functions it imports, which only llvm.used keeps: the loader's, which no
 * function reads. */
static bool
dyld_table(LLVMValueRef global)
{
   const char *section = LLVMGetSection(global);
   if (!section || (strcmp(section, "air.dyld_lib_table") && strcmp(section, "air.dyld_str_table") &&
                    strcmp(section, "air.dyld_flat_table")))
      return false;
   for (LLVMUseRef use = LLVMGetFirstUse(global); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (!LLVMIsAConstant(user))
         return false;
      LLVMUseRef held = LLVMGetFirstUse(user);
      if (!held || LLVMGetNextUse(held) || !LLVMIsAGlobalVariable(LLVMGetUser(held)) ||
          !retention_list(LLVMGetUser(held)))
         return false;
   }
   return true;
}

bool
stela_air_metadata_globals(struct stela_air_metadata *t, bool *threadgroup)
{
   unsigned count = 0;
   *threadgroup = false;
   LLVMValueRef constructors = stela_air_metadata_constructors(t->module);
   t->constructed = constructors != NULL;
   for (LLVMValueRef global = LLVMGetFirstGlobal(t->module); global;
        global = LLVMGetNextGlobal(global)) {
      struct stela_air_global info;
      if (++count > AIR_MAX_GLOBALS)
         return fail(t, STELA_AIR_LIMIT, "global count exceeded");
      if (global == constructors || retention_list(global) || dyld_table(global) ||
          stela_air_metadata_is_function_constant(t, global) || stela_air_log_only(global))
         continue;
      if (!stela_air_metadata_global(t, global, &info))
         return false;
      *threadgroup |= !info.constant;
   }
   return true;
}

static bool
version_metadata(struct stela_air_metadata *t, const char *name, bool language)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count, fields_count, major, minor, patch;
   if (!stela_air_named_md(t, name, nodes, &count) || count != 1 ||
       !stela_air_md_node(t, nodes[0], fields, &fields_count))
      return fail(t, STELA_AIR_METADATA, "missing or invalid %s", name);
   unsigned base = language ? 1 : 0;
   if (fields_count != base + 3 || (language && !stela_air_md_string(fields[0], "Metal")) ||
       !stela_air_md_uint(fields[base], &major) || !stela_air_md_uint(fields[base + 1], &minor) ||
       !stela_air_md_uint(fields[base + 2], &patch) || patch != 0)
      return fail(t, STELA_AIR_METADATA, "invalid %s", name);
   /* Every Metal language version, and the AIR versions their compilers
    * emit, 1.11 being Metal 1.2's; LLVM upgrades the typed pointers of older
    * AIR as it reads it. */
   bool supported = language ?
      ((major == 1 && minor <= 2) || (major == 2 && minor <= 4) || (major == 3 && minor <= 2) ||
       (major == 4 && minor <= 1)) : ((major == 1 && minor <= 11) || (major == 2 && minor <= 9));
   if (!supported)
      return fail(t, STELA_AIR_METADATA, "unsupported %s %u.%u.%u", name, major, minor, patch);
   if (!language) {
      t->air_major = major;
      t->air_minor = minor;
   } else {
      t->language_major = major;
      t->language_minor = minor;
   }
   return true;
}

bool
stela_air_metadata_target(const struct stela_air_metadata *t, const char *target)
{
   char prefix[40];
   snprintf(prefix, sizeof(prefix), "air64_v%u%u-apple-", t->air_major, t->air_minor);
   return !strncmp(target, prefix, strlen(prefix)) ||
          !strncmp(target, "air64-apple-", strlen("air64-apple-"));
}

static bool
module_flags(struct stela_air_metadata *t)
{
   /* These are the LLVM IR serialized behavior values, not the smaller C API
    * LLVMModuleFlagBehavior enum (which does not expose Max in LLVM 23). */
   enum { IR_FLAG_ERROR = 1, IR_FLAG_MAX = 7 };
   const char *keys[] = {"wchar_size", "frame-pointer", "air.max_device_buffers",
      "air.max_constant_buffers", "air.max_threadgroup_buffers", "air.max_textures",
      "air.max_read_write_textures", "air.max_samplers"};
   LLVMValueRef flags[AIR_MAX_METADATA_OPERANDS];
   unsigned count, seen = 0;
   if (!stela_air_named_md(t, "llvm.module.flags", flags, &count))
      return false;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count, behavior, value, key;
      if (!stela_air_md_node(t, flags[i], fields, &field_count) || field_count != 3)
         return fail(t, STELA_AIR_METADATA, "unsupported module flag shape");
      for (key = 0; key < ARRAY_SIZE(keys); key++) {
         if (stela_air_md_string(fields[1], keys[key]))
            break;
      }
      /* LLVM's notes on the build, such as its SDK's version, are no part of
       * AIR, and their values need not be integers. */
      if (key == ARRAY_SIZE(keys) && !air_flag(fields[1]))
         continue;
      if (!stela_air_md_uint(fields[0], &behavior) || !stela_air_md_uint(fields[2], &value))
         return fail(t, STELA_AIR_METADATA, "unsupported module flag shape");
      if (key == ARRAY_SIZE(keys) || (seen & (1u << key)))
         return fail(t, STELA_AIR_METADATA, "unsupported/duplicate module flag");
      seen |= 1u << key;
      if (behavior != (key == 0 ? IR_FLAG_ERROR : IR_FLAG_MAX) ||
          (key == 0 && value != 4) || (key == 1 && value > 2) ||
          (key >= 2 && !value))
         return fail(t, STELA_AIR_METADATA, "unsupported module flag value: %s", keys[key]);
      if (key == 2)
         t->max_device_buffers = value;
      if (key == 4)
         t->max_threadgroup_buffers = value;
      if (key == 3)
         t->max_constant_buffers = value;
   }
   /* No linking, CPU frame operations or source wchar operations occur in the
    * implemented compute subset. Other resource kinds remain refused.
    * Device/threadgroup location bounds are enforced below, never advertised as the
    * hardware's actual Metal capability or silently removed from the input. */
   return true;
}

bool
stela_air_metadata_validate(struct stela_air_metadata *t)
{
   /* Debug info says nothing a function does, and Xcode's Debug builds carry it. */
   LLVMStripModuleDebugInfo(t->module);
   if (LLVMGetNamedGlobal(t->module, "llvm.global_ctors") && !stela_air_metadata_constructors(t->module))
      return fail(t, STELA_AIR_METADATA, "invalid AIR constructor list");
   for (LLVMNamedMDNodeRef node = LLVMGetFirstNamedMetadata(t->module); node;
        node = LLVMGetNextNamedMetadata(node)) {
      size_t size;
      const char *name = LLVMGetNamedMetadataName(node, &size);
      /* A library's module lists every entry point it defines, of any
       * stage, and names its source file. */
      const char *allowed[] = {"air.version", "air.language_version", "air.compile_options",
                               "air.kernel", "air.vertex", "air.fragment", "air.object",
                               "air.mesh", "air.visible", "air.function_constants",
                               "air.source_file_name",
                               "air.sampler_states", "air.visible_function_references"};
      /* Tools' own notes, such as a build's sources, are no part of AIR. */
      bool found = size < 4 || memcmp(name, "air.", 4);
      for (unsigned i = 0; i < ARRAY_SIZE(allowed); i++)
         found |= size == strlen(allowed[i]) && !memcmp(name, allowed[i], size);
      if (!found)
         return fail(t, STELA_AIR_METADATA, "unsupported module metadata: %.*s",
                     (int)MIN2(size, 160), name);
   }
   struct stela_air_function_constant constants[AIR_MAX_FUNCTION_CONSTANTS];
   LLVMValueRef samplers[AIR_MAX_SAMPLER_STATES];
   uint64_t states[AIR_MAX_SAMPLER_STATES];
   unsigned constant_count, sampler_count;
   if (!version_metadata(t, "air.version", false) ||
       !version_metadata(t, "air.language_version", true) || !module_flags(t) ||
       !stela_air_metadata_function_constants(t, constants, NULL, &constant_count) ||
       !stela_air_metadata_sampler_states(t, samplers, states, &sampler_count))
      return false;
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_named_md(t, "air.compile_options", nodes, &count))
      return false;
   unsigned seen = 0;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count;
      if (!stela_air_md_node(t, nodes[i], fields, &fields_count) || fields_count != 1 ||
          !(stela_air_md_string(fields[0], "air.compile.denorms_disable") ||
            stela_air_md_string(fields[0], "air.compile.fast_math_enable") ||
            stela_air_md_string(fields[0], "air.compile.fast_math_disable") ||
            stela_air_md_string(fields[0], "air.compile.framebuffer_fetch_enable") ||
            stela_air_md_string(fields[0], "air.compile.framebuffer_fetch_disable")))
         return fail(t, STELA_AIR_METADATA, "unsupported AIR compile option");
      unsigned bit = stela_air_md_string(fields[0], "air.compile.denorms_disable") ? 1 :
                     stela_air_md_string(fields[0], "air.compile.fast_math_enable") ||
                     stela_air_md_string(fields[0], "air.compile.fast_math_disable") ? 2 : 4;
      if (seen & bit)
         return fail(t, STELA_AIR_METADATA, "duplicate/conflicting AIR compile option");
      seen |= bit;
      if (bit == 4) {
         t->framebuffer_fetch_present = true;
         t->framebuffer_fetch_enabled = stela_air_md_string(fields[0], "air.compile.framebuffer_fetch_enable");
      }
   }
   t->denorms_disable = seen & 1;
   t->fast_math = seen & 2;
   /* The identity is observational: its absence or shape refuses nothing. */
   struct stela_air_error ident_error = {0};
   struct stela_air_metadata observed = *t;
   observed.error = &ident_error;
   LLVMValueRef idents[AIR_MAX_METADATA_OPERANDS], ident[AIR_MAX_METADATA_OPERANDS];
   unsigned ident_count, ident_fields;
   t->ident = NULL;
   t->ident_bytes = 0;
   if (stela_air_named_md(&observed, "llvm.ident", idents, &ident_count) && ident_count == 1 &&
       stela_air_md_node(&observed, idents[0], ident, &ident_fields) && ident_fields == 1 &&
       ident[0] && LLVMIsAMDString(ident[0]))
      t->ident = LLVMGetMDString(ident[0], &t->ident_bytes);
   /* Arithmetic requires an explicit qualified FP policy for this private AIR
    * option. Exact storage/shared access and integer operations do not depend
    * on FP denorm mode. */
   return true;
}

bool
stela_air_metadata_layout(struct stela_air_metadata *t)
{
   t->layout = LLVMGetModuleDataLayout(t->module);
   const char *layout = LLVMGetDataLayoutStr(t->module);
   if (!layout || !*layout || LLVMByteOrder(t->layout) != LLVMLittleEndian ||
       LLVMPointerSizeForAS(t->layout, 0) != 8 || LLVMPointerSizeForAS(t->layout, 1) != 8)
      return fail(t, STELA_AIR_TARGET, "requires explicit little-endian 64-bit AIR layout");
   /* LLVM's C DataLayout API does not expose pointer-index width. Validate only
    * that property here; actual allocation sizes/field offsets come from LLVM.
    * Nonintegral/external-state pointers need a different NIR representation. */
   for (const char *part = layout; *part;) {
      const char *end = strchr(part, '-');
      size_t length = end ? (size_t)(end - part) : strlen(part);
      if ((length > 3 && !memcmp(part, "ni:", 3)) || (length && *part == 'P'))
         return fail(t, STELA_AIR_TARGET, "unsupported nonintegral/program address-space layout");
      if (length && *part == 'p') {
         unsigned colons = 0;
         const char *last = NULL;
         for (size_t i = 0; i < length; i++) {
            if (part[i] == ':') {
               colons++;
               last = part + i + 1;
            }
         }
         if (colons > 4 || (colons == 4 &&
             ((size_t)(part + length - last) != 2 || memcmp(last, "64", 2))))
            return fail(t, STELA_AIR_TARGET, "unsupported pointer-index width");
      }
      part += length;
      if (*part)
         part++;
   }
   return true;
}

/* This is only a conservative public-reflection classification. Unknown/struct
 * types are NOT inferred to lack argument buffers. It changes no NIR admission.
 * MSL argument buffers require structures; builtin scalar/vector buffer elements
 * cannot describe such a structure. Exact IR/layout validation remains separate. */
static enum stela_air_primitive
primitive_type(LLVMValueRef name, unsigned *components)
{
   const char *scalar[] = {"char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "float",
                           "half"};
   for (unsigned i = 0; i < ARRAY_SIZE(scalar); i++) {
      for (unsigned n = 1; n <= 4; n++) {
         char type[16];
         if (n == 1)
            snprintf(type, sizeof(type), "%s", scalar[i]);
         else
            snprintf(type, sizeof(type), "%s%u", scalar[i], n);
         if (stela_air_md_string(name, type)) {
            *components = n;
            return STELA_AIR_CHAR + i;
         }
      }
   }
   *components = 0;
   return STELA_AIR_PRIMITIVE_UNKNOWN;
}

/* A texture's reflected type name, "<type><<component>, <access>>" with
 * optional spaces: the MTLTextureType and component type. The access comes
 * from the argument's own access key. */
static bool
texture_type(const char *name, unsigned bytes, struct stela_air_texture *texture)
{
   static const struct {
      const char *name;
      enum stela_air_texture_type type;
      bool depth;
   } types[] = {
      {"texture1d", STELA_AIR_TEXTURE_1D}, {"texture1d_array", STELA_AIR_TEXTURE_1D_ARRAY},
      {"texture2d", STELA_AIR_TEXTURE_2D}, {"texture2d_array", STELA_AIR_TEXTURE_2D_ARRAY},
      {"texture2d_ms", STELA_AIR_TEXTURE_2D_MS},
      {"texture2d_ms_array", STELA_AIR_TEXTURE_2D_MS_ARRAY},
      {"texture3d", STELA_AIR_TEXTURE_3D}, {"texturecube", STELA_AIR_TEXTURE_CUBE},
      {"texturecube_array", STELA_AIR_TEXTURE_CUBE_ARRAY},
      {"texture_buffer", STELA_AIR_TEXTURE_BUFFER},
      {"depth2d", STELA_AIR_TEXTURE_2D, true}, {"depth2d_array", STELA_AIR_TEXTURE_2D_ARRAY, true},
      {"depth2d_ms", STELA_AIR_TEXTURE_2D_MS, true},
      {"depth2d_ms_array", STELA_AIR_TEXTURE_2D_MS_ARRAY, true},
      {"depthcube", STELA_AIR_TEXTURE_CUBE, true},
      {"depthcube_array", STELA_AIR_TEXTURE_CUBE_ARRAY, true},
   };
   static const struct {
      const char *name;
      enum stela_air_primitive primitive;
   } components[] = {
      {"float", STELA_AIR_FLOAT}, {"half", STELA_AIR_HALF}, {"int", STELA_AIR_INT},
      {"uint", STELA_AIR_UINT}, {"short", STELA_AIR_SHORT}, {"ushort", STELA_AIR_USHORT},
   };
   const char *open = memchr(name, '<', bytes);
   const char *end = name + bytes;
   if (!open || end[-1] != '>')
      return false;
   size_t type_bytes = (size_t)(open - name);
   const char *component = open + 1;
   while (component < end && *component == ' ')
      component++;
   const char *comma = memchr(component, ',', (size_t)(end - component));
   if (!comma)
      return false;
   size_t component_bytes = (size_t)(comma - component);
   while (component_bytes && component[component_bytes - 1] == ' ')
      component_bytes--;
   texture->type = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
      if (strlen(types[i].name) == type_bytes && !memcmp(types[i].name, name, type_bytes)) {
         texture->type = types[i].type;
         texture->depth = types[i].depth;
      }
   }
   texture->primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
   for (unsigned i = 0; i < ARRAY_SIZE(components); i++) {
      if (strlen(components[i].name) == component_bytes &&
          !memcmp(components[i].name, component, component_bytes))
         texture->primitive = components[i].primitive;
   }
   return texture->type && texture->primitive &&
          (!texture->depth || texture->primitive == STELA_AIR_FLOAT);
}

/* An "array<element, length>" type name's element, which *name and *bytes
 * become. */
static bool
array_type(const char **name, unsigned *bytes, unsigned length)
{
   static const char prefix[] = "array<";
   const char *start = *name + strlen(prefix), *end = *name + *bytes;
   if (*bytes <= strlen(prefix) + 1 || memcmp(*name, prefix, strlen(prefix)) || end[-1] != '>')
      return false;
   /* The length follows the last comma; the element may hold others. */
   const char *comma = end - 1;
   while (comma > start && *comma != ',')
      comma--;
   const char *digit = comma + 1;
   while (digit < end - 1 && *digit == ' ')
      digit++;
   if (*comma != ',' || digit == end - 1)
      return false;
   uint64_t value = 0;
   for (; digit < end - 1; digit++) {
      if (*digit < '0' || *digit > '9' || value > UINT32_MAX)
         return false;
      value = value * 10 + (unsigned)(*digit - '0');
   }
   while (comma > start && comma[-1] == ' ')
      comma--;
   *name = start;
   *bytes = (unsigned)(comma - start);
   return value == length && *bytes;
}

/* Whether value is used, directly or through constant expressions, in fn. */
static bool
used_in(LLVMValueRef value, LLVMValueRef fn, unsigned depth)
{
   for (LLVMUseRef use = LLVMGetFirstUse(value); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (LLVMIsAInstruction(user) ? LLVMGetBasicBlockParent(LLVMGetInstructionParent(user)) == fn :
          LLVMIsAConstantExpr(user) && depth < 8 && used_in(user, fn, depth + 1))
         return true;
   }
   return false;
}

/* Whether fn uses a threadgroup global. */
static bool
uses_threadgroup(struct stela_air_metadata *m, LLVMValueRef fn)
{
   LLVMValueRef constructors = stela_air_metadata_constructors(m->module);
   for (LLVMValueRef global = LLVMGetFirstGlobal(m->module); global;
        global = LLVMGetNextGlobal(global)) {
      struct stela_air_global info;
      if (global == constructors || retention_list(global) || dyld_table(global) ||
          stela_air_metadata_is_function_constant(m, global) || stela_air_log_only(global))
         continue;
      if (stela_air_metadata_global(m, global, &info) && !info.constant && used_in(global, fn, 0))
         return true;
   }
   return false;
}

/* The bytes of the threadgroup globals fn uses, in module order at their
 * alignments, and whether it calls air.discard_fragment. Globals are
 * qualified by compilation, which refuses the rest; here they add nothing. */
static void
entry_facts(const struct stela_air_metadata *m, LLVMValueRef fn, uint64_t *threadgroup_bytes,
            bool *discards)
{
   *threadgroup_bytes = 0;
   *discards = false;
   struct stela_air_error observed_error = {0};
   struct stela_air_metadata observed = *m;
   observed.error = &observed_error;
   for (LLVMValueRef global = LLVMGetFirstGlobal(m->module); global;
        global = LLVMGetNextGlobal(global)) {
      struct stela_air_global info;
      observed_error.kind = STELA_AIR_OK;
      if (!stela_air_metadata_global(&observed, global, &info))
         continue;
      if (!info.constant && used_in(global, fn, 0))
         *threadgroup_bytes = (*threadgroup_bytes + info.alignment - 1) / info.alignment *
                                 info.alignment + info.size;
   }
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = LLVMIsACallInst(inst) ? LLVMGetCalledValue(inst) : NULL;
         size_t bytes = 0;
         const char *name = callee && LLVMIsAFunction(callee) ? LLVMGetValueName2(callee, &bytes) : NULL;
         *discards |= name && bytes == strlen("air.discard_fragment") &&
                      !memcmp(name, "air.discard_fragment", bytes);
      }
   }
}

/* This is reflection admission, not a change to executable/NIR admission.
 * Reject unknown function metadata/string attributes and unqualified globals
 * instead of claiming absent annotations/constants/static-resource reflection.
 * Threadgroup memory and constant data globals add no function argument;
 * actual selected-entry allocation remains the original NIR compiler's work. The
 * accepted strings are standard LLVM code-generation/FP attributes observed in
 * the retained original AIR, not arbitrary app or compiler-name exceptions. */
static bool
complete_reflection(struct stela_air_metadata *m, LLVMValueRef fn,
                    const struct stela_air_kernel *kernel)
{
   if (LLVMGetFirstGlobal(m->module)) {
      /* Reflection incompleteness is observational, not an inspection failure.
       * Keep executable/profile diagnostics local to this conservative query. */
      struct stela_air_error observed_error = {0};
      struct stela_air_metadata observed = *m;
      observed.error = &observed_error;
      bool threadgroup;
      if (!stela_air_metadata_globals(&observed, &threadgroup) ||
          (threadgroup && !stela_air_metadata_shared_profile(&observed)))
         return false;
   }
   size_t metadata_count;
   LLVMValueMetadataEntry *metadata = LLVMGlobalCopyAllMetadata(fn, &metadata_count);
   LLVMDisposeValueMetadataEntries(metadata);
   if (metadata_count)
      return false;
   unsigned count = LLVMGetAttributeCountAtIndex(fn, LLVMAttributeFunctionIndex);
   if (count > AIR_MAX_METADATA_OPERANDS)
      return false;
   LLVMAttributeRef attributes[AIR_MAX_METADATA_OPERANDS];
   LLVMGetAttributesAtIndex(fn, LLVMAttributeFunctionIndex, attributes);
   const char *allowed[] = {"approx-func-fp-math", "frame-pointer", "min-legal-vector-width",
      "no-builtins", "no-infs-fp-math", "no-nans-fp-math", "no-signed-zeros-fp-math",
      "no-trapping-math", "stack-protector-buffer-size", "unsafe-fp-math"};
   for (unsigned a = 0; a < count; a++) {
      if (!LLVMIsStringAttribute(attributes[a]))
         continue;
      unsigned bytes;
      const char *key = LLVMGetStringAttributeKind(attributes[a], &bytes);
      bool found = false;
      for (unsigned i = 0; i < ARRAY_SIZE(allowed); i++)
         found |= bytes == strlen(allowed[i]) && !memcmp(key, allowed[i], bytes);
      if (!found)
         return false;
   }
   for (unsigned a = 0; a < kernel->count; a++) {
      const struct stela_air_argument *arg = &kernel->arguments[a];
      if (!arg->is_buffer)
         continue;
      if (!arg->plain_buffer_type || !arg->name_bytes || arg->name_bytes > 4096 ||
          memchr(arg->name, 0, arg->name_bytes))
         return false;
      unsigned scalar = arg->primitive <= STELA_AIR_UCHAR ? 1 :
                        arg->primitive <= STELA_AIR_USHORT ? 2 :
                        arg->primitive == STELA_AIR_LONG || arg->primitive == STELA_AIR_ULONG ? 8 : 4;
      unsigned extent = scalar * (arg->type_components == 3 ? 4 : arg->type_components);
      if (arg->buffer.type_size != extent || arg->buffer.type_alignment != extent)
         return false;
      /* Unknown parameter string attributes could carry unimplemented source
       * reflection; only the observed AIR alias contract is recognized here. */
      count = LLVMGetAttributeCountAtIndex(fn, arg->buffer.argument + 1);
      if (count > AIR_MAX_METADATA_OPERANDS)
         return false;
      LLVMGetAttributesAtIndex(fn, arg->buffer.argument + 1, attributes);
      for (unsigned i = 0; i < count; i++) {
         if (!LLVMIsStringAttribute(attributes[i]))
            continue;
         unsigned bytes;
         const char *key = LLVMGetStringAttributeKind(attributes[i], &bytes);
         if (bytes != strlen("air-buffer-no-alias") || memcmp(key, "air-buffer-no-alias", bytes))
            return false;
      }
   }
   return true;
}

/* UTF-8 scalar validation is bounded by the explicit metadata string length.
 * No locale-dependent normalization: opaque linkage bytes compare exactly. */
static bool
stage_text(const char *s, size_t n)
{
   if (!s || !n || n > 4096) return false;
   for (size_t i = 0; i < n;) {
      unsigned a = (unsigned char)s[i++], value, count, minimum;
      if (!a) return false;
      if (a < 0x80) continue;
      if (a >= 0xc2 && a <= 0xdf) { value = a & 31; count = 1; minimum = 0x80; }
      else if (a >= 0xe0 && a <= 0xef) { value = a & 15; count = 2; minimum = 0x800; }
      else if (a >= 0xf0 && a <= 0xf4) { value = a & 7; count = 3; minimum = 0x10000; }
      else return false;
      if (count > n - i) return false;
      while (count--) {
         unsigned b = (unsigned char)s[i++];
         if ((b & 0xc0) != 0x80) return false;
         value = (value << 6) | (b & 63);
      }
      if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
   }
   return true;
}

static bool
metadata_text(struct stela_air_metadata *m, LLVMValueRef v, const char **s, size_t *n)
{
   if (!v || !LLVMIsAMDString(v)) return fail(m, STELA_AIR_METADATA, "expected stage metadata string");
   unsigned bytes;
   *s = LLVMGetMDString(v, &bytes); *n = bytes;
   return stage_text(*s, *n) || fail(m, STELA_AIR_METADATA, "invalid stage metadata text");
}

/* A function constant's storage: an integer, half or float scalar, or a
 * vector of two to four. */
static bool
function_constant_type(LLVMTypeRef type)
{
   if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
      unsigned lanes = LLVMGetVectorSize(type);
      if (lanes < 2 || lanes > 4)
         return false;
      type = LLVMGetElementType(type);
   }
   switch (LLVMGetTypeKind(type)) {
   case LLVMIntegerTypeKind: {
      unsigned width = LLVMGetIntTypeWidth(type);
      return width == 1 || width == 8 || width == 16 || width == 32 || width == 64;
   }
   case LLVMHalfTypeKind:
   case LLVMFloatTypeKind:
      return true;
   default:
      return false;
   }
}

static bool
function_constant_text(LLVMValueRef value, const char **text, size_t *bytes)
{
   if (!value || !LLVMIsAMDString(value))
      return false;
   unsigned length;
   *text = LLVMGetMDString(value, &length);
   *bytes = length;
   return length && stage_text(*text, *bytes);
}

bool
stela_air_metadata_function_constants(struct stela_air_metadata *t,
                                      struct stela_air_function_constant *constants,
                                      LLVMValueRef *storage, unsigned *count)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS], globals[AIR_MAX_FUNCTION_CONSTANTS];
   if (!stela_air_named_md(t, "air.function_constants", nodes, count))
      return false;
   for (unsigned i = 0; i < *count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count, index;
      struct stela_air_function_constant *constant = &constants[i];
      if (!stela_air_md_node(t, nodes[i], fields, &field_count))
         return false;
      LLVMValueRef global = field_count == 4 || field_count == 5 ? fields[0] : NULL;
      if (!global || !LLVMIsAGlobalVariable(global) ||
          LLVMGetPointerAddressSpace(LLVMTypeOf(global)) != 2 || LLVMIsThreadLocal(global) ||
          !function_constant_type(LLVMGlobalGetValueType(global)) ||
          !function_constant_text(fields[1], &constant->type, &constant->type_bytes) ||
          !function_constant_text(fields[2], &constant->name, &constant->name_bytes) ||
          !stela_air_md_uint(fields[3], &index) || index > UINT16_MAX ||
          (field_count == 5 && (!LLVMIsAConstantInt(fields[4]) ||
                                LLVMGetIntTypeWidth(LLVMTypeOf(fields[4])) != 1)))
         return fail(t, STELA_AIR_METADATA, "invalid function constant metadata");
      constant->index = index;
      constant->required = field_count == 5 && LLVMConstIntGetZExtValue(fields[4]);
      globals[i] = global;
      for (unsigned j = 0; j < i; j++) {
         if (constants[j].index == index || globals[j] == global ||
             (constants[j].name_bytes == constant->name_bytes &&
              !memcmp(constants[j].name, constant->name, constant->name_bytes)))
            return fail(t, STELA_AIR_METADATA, "duplicate function constant");
      }
      if (storage)
         storage[i] = global;
   }
   return true;
}

bool
stela_air_metadata_is_function_constant(struct stela_air_metadata *t, LLVMValueRef global)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count = LLVMGetNamedMetadataNumOperands(t->module, "air.function_constants");
   if (count > AIR_MAX_METADATA_OPERANDS)
      return false;
   LLVMGetNamedMetadataOperands(t->module, "air.function_constants", nodes);
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[5];
      unsigned field_count = LLVMIsAMDNode(nodes[i]) ? LLVMGetMDNodeNumOperands(nodes[i]) : 0;
      if (field_count < 4 || field_count > 5)
         continue;
      LLVMGetMDNodeOperands(nodes[i], fields);
      if (fields[0] == global)
         return true;
   }
   return false;
}

/* A constexpr sampler's global and its state's first word. */
static bool
sampler_state(LLVMValueRef global, uint64_t *state)
{
   LLVMValueRef initializer = global && LLVMIsAGlobalVariable(global) ? LLVMGetInitializer(global) : NULL;
   LLVMTypeRef type = initializer ? LLVMTypeOf(initializer) : NULL;
   LLVMLinkage linkage = initializer ? LLVMGetLinkage(global) : LLVMExternalLinkage;
   if (!type || LLVMGetPointerAddressSpace(LLVMTypeOf(global)) != 2 ||
       !LLVMIsGlobalConstant(global) || LLVMIsThreadLocal(global) ||
       (linkage != LLVMInternalLinkage && linkage != LLVMPrivateLinkage))
      return false;
   /* Before Metal 3.2 it is an i64 of the same word with its top bit set. */
   if (LLVMGetTypeKind(type) == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type) == 64 &&
       LLVMIsAConstantInt(initializer)) {
      *state = LLVMConstIntGetZExtValue(initializer) & ~(1ull << 63);
      return true;
   }
   if (LLVMGetTypeKind(type) != LLVMArrayTypeKind || LLVMGetArrayLength2(type) != 2 ||
       LLVMGetTypeKind(LLVMGetElementType(type)) != LLVMIntegerTypeKind ||
       LLVMGetIntTypeWidth(LLVMGetElementType(type)) != 64)
      return false;
   LLVMValueRef words[2] = {LLVMGetAggregateElement(initializer, 0),
                            LLVMGetAggregateElement(initializer, 1)};
   if (!words[0] || !words[1] || !LLVMIsAConstantInt(words[0]) || !LLVMIsAConstantInt(words[1]) ||
       LLVMConstIntGetZExtValue(words[1]))
      return false;
   *state = LLVMConstIntGetZExtValue(words[0]);
   return true;
}

bool
stela_air_metadata_sampler_states(struct stela_air_metadata *t, LLVMValueRef *globals,
                                  uint64_t *states, unsigned *count)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   if (!stela_air_named_md(t, "air.sampler_states", nodes, count))
      return false;
   for (unsigned i = 0; i < *count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count;
      if (!stela_air_md_node(t, nodes[i], fields, &field_count) || field_count != 2 ||
          !stela_air_md_string(fields[0], "air.sampler_state") ||
          !sampler_state(fields[1], &states[i]))
         return fail(t, STELA_AIR_METADATA, "invalid constexpr sampler metadata");
      globals[i] = fields[1];
      for (unsigned j = 0; j < i; j++) {
         if (globals[j] == globals[i])
            return fail(t, STELA_AIR_METADATA, "duplicate constexpr sampler");
      }
   }
   return true;
}

bool
stela_air_metadata_sampler_state(struct stela_air_metadata *t, LLVMValueRef global,
                                 uint64_t *state)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count = LLVMGetNamedMetadataNumOperands(t->module, "air.sampler_states");
   if (count > AIR_MAX_METADATA_OPERANDS)
      return false;
   LLVMGetNamedMetadataOperands(t->module, "air.sampler_states", nodes);
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[2];
      if (LLVMIsAMDNode(nodes[i]) && LLVMGetMDNodeNumOperands(nodes[i]) == 2) {
         LLVMGetMDNodeOperands(nodes[i], fields);
         if (fields[1] == global)
            return sampler_state(global, state);
      }
   }
   return false;
}

static unsigned
primitive_bytes(enum stela_air_primitive p)
{
   return p == STELA_AIR_CHAR || p == STELA_AIR_UCHAR ? 1 :
          p == STELA_AIR_SHORT || p == STELA_AIR_USHORT || p == STELA_AIR_HALF ? 2 :
          p == STELA_AIR_INT || p == STELA_AIR_UINT || p == STELA_AIR_FLOAT ? 4 :
          p == STELA_AIR_LONG || p == STELA_AIR_ULONG ? 8 : 0;
}

static bool
stage_type_matches(LLVMTypeRef type, enum stela_air_primitive p, unsigned n)
{
   if (!n || n > 4) return false;
   if (n > 1) {
      if (LLVMGetTypeKind(type) != LLVMVectorTypeKind || LLVMGetVectorSize(type) != n) return false;
      type = LLVMGetElementType(type);
   }
   return p == STELA_AIR_FLOAT ? LLVMGetTypeKind(type) == LLVMFloatTypeKind :
      p == STELA_AIR_HALF ? LLVMGetTypeKind(type) == LLVMHalfTypeKind :
      primitive_bytes(p) && LLVMGetTypeKind(type) == LLVMIntegerTypeKind &&
      LLVMGetIntTypeWidth(type) == primitive_bytes(p) * 8;
}

bool
stela_air_metadata_output_type(const struct stela_air_stage_io *io, LLVMTypeRef type)
{
   if (io->semantic == STELA_AIR_PRIMITIVE_CULLED)
      return LLVMGetTypeKind(type) == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type) == 1;
   return stage_type_matches(type, io->primitive, io->components);
}

/* The builtin input an argument descriptor's kind names, when the stage has
 * it. Positions and sizes have up to three lanes; the rest are scalars.
 * PATCH is a post-tessellation vertex function. */
static enum stela_air_builtin
builtin_input(LLVMValueRef kind, const struct stela_air_render *render, unsigned *lanes)
{
   enum { KERNEL = 1, VERTEX = 2, FRAGMENT = 4, PATCH = 8, RENDER = VERTEX | FRAGMENT | PATCH,
          ALL = KERNEL | RENDER };
   static const struct {
      const char *name;
      enum stela_air_builtin builtin;
      unsigned stages, lanes;
   } builtins[] = {
      {"air.thread_position_in_grid", STELA_AIR_THREAD_POSITION_IN_GRID, KERNEL, 3},
      {"air.thread_position_in_threadgroup", STELA_AIR_THREAD_POSITION_IN_THREADGROUP, KERNEL, 3},
      {"air.threadgroup_position_in_grid", STELA_AIR_THREADGROUP_POSITION_IN_GRID, KERNEL, 3},
      {"air.threads_per_threadgroup", STELA_AIR_THREADS_PER_THREADGROUP, KERNEL, 3},
      {"air.dispatch_threads_per_threadgroup", STELA_AIR_DISPATCH_THREADS_PER_THREADGROUP, KERNEL, 3},
      {"air.threadgroups_per_grid", STELA_AIR_THREADGROUPS_PER_GRID, KERNEL, 3},
      {"air.threads_per_grid", STELA_AIR_THREADS_PER_GRID, KERNEL, 3},
      {"air.thread_index_in_threadgroup", STELA_AIR_THREAD_INDEX_IN_THREADGROUP, KERNEL, 1},
      {"air.simdgroup_index_in_threadgroup", STELA_AIR_SIMDGROUP_INDEX_IN_THREADGROUP, KERNEL, 1},
      {"air.simdgroups_per_threadgroup", STELA_AIR_SIMDGROUPS_PER_THREADGROUP, KERNEL, 1},
      {"air.dispatch_simdgroups_per_threadgroup", STELA_AIR_DISPATCH_SIMDGROUPS_PER_THREADGROUP,
       KERNEL, 1},
      {"air.quadgroup_index_in_threadgroup", STELA_AIR_QUADGROUP_INDEX_IN_THREADGROUP, KERNEL, 1},
      {"air.quadgroups_per_threadgroup", STELA_AIR_QUADGROUPS_PER_THREADGROUP, KERNEL, 1},
      {"air.dispatch_quadgroups_per_threadgroup", STELA_AIR_DISPATCH_QUADGROUPS_PER_THREADGROUP,
       KERNEL, 1},
      {"air.stage_in_grid_origin", STELA_AIR_STAGE_IN_GRID_ORIGIN, KERNEL, 3},
      {"air.stage_in_grid_size", STELA_AIR_STAGE_IN_GRID_SIZE, KERNEL, 3},
      {"air.thread_index_in_simdgroup", STELA_AIR_THREAD_INDEX_IN_SIMDGROUP, ALL, 1},
      {"air.threads_per_simdgroup", STELA_AIR_THREADS_PER_SIMDGROUP, ALL, 1},
      {"air.thread_execution_width", STELA_AIR_THREAD_EXECUTION_WIDTH, ALL, 1},
      {"air.thread_index_in_quadgroup", STELA_AIR_THREAD_INDEX_IN_QUADGROUP, ALL, 1},
      {"air.vertex_id", STELA_AIR_VERTEX_ID, VERTEX, 1},
      {"air.instance_id", STELA_AIR_INSTANCE_ID, VERTEX | PATCH, 1},
      {"air.base_vertex", STELA_AIR_BASE_VERTEX, VERTEX, 1},
      {"air.base_instance", STELA_AIR_BASE_INSTANCE, VERTEX | PATCH, 1},
      {"air.patch_id", STELA_AIR_PATCH_ID, PATCH, 1},
      {"air.amplification_id", STELA_AIR_AMPLIFICATION_ID, RENDER, 1},
      {"air.amplification_count", STELA_AIR_AMPLIFICATION_COUNT, RENDER, 1},
      {"air.front_facing", STELA_AIR_FRONT_FACING, FRAGMENT, 1},
      {"air.sample_id", STELA_AIR_SAMPLE_ID, FRAGMENT, 1},
      {"air.sample_mask_in", STELA_AIR_SAMPLE_MASK_IN, FRAGMENT, 1},
      {"air.primitive_id", STELA_AIR_PRIMITIVE_ID, FRAGMENT, 1},
      {"air.render_target_array_index", STELA_AIR_RENDER_TARGET_ARRAY_INDEX_IN, FRAGMENT, 1},
      {"air.viewport_array_index", STELA_AIR_VIEWPORT_ARRAY_INDEX_IN, FRAGMENT, 1},
      {"air.point_coord", STELA_AIR_POINT_COORD, FRAGMENT, 2},
   };
   unsigned stage = render && render->entry.stage == STELA_AIR_VERTEX ?
                       (render->entry.patch ? PATCH : VERTEX) :
                    render && render->entry.stage == STELA_AIR_FRAGMENT ? FRAGMENT : KERNEL;
   for (unsigned i = 0; i < ARRAY_SIZE(builtins); i++) {
      if (stela_air_md_string(kind, builtins[i].name)) {
         *lanes = builtins[i].lanes;
         return builtins[i].stages & stage ? builtins[i].builtin : STELA_AIR_BUILTIN_NONE;
      }
   }
   return STELA_AIR_BUILTIN_NONE;
}

/* Stage IO carries 8-, 16- and 32-bit integers and 16- and 32-bit floats. */
static bool
stage_varying(enum stela_air_primitive p)
{
   return p != STELA_AIR_PRIMITIVE_UNKNOWN && p != STELA_AIR_LONG && p != STELA_AIR_ULONG;
}

/* An output's keyed reflection from fields[f]: its type and name, a
 * position's invariance and a depth's qualifier. */
static bool
output_reflection(struct stela_air_metadata *m, const LLVMValueRef *fields, unsigned f, unsigned n,
                  struct stela_air_stage_io *io)
{
   bool qualified = false;
   for (; f < n;) {
      LLVMValueRef key = fields[f++];
      if (stela_air_md_string(key, "air.arg_type_name")) {
         if (io->type_name || f == n ||
             !metadata_text(m, fields[f], &io->type_name, &io->type_name_bytes))
            return fail(m, STELA_AIR_METADATA, "invalid output type name");
         io->primitive = primitive_type(fields[f++], &io->components);
         /* Metal 1 writes the array of clip distances in its type name. */
         if (io->semantic == STELA_AIR_CLIP_DISTANCE && io->type_name_bytes > strlen("float [") &&
             !memcmp(io->type_name, "float [", strlen("float ["))) {
            io->primitive = STELA_AIR_FLOAT;
            io->components = 1;
         }
      } else if (stela_air_md_string(key, "air.arg_name")) {
         if (io->name || f == n || !metadata_text(m, fields[f++], &io->name, &io->name_bytes))
            return fail(m, STELA_AIR_METADATA, "invalid output name");
      } else if (stela_air_md_string(key, "air.shared")) {
         /* The output is the same in every amplified view. Each view runs
          * the function, so the hint changes nothing. */
      } else if (io->semantic == STELA_AIR_POSITION && stela_air_md_string(key, "air.invariant")) {
         if (io->invariant) return fail(m, STELA_AIR_METADATA, "duplicate invariant qualifier");
         io->invariant = true;
      } else if (io->semantic == STELA_AIR_DEPTH && stela_air_md_string(key, "air.depth_qualifier")) {
         if (qualified || f == n) return fail(m, STELA_AIR_METADATA, "invalid depth qualifier");
         LLVMValueRef value = fields[f++];
         if (stela_air_md_string(value, "air.any")) io->depth = STELA_AIR_DEPTH_ANY;
         else if (stela_air_md_string(value, "air.greater")) io->depth = STELA_AIR_DEPTH_GREATER;
         else if (stela_air_md_string(value, "air.less")) io->depth = STELA_AIR_DEPTH_LESS;
         else return fail(m, STELA_AIR_METADATA, "invalid depth qualifier");
         qualified = true;
      } else if (io->semantic == STELA_AIR_RENDER_TARGET &&
                 stela_air_md_string(key, "air.raster_order_group")) {
         /* Color writes already land in raster order, and [[color(n)]]
          * reads keep programmable blending's own order. */
         unsigned group;
         if (f == n || !stela_air_md_uint(fields[f++], &group))
            return fail(m, STELA_AIR_METADATA, "invalid raster order group");
      } else return fail(m, STELA_AIR_METADATA, "unsupported output metadata");
   }
   return true;
}

/* A name Metal before 2.3 leaves on inputs it generated, which says nothing. */
static bool
tool_generated(LLVMValueRef key)
{
   unsigned length = 0;
   const char *text = key && LLVMIsAMDString(key) ? LLVMGetMDString(key, &length) : NULL;
   return text && length > strlen("generated(") && !memcmp(text, "generated(", strlen("generated("));
}

/* A clip distance output's air.clip_distance_array_size at fields[*f]. */
static bool
clip_distance_size(struct stela_air_metadata *m, const LLVMValueRef *fields, unsigned *f,
                   unsigned n, struct stela_air_stage_io *io)
{
   if (*f + 2 > n || !stela_air_md_string(fields[*f], "air.clip_distance_array_size") ||
       !stela_air_md_uint(fields[*f + 1], &io->clip_distances) || !io->clip_distances ||
       io->clip_distances > AIR_MAX_CLIP_DISTANCES)
      return fail(m, STELA_AIR_ARGUMENT, "clip distances need an array size of 1 to %u",
                  AIR_MAX_CLIP_DISTANCES);
   *f += 2;
   return true;
}

/* Whether an output's reflected type suits its semantic. */
/* A fragment's [[imageblock_data]] input or output from its descriptor's
 * keys from f: a struct of the size its descriptor names, which every one
 * of the function's shares. */
static bool
imageblock_data(struct stela_air_metadata *m, const LLVMValueRef *fields, unsigned f, unsigned n,
                LLVMTypeRef type, struct stela_air_stage_io *io, unsigned *bytes)
{
   unsigned size = 0;
   for (; f + 1 < n; f++) {
      if (stela_air_md_string(fields[f], "air.imageblock_data_size") &&
          !stela_air_md_uint(fields[f + 1], &size))
         size = 0;
      else if (stela_air_md_string(fields[f], "air.arg_type_name"))
         metadata_text(m, fields[f + 1], &io->type_name, &io->type_name_bytes);
      else if (stela_air_md_string(fields[f], "air.arg_name"))
         metadata_text(m, fields[f + 1], &io->name, &io->name_bytes);
   }
   if (!size || LLVMGetTypeKind(type) != LLVMStructTypeKind || LLVMIsOpaqueStruct(type))
      return fail(m, STELA_AIR_ARGUMENT, "imageblock data of an unknown layout");
   if (io->absent)
      return true;
   if (*bytes && *bytes != size)
      return fail(m, STELA_AIR_ARGUMENT, "a fragment's imageblock data of two sizes");
   *bytes = size;
   return true;
}

static bool
output_type(const struct stela_air_stage_io *io)
{
   bool scalar = io->components == 1;
   bool integer = io->primitive == STELA_AIR_INT || io->primitive == STELA_AIR_UINT;
   switch (io->semantic) {
   case STELA_AIR_POSITION: return io->primitive == STELA_AIR_FLOAT && io->components == 4;
   case STELA_AIR_VARYING: case STELA_AIR_RENDER_TARGET: return stage_varying(io->primitive);
   case STELA_AIR_POINT_SIZE: case STELA_AIR_DEPTH: case STELA_AIR_CLIP_DISTANCE:
      return io->primitive == STELA_AIR_FLOAT && scalar;
   case STELA_AIR_PRIMITIVE_CULLED:
      return io->type_name_bytes == strlen("bool") && !memcmp(io->type_name, "bool", strlen("bool"));
   default: return integer && scalar; /* Indices, the primitive ID, masks and stencil. */
   }
}

/* Whether two outputs write the same thing; varyings are linked by
 * identifier. */
static bool
same_output(const struct stela_air_stage_io *a, const struct stela_air_stage_io *b)
{
   if (a->semantic != b->semantic)
      return false;
   if (a->semantic == STELA_AIR_VARYING)
      return a->identifier_bytes == b->identifier_bytes &&
             !memcmp(a->identifier, b->identifier, a->identifier_bytes);
   if (a->semantic == STELA_AIR_RENDER_TARGET)
      return a->location == b->location && a->index == b->index;
   return true;
}

/* One entry of a mesh's vertex or primitive data. */
static bool
mesh_output(struct stela_air_metadata *m, LLVMValueRef node, bool per_primitive,
            struct stela_air_stage_io *io)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned n, f = 1;
   if (!stela_air_md_node(m, node, fields, &n) || !n)
      return fail(m, STELA_AIR_METADATA, "invalid mesh output descriptor");
   *io = (struct stela_air_stage_io){.per_primitive = per_primitive};
   if (stela_air_md_string(fields[0], per_primitive ? "air.mesh_primitive_data" :
                                                      "air.mesh_vertex_data")) {
      io->semantic = STELA_AIR_VARYING;
      if (n < 3 || !stela_air_md_uint(fields[f++], &io->index) ||
          !metadata_text(m, fields[f++], &io->identifier, &io->identifier_bytes))
         return fail(m, STELA_AIR_METADATA, "invalid mesh data output");
   } else if (!per_primitive && stela_air_md_string(fields[0], "air.position")) {
      io->semantic = STELA_AIR_POSITION;
   } else if (!per_primitive && stela_air_md_string(fields[0], "air.point_size")) {
      io->semantic = STELA_AIR_POINT_SIZE;
   } else if (!per_primitive && stela_air_md_string(fields[0], "air.clip_distance")) {
      io->semantic = STELA_AIR_CLIP_DISTANCE;
      if (!clip_distance_size(m, fields, &f, n, io))
         return false;
   } else if (per_primitive && stela_air_md_string(fields[0], "air.render_target_array_index")) {
      io->semantic = STELA_AIR_LAYER;
   } else if (per_primitive && stela_air_md_string(fields[0], "air.viewport_array_index")) {
      io->semantic = STELA_AIR_VIEWPORT;
   } else if (per_primitive && stela_air_md_string(fields[0], "air.primitive_id")) {
      io->semantic = STELA_AIR_MESH_PRIMITIVE_ID;
   } else if (per_primitive && stela_air_md_string(fields[0], "air.primitive_culled")) {
      io->semantic = STELA_AIR_PRIMITIVE_CULLED;
   } else {
      return fail(m, STELA_AIR_METADATA, "unsupported mesh output semantic");
   }
   if (!output_reflection(m, fields, f, n, io))
      return false;
   /* A bool, which no primitive names, in one lane. */
   if (io->semantic == STELA_AIR_PRIMITIVE_CULLED)
      io->components = 1;
   return (output_type(io) && stage_text(io->name, io->name_bytes)) ||
      fail(m, STELA_AIR_TYPE, "unsupported mesh output type");
}

/* A mesh argument's air.mesh_type_info: its vertex data, primitive data,
 * vertex and primitive capacities and topology, which are the mesh
 * function's outputs. */
static bool
mesh_outputs(struct stela_air_metadata *m, struct stela_air_render *r, LLVMValueRef node)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS], lists[2][AIR_MAX_METADATA_OPERANDS];
   unsigned n, counts[2];
   struct stela_air_stage_entry *entry = &r->entry;
   if (!stela_air_md_node(m, node, fields, &n) || n != 6 ||
       !stela_air_md_string(fields[0], "air.mesh_type_info") ||
       !stela_air_md_node(m, fields[1], lists[0], &counts[0]) ||
       !stela_air_md_node(m, fields[2], lists[1], &counts[1]) ||
       !stela_air_md_uint(fields[3], &entry->max_vertices) ||
       !stela_air_md_uint(fields[4], &entry->max_primitives))
      return fail(m, STELA_AIR_METADATA, "invalid mesh type info");
   entry->topology = stela_air_md_string(fields[5], "air.point") ? STELA_AIR_POINTS :
                     stela_air_md_string(fields[5], "air.line") ? STELA_AIR_LINES :
                     stela_air_md_string(fields[5], "air.triangle") ? STELA_AIR_TRIANGLES : 0;
   if (!entry->topology || !entry->max_vertices || !entry->max_primitives ||
       entry->max_vertices > UINT16_MAX || entry->max_primitives > UINT16_MAX)
      return fail(m, STELA_AIR_ARGUMENT, "unsupported mesh topology or capacity");
   if (counts[0] + counts[1] > AIR_MAX_ARGUMENTS)
      return fail(m, STELA_AIR_LIMIT, "mesh output budget exceeded");
   unsigned positions = 0;
   for (unsigned list = 0; list < 2; list++) {
      for (unsigned i = 0; i < counts[list]; i++) {
         struct stela_air_stage_io *io = &r->outputs[entry->output_count];
         if (!mesh_output(m, lists[list][i], list == 1, io))
            return false;
         io->argument = entry->output_count;
         for (unsigned j = 0; j < entry->output_count; j++) {
            const struct stela_air_stage_io *other = &r->outputs[j];
            /* Mesh data is also set by its data index. */
            if (same_output(io, other) ||
                (io->semantic == STELA_AIR_VARYING && other->semantic == STELA_AIR_VARYING &&
                 io->per_primitive == other->per_primitive && io->index == other->index))
               return fail(m, STELA_AIR_METADATA, "duplicate mesh output");
         }
         positions += io->semantic == STELA_AIR_POSITION;
         entry->output_count++;
      }
   }
   return positions == 1 ||
      fail(m, STELA_AIR_METADATA, "mesh vertices require exactly one position");
}

static bool argument_fields(struct stela_air_metadata *m, struct stela_air_kernel *kernel,
                            LLVMValueRef node, unsigned extent, unsigned argument,
                            unsigned depth, struct stela_air_fields *fields);

/* Whether key is an access key, whose texture or buffer access *access
 * receives. */
static bool
field_access(LLVMValueRef key, bool texture, unsigned *access)
{
   if (texture && stela_air_md_string(key, "air.sample"))
      *access = STELA_AIR_TEXTURE_SAMPLE;
   else if (stela_air_md_string(key, "air.read"))
      *access = texture ? STELA_AIR_TEXTURE_READ : STELA_AIR_READ;
   else if (stela_air_md_string(key, "air.write"))
      *access = texture ? STELA_AIR_TEXTURE_WRITE : STELA_AIR_WRITE;
   else if (stela_air_md_string(key, "air.read_write"))
      *access = texture ? STELA_AIR_TEXTURE_READ_WRITE : STELA_AIR_READ_WRITE;
   else
      return false;
   return true;
}

/* The kinds of an argument buffer's fields, as their argument tuples name
 * them. */
static bool
field_kind(LLVMValueRef name, enum stela_air_field_kind *kind)
{
   static const struct {
      const char *name;
      enum stela_air_field_kind kind;
   } kinds[] = {
      {"air.indirect_constant", STELA_AIR_FIELD_DATA},
      {"air.buffer", STELA_AIR_FIELD_BUFFER},
      {"air.indirect_buffer", STELA_AIR_FIELD_ARGUMENTS},
      {"air.texture", STELA_AIR_FIELD_TEXTURE},
      {"air.sampler", STELA_AIR_FIELD_SAMPLER},
      {"air.command_buffer", STELA_AIR_FIELD_COMMANDS},
      {"air.render_pipeline_state", STELA_AIR_FIELD_RENDER_PIPELINE},
      {"air.compute_pipeline_state", STELA_AIR_FIELD_COMPUTE_PIPELINE},
      {"air.visible_function_table", STELA_AIR_FIELD_FUNCTION_TABLE},
   };
   for (unsigned k = 0; k < ARRAY_SIZE(kinds); k++) {
      if (stela_air_md_string(name, kinds[k].name)) {
         *kind = kinds[k].kind;
         return true;
      }
   }
   return false;
}

/* One field's argument tuple: its position, its kind and its keyed
 * reflection, as a top-level argument of that kind spells it. Its [[id]],
 * *id, counts from id_base, that of the structure inlining it. */
static bool
argument_field(struct stela_air_metadata *m, struct stela_air_kernel *kernel, LLVMValueRef node,
               unsigned argument, unsigned depth, unsigned id_base, struct stela_air_field *field,
               unsigned *id)
{
   LLVMValueRef operands[AIR_MAX_METADATA_OPERANDS];
   unsigned count, position;
   if (!stela_air_md_node(m, node, operands, &count) || count < 2 ||
       !stela_air_md_uint(operands[0], &position))
      return fail(m, STELA_AIR_METADATA, "invalid argument buffer field");
   if (!field_kind(operands[1], &field->kind))
      return fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer field kind");
   bool texture = field->kind == STELA_AIR_FIELD_TEXTURE;
   bool table = field->kind == STELA_AIR_FIELD_FUNCTION_TABLE;
   bool buffer = field->kind == STELA_AIR_FIELD_BUFFER || field->kind == STELA_AIR_FIELD_ARGUMENTS;
   bool has_location = false, has_access = false, has_space = false, has_size = false;
   unsigned index = 0, access = 0, keyed, buffer_size = 0;
   const char *type_name = NULL;
   unsigned type_name_bytes = 0;
   LLVMValueRef info = NULL;
   for (unsigned f = 2; f < count;) {
      LLVMValueRef key = operands[f++];
      unsigned *number = stela_air_md_string(key, "air.address_space") ? &field->buffer.address_space :
                         stela_air_md_string(key, "air.buffer_size") ? &buffer_size :
                         stela_air_md_string(key, "air.arg_type_size") ? &field->buffer.type_size :
                         stela_air_md_string(key, "air.arg_type_align_size") ?
                            &field->buffer.type_alignment : NULL;
      if (stela_air_md_string(key, "air.location_index")) {
         if (has_location || f + 2 > count || !stela_air_md_uint(operands[f], &index) ||
             !stela_air_md_uint(operands[f + 1], &field->count) || !field->count)
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field location");
         has_location = true;
         f += 2;
      } else if (field_access(key, texture, &keyed)) {
         if (has_access || (!buffer && !texture && !table))
            return fail(m, STELA_AIR_METADATA, "duplicate/inapplicable argument buffer field access");
         access = keyed;
         has_access = true;
      } else if (number) {
         if (!buffer || f == count || !stela_air_md_uint(operands[f++], number))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field size or space");
         has_space |= number == &field->buffer.address_space;
         has_size |= number == &buffer_size;
      } else if (stela_air_md_string(key, "air.struct_type_info")) {
         /* A buffer's layout is the pointee's own business. */
         if ((field->kind != STELA_AIR_FIELD_ARGUMENTS && !buffer) || info || f == count)
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field structure");
         if (field->kind == STELA_AIR_FIELD_ARGUMENTS)
            info = operands[f];
         f++;
      } else if (stela_air_md_string(key, "air.arg_type_name") ||
                 stela_air_md_string(key, "air.arg_name")) {
         if (f == count || !operands[f] || !LLVMIsAMDString(operands[f]))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field name");
         if (stela_air_md_string(key, "air.arg_type_name"))
            type_name = LLVMGetMDString(operands[f], &type_name_bytes);
         f++;
      } else {
         return fail(m, STELA_AIR_METADATA, "unsupported argument buffer field metadata");
      }
   }
   if (!has_location || index > UINT16_MAX - id_base)
      return fail(m, STELA_AIR_METADATA, "argument buffer field lacks a location");
   index += id_base;
   *id = index;
   /* Apple's compiler names an array of resources array<element, count>. */
   if (type_name && field->count > 1 && type_name_bytes > strlen("array<") &&
       !memcmp(type_name, "array<", strlen("array<")) &&
       !array_type(&type_name, &type_name_bytes, field->count))
      return fail(m, STELA_AIR_METADATA, "argument buffer array and location counts differ");
   switch (field->kind) {
   case STELA_AIR_FIELD_DATA:
   case STELA_AIR_FIELD_COMMANDS:
   case STELA_AIR_FIELD_RENDER_PIPELINE:
   case STELA_AIR_FIELD_COMPUTE_PIPELINE:
      return true;
   case STELA_AIR_FIELD_TEXTURE:
      field->texture = (struct stela_air_texture){.argument = argument, .index = index,
                                                  .access = access};
      return (has_access && type_name && texture_type(type_name, type_name_bytes, &field->texture)) ||
         fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer texture");
   case STELA_AIR_FIELD_SAMPLER:
      field->sampler = (struct stela_air_sampler){.argument = argument, .index = index};
      return (type_name && type_name_bytes == strlen("sampler") &&
              !memcmp(type_name, "sampler", type_name_bytes)) ||
         fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer sampler");
   case STELA_AIR_FIELD_FUNCTION_TABLE:
      /* Tables are only read, through their handles. */
      field->buffer = (struct stela_air_buffer){.argument = argument, .index = index,
                                                .access = STELA_AIR_READ, .address_space = 1};
      return (!has_access || access == STELA_AIR_READ) ||
         fail(m, STELA_AIR_ARGUMENT, "a visible function table is only read");
   case STELA_AIR_FIELD_BUFFER:
   case STELA_AIR_FIELD_ARGUMENTS:
      break;
   }
   struct stela_air_buffer *desc = &field->buffer;
   desc->argument = argument;
   desc->index = index;
   desc->access = access;
   /* Before Metal 3.0 no field names its address space, which only its access
    * can tell, and both are the same memory. */
   if (!has_space)
      desc->address_space = access == STELA_AIR_READ ? 2 : 1;
   if (!has_access || desc->address_space < 1 || desc->address_space > 2 ||
       (desc->address_space == 2 && access != STELA_AIR_READ) ||
       (desc->type_alignment & (desc->type_alignment - 1)))
      return fail(m, STELA_AIR_ARGUMENT, "unsupported buffer in an argument buffer");
   if (field->kind == STELA_AIR_FIELD_BUFFER)
      return true;
   if (!info || !desc->type_size || (has_size && buffer_size != desc->type_size))
      return fail(m, STELA_AIR_ARGUMENT, "unsupported nested argument buffer");
   return argument_fields(m, kernel, info, desc->type_size, argument, depth + 1, &field->arguments);
}

/* An argument buffer's air.struct_type_info lists its members in increasing
 * offsets: per field its offset, byte size, element count (zero for one),
 * type name, name, "air.indirect_argument" and argument tuple; per structure
 * it inlines "air.struct_type_info" and that structure's node first, its
 * element size in place of the byte size and its first [[id]] in place of
 * an argument tuple. An inlined structure's fields are the enclosing
 * buffer's, element after element, each taking the [[id]]s after the
 * last's. */
enum { MEMBER = 7, INLINED = 9 };

static bool
structure_operands(struct stela_air_metadata *m, LLVMValueRef node, unsigned depth,
                   LLVMValueRef *operands, unsigned *count)
{
   if (depth >= AIR_MAX_ARGUMENT_BUFFER_DEPTH)
      return fail(m, STELA_AIR_LIMIT, "argument buffer nesting exceeded");
   return (stela_air_md_node(m, node, operands, count) && *count) ||
      fail(m, STELA_AIR_METADATA, "invalid argument buffer structure");
}

/* The fields of a structure, its inlined structures' among them. */
static bool
structure_field_count(struct stela_air_metadata *m, LLVMValueRef node, unsigned depth,
                      unsigned *fields)
{
   LLVMValueRef operands[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!structure_operands(m, node, depth, operands, &count))
      return false;
   *fields = 0;
   for (unsigned i = 0; i < count;) {
      bool inlined = stela_air_md_string(operands[i], "air.struct_type_info");
      unsigned inner = 1, elements = 1;
      if (i + (inlined ? INLINED : MEMBER) > count ||
          (inlined && (!stela_air_md_uint(operands[i + 4], &elements) ||
                       !structure_field_count(m, operands[i + 1], depth + 1, &inner))))
         return fail(m, STELA_AIR_METADATA, "invalid argument buffer structure");
      elements = MAX2(elements, 1);
      if (inner > (AIR_MAX_FIELDS - *fields) / elements)
         return fail(m, STELA_AIR_LIMIT, "argument buffer field budget exceeded");
      *fields += inner * elements;
      i += inlined ? INLINED : MEMBER;
   }
   return true;
}

/* A member's offset, size and element count, checking its names. */
static bool
member_layout(struct stela_air_metadata *m, const LLVMValueRef *member, unsigned *offset,
              unsigned *size, unsigned *elements)
{
   return (stela_air_md_uint(member[0], offset) && stela_air_md_uint(member[1], size) &&
           stela_air_md_uint(member[2], elements) && member[3] && LLVMIsAMDString(member[3]) &&
           member[4] && LLVMIsAMDString(member[4]) &&
           stela_air_md_string(member[5], "air.indirect_argument")) ||
      fail(m, STELA_AIR_METADATA, "invalid argument buffer member");
}

/* Fills the fields of a structure at byte base and [[id]] id_base of its
 * argument buffer, in extent bytes, from kernel->fields[*next]. Their
 * offsets increase from *end, which receives the last one's end, and *ids
 * receives the [[id]]s the structure spans. */
static bool
structure_fields(struct stela_air_metadata *m, struct stela_air_kernel *kernel, LLVMValueRef node,
                 unsigned base, unsigned id_base, unsigned extent, unsigned argument,
                 unsigned depth, unsigned *next, unsigned *end, unsigned *ids)
{
   LLVMValueRef operands[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!structure_operands(m, node, depth, operands, &count))
      return false;
   *ids = 0;
   for (unsigned i = 0; i < count;) {
      bool inlined = stela_air_md_string(operands[i], "air.struct_type_info");
      const LLVMValueRef *member = &operands[inlined ? i + 2 : i];
      unsigned offset, size, elements, id;
      if (!member_layout(m, member, &offset, &size, &elements))
         return false;
      if (inlined) {
         elements = MAX2(elements, 1);
         if (!stela_air_md_uint(member[6], &id) || id > UINT16_MAX - id_base)
            return fail(m, STELA_AIR_METADATA, "invalid inlined argument buffer structure");
         if (!size || offset > extent || size > (extent - offset) / elements)
            return fail(m, STELA_AIR_TYPE, "argument buffer members overlap or exceed the buffer");
         unsigned span = 0;
         for (unsigned e = 0; e < elements; e++) {
            unsigned spanned;
            if (e * span > UINT16_MAX - id_base - id)
               return fail(m, STELA_AIR_METADATA, "invalid inlined argument buffer structure");
            if (!structure_fields(m, kernel, operands[i + 1], base + offset + e * size,
                                  id_base + id + e * span, size, argument, depth + 1, next, end,
                                  &spanned))
               return false;
            span = e ? span : spanned;
         }
         *ids = MAX2(*ids, id + elements * span);
         i += INLINED;
         continue;
      }
      struct stela_air_field *field = &kernel->fields[(*next)++];
      *field = (struct stela_air_field){0};
      if (!argument_field(m, kernel, member[6], argument, depth, id_base, field, &id))
         return false;
      /* An array of pointers sizes and locates its element once. */
      if (elements > 1 && field->count == 1) {
         if (size > extent / elements)
            return fail(m, STELA_AIR_TYPE, "argument buffer members overlap or exceed the buffer");
         field->count = elements;
         size *= elements;
      }
      *ids = MAX2(*ids, id - id_base + field->count);
      field->offset = base + offset;
      field->size = size;
      if (elements && elements != field->count)
         return fail(m, STELA_AIR_METADATA, "argument buffer member and location counts differ");
      if (!size || size % field->count || offset > extent || size > extent - offset ||
          field->offset < *end)
         return fail(m, STELA_AIR_TYPE, "argument buffer members overlap or exceed the buffer");
      if (field->kind != STELA_AIR_FIELD_DATA && (field->offset % 8 || size / field->count != 8))
         return fail(m, STELA_AIR_TYPE, "argument buffer addresses and IDs are aligned 8-byte values");
      *end = field->offset + size;
      i += MEMBER;
   }
   return true;
}

static bool
argument_fields(struct stela_air_metadata *m, struct stela_air_kernel *kernel, LLVMValueRef node,
                unsigned extent, unsigned argument, unsigned depth, struct stela_air_fields *fields)
{
   unsigned count;
   if (!structure_field_count(m, node, depth, &count))
      return false;
   if (count > AIR_MAX_FIELDS - kernel->field_count)
      return fail(m, STELA_AIR_LIMIT, "argument buffer field budget exceeded");
   /* Reserve this level's range before nested levels take theirs. */
   *fields = (struct stela_air_fields){kernel->field_count, count, extent};
   kernel->field_count += count;
   unsigned next = fields->first, end = 0, ids;
   return structure_fields(m, kernel, node, 0, 0, extent, argument, depth, &next, &end, &ids);
}

/* An argument buffer member's argument tuple, as a top-level argument of
 * its kind spells it; a nested argument buffer's layout is the member's. */
static bool
layout_argument(struct stela_air_metadata *m, LLVMValueRef node,
                struct stela_air_layout_member *member)
{
   LLVMValueRef operands[AIR_MAX_METADATA_OPERANDS];
   unsigned count, position, locations = 1;
   if (!stela_air_md_node(m, node, operands, &count) || count < 2 ||
       !stela_air_md_uint(operands[0], &position) || !field_kind(operands[1], &member->kind))
      return fail(m, STELA_AIR_METADATA, "invalid argument buffer member argument");
   bool texture = member->kind == STELA_AIR_FIELD_TEXTURE;
   const char *type_name = NULL;
   unsigned type_name_bytes = 0, access, ignored;
   for (unsigned f = 2; f < count;) {
      LLVMValueRef key = operands[f++];
      unsigned *number = stela_air_md_string(key, "air.address_space") ? &member->buffer.address_space :
                         stela_air_md_string(key, "air.arg_type_size") ? &member->buffer.type_size :
                         stela_air_md_string(key, "air.arg_type_align_size") ?
                            &member->buffer.type_alignment :
                         stela_air_md_string(key, "air.buffer_size") ? &ignored : NULL;
      if (field_access(key, texture, &access)) {
         if (texture)
            member->texture.access = access;
         else
            member->buffer.access = access;
      } else if (stela_air_md_string(key, "air.location_index")) {
         if (f + 2 > count || !stela_air_md_uint(operands[f], &member->id) ||
             !stela_air_md_uint(operands[f + 1], &locations))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer member location");
         f += 2;
      } else if (number) {
         if (f == count || !stela_air_md_uint(operands[f++], number))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer member size or space");
      } else if (stela_air_md_string(key, "air.struct_type_info")) {
         if (f == count)
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer member structure");
         member->layout = (const struct stela_air_layout *)operands[f++];
      } else if (stela_air_md_string(key, "air.arg_type_name") ||
                 stela_air_md_string(key, "air.arg_name")) {
         if (f == count || !operands[f] || !LLVMIsAMDString(operands[f]))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer member name");
         if (stela_air_md_string(key, "air.arg_type_name"))
            type_name = LLVMGetMDString(operands[f], &type_name_bytes);
         f++;
      } else {
         return fail(m, STELA_AIR_METADATA, "unsupported argument buffer member metadata");
      }
   }
   member->count = locations;
   if (!texture)
      return true;
   /* An array of textures names its element. */
   if (type_name && locations > 1)
      array_type(&type_name, &type_name_bytes, locations);
   member->texture.length = locations > 1 ? locations : 0;
   return (type_name && texture_type(type_name, type_name_bytes, &member->texture)) ||
      fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer texture");
}

/* A plain structure's members are (offset, size, elements, type, name);
 * an argument buffer's follow each with "air.indirect_argument" and its
 * argument tuple. A member that is a structure is prefixed by
 * "air.struct_type_info" and its layout, and in an argument buffer has its
 * first [[id]] in place of a tuple. */
enum { LAYOUT_FIELDS = 5 };

bool
stela_air_layout_members(const struct stela_air_inspection *info,
                         const struct stela_air_layout *layout, stela_air_visit_member visit,
                         void *data)
{
   struct stela_air_metadata *m = info->metadata;
   LLVMValueRef node = (LLVMValueRef)layout;
   if (!node || !LLVMIsAMDNode(node))
      return fail(m, STELA_AIR_METADATA, "expected a structure layout");
   /* Structures may have more members than other nodes have operands. */
   unsigned count = LLVMGetMDNodeNumOperands(node);
   LLVMValueRef *operands = malloc(MAX2(count, 1) * sizeof(*operands));
   if (!operands)
      return fail(m, STELA_AIR_ALLOCATION, "structure layout allocation failed");
   LLVMGetMDNodeOperands(node, operands);
   bool visited = true;
   for (unsigned i = 0; visited && i < count;) {
      struct stela_air_layout_member member = {0};
      if (stela_air_md_string(operands[i], "air.struct_type_info")) {
         if (i + 2 > count) {
            visited = fail(m, STELA_AIR_METADATA, "invalid structure layout");
            break;
         }
         member.layout = (const struct stela_air_layout *)operands[i + 1];
         i += 2;
      }
      unsigned name_bytes, type_name_bytes;
      if (i + LAYOUT_FIELDS > count || !stela_air_md_uint(operands[i], &member.offset) ||
          !stela_air_md_uint(operands[i + 1], &member.size) ||
          !stela_air_md_uint(operands[i + 2], &member.elements) ||
          !operands[i + 3] || !LLVMIsAMDString(operands[i + 3]) ||
          !operands[i + 4] || !LLVMIsAMDString(operands[i + 4])) {
         visited = fail(m, STELA_AIR_METADATA, "invalid structure layout member");
         break;
      }
      member.type_name = LLVMGetMDString(operands[i + 3], &type_name_bytes);
      member.name = LLVMGetMDString(operands[i + 4], &name_bytes);
      member.type_name_bytes = type_name_bytes;
      member.name_bytes = name_bytes;
      i += LAYOUT_FIELDS;
      if (i < count && stela_air_md_string(operands[i], "air.indirect_argument")) {
         member.argument = true;
         visited = i + 2 <= count &&
            (member.layout ? stela_air_md_uint(operands[i + 1], &member.id) :
                             layout_argument(m, operands[i + 1], &member));
         if (!visited) {
            fail(m, STELA_AIR_METADATA, "invalid argument buffer member");
            break;
         }
         i += 2;
      }
      visited = visit(&member, data);
   }
   free(operands);
   return visited;
}

/* A post-tessellation vertex function's patch_control_point<T> stage-in:
 * {i32 argument, "air.patch_control_point_input",
 * {"air.patch_control_point_function", fn}, member...}. fn, externally
 * defined, returns a control point's members as a struct from its index in
 * the patch and the argument. Each member names its attribute's
 * air.location_index, its type and name, and air.arg_unused when the
 * function never reads it. */
static bool
control_point_input(struct stela_air_metadata *m, struct stela_air_render *r,
                    struct stela_air_stage_io *io, LLVMValueRef param, const LLVMValueRef *fields,
                    unsigned count, bool *locations)
{
   LLVMValueRef function[AIR_MAX_METADATA_OPERANDS];
   unsigned n;
   if (r->control_point_function || count < 4 || !stela_air_md_node(m, fields[2], function, &n) ||
       n != 2 || !stela_air_md_string(function[0], "air.patch_control_point_function") ||
       !function[1] || !LLVMIsAFunction(function[1]))
      return fail(m, STELA_AIR_METADATA, "invalid/duplicate patch control point input");
   LLVMValueRef fn = function[1];
   LLVMTypeRef type = LLVMGlobalGetValueType(fn), result = LLVMGetReturnType(type);
   const char *section = LLVMGetSection(fn);
   unsigned members = count - 3;
   if (!LLVMIsDeclaration(fn) || !section || strcmp(section, "air.externally_defined") ||
       LLVMGetFunctionCallConv(fn) != LLVMCCallConv || LLVMIsFunctionVarArg(type) ||
       LLVMCountParamTypes(type) != 2 || LLVMGetTypeKind(result) != LLVMStructTypeKind ||
       LLVMIsOpaqueStruct(result) || LLVMIsPackedStruct(result) ||
       LLVMCountStructElementTypes(result) != members || members > AIR_MAX_ARGUMENTS - r->member_count)
      return fail(m, STELA_AIR_ARGUMENT, "unsupported patch control point function");
   LLVMTypeRef params[2];
   LLVMGetParamTypes(type, params);
   if (LLVMGetTypeKind(params[0]) != LLVMIntegerTypeKind || LLVMGetIntTypeWidth(params[0]) != 32 ||
       LLVMGetTypeKind(params[1]) != LLVMPointerTypeKind || LLVMGetPointerAddressSpace(params[1]) ||
       LLVMTypeOf(param) != params[1])
      return fail(m, STELA_AIR_ARGUMENT, "unsupported patch control point function parameters");
   io->members = &r->members[r->member_count];
   for (unsigned i = 0; i < members; i++) {
      struct stela_air_struct_member *member = &r->members[r->member_count++];
      io->member_count++;
      LLVMValueRef info[AIR_MAX_METADATA_OPERANDS];
      unsigned info_count, attributes;
      bool located = false, typed = false, named = false;
      if (!stela_air_md_node(m, fields[3 + i], info, &info_count))
         return false;
      for (unsigned f = 0; f < info_count;) {
         LLVMValueRef key = info[f++];
         if (!located && stela_air_md_string(key, "air.location_index") && f + 2 <= info_count &&
             stela_air_md_uint(info[f], &member->location) &&
             stela_air_md_uint(info[f + 1], &attributes) && attributes == 1) {
            located = true;
            f += 2;
         } else if (!typed && stela_air_md_string(key, "air.arg_type_name") && f < info_count &&
                    metadata_text(m, info[f], &member->type_name, &member->type_name_bytes)) {
            member->primitive = primitive_type(info[f++], &member->components);
            typed = true;
         } else if (!named && stela_air_md_string(key, "air.arg_name") && f < info_count &&
                    metadata_text(m, info[f++], &member->name, &member->name_bytes)) {
            named = true;
         } else if (!member->unused && stela_air_md_string(key, "air.arg_unused")) {
            member->unused = true;
         } else if (!tool_generated(key)) {
            return fail(m, STELA_AIR_METADATA, "unsupported patch control point member metadata");
         }
      }
      if (!located || !typed || !named || member->location >= AIR_MAX_VERTEX_ATTRIBUTES ||
          locations[member->location] || !stage_varying(member->primitive) ||
          !stage_type_matches(LLVMStructGetTypeAtIndex(result, i), member->primitive, member->components))
         return fail(m, STELA_AIR_ARGUMENT, "unsupported/duplicate control point attribute %u", i);
      locations[member->location] = true;
   }
   r->control_point_function = fn;
   return true;
}

/* The bits of a [[function_constant]] argument's predicate of the named
 * scalar type, or 0. */
static unsigned
predicate_bits(LLVMValueRef name)
{
   static const struct {
      const char *name;
      unsigned bits;
   } types[] = {
      {"bool", 8},  {"char", 8},  {"uchar", 8}, {"short", 16}, {"ushort", 16},
      {"int", 32},  {"uint", 32}, {"long", 64}, {"ulong", 64},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
      if (stela_air_md_string(name, types[i].name))
         return types[i].bits;
   }
   return 0;
}

/* A [[function_constant]] argument's predicate, {ptr addrspace(2)
 * @predicate, !"type", !"name"}: an internal AS2 integer of the constant's
 * scalar type, a bool or one Metal tests against zero, that the module's
 * constructors store. Once specialization has constructed it, *known is set,
 * and *absent when it is zero. */
static bool
argument_predicate(struct stela_air_metadata *m, LLVMValueRef node, bool *known, bool *absent)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(m, node, fields, &count))
      return false;
   LLVMValueRef global = count == 3 ? fields[0] : NULL;
   LLVMValueRef value = global && LLVMIsAGlobalVariable(global) ? LLVMGetInitializer(global) : NULL;
   LLVMTypeRef type = value ? LLVMGlobalGetValueType(global) : NULL;
   if (!value || !LLVMIsAConstantInt(value) || LLVMGetPointerAddressSpace(LLVMTypeOf(global)) != 2 ||
       LLVMGetLinkage(global) != LLVMInternalLinkage || LLVMGetTypeKind(type) != LLVMIntegerTypeKind ||
       LLVMGetIntTypeWidth(type) != predicate_bits(fields[1]) || !fields[2] ||
       !LLVMIsAMDString(fields[2]))
      return fail(m, STELA_AIR_METADATA, "invalid function constant argument predicate");
   *known = LLVMIsGlobalConstant(global);
   *absent = *known && !LLVMConstIntGetZExtValue(value);
   return true;
}

/* An argument's attribute index: a number, or the AS2 global the module's
 * constructors compute a constant expression into, zero until specialization
 * has constructed it. */
static bool
argument_location(LLVMValueRef field, unsigned *location)
{
   if (stela_air_md_uint(field, location))
      return true;
   LLVMValueRef value = field && LLVMIsAGlobalVariable(field) ? LLVMGetInitializer(field) : NULL;
   if (!value || !LLVMIsAConstantInt(value))
      return false;
   *location = (unsigned)LLVMConstIntGetZExtValue(value);
   return true;
}

/* Whether fn calls an imageblock function, which its imageblock's
 * reflection reports as using it: an implicit imageblock's calls name the
 * attachments, not the argument. */
static bool
calls_imageblock(LLVMValueRef fn)
{
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = LLVMIsACallInst(inst) ? LLVMGetCalledValue(inst) : NULL;
         size_t bytes = 0;
         const char *name =
            callee && LLVMIsAFunction(callee) ? LLVMGetValueName2(callee, &bytes) : NULL;
         if (name && bytes > 4 && !strncmp(name, "air.", 4) && strstr(name, "imageblock"))
            return true;
      }
   }
   return false;
}

static bool
metadata_arguments(struct stela_air_metadata *t, LLVMValueRef fn, LLVMValueRef args_node,
                   struct stela_air_kernel *kernel, struct stela_air_render *render)
{
   unsigned argc = LLVMCountParams(fn);
   if (argc > AIR_MAX_ARGUMENTS)
      return fail(t, STELA_AIR_LIMIT, "AIR argument budget exceeded");
   LLVMValueRef args[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(t, args_node, args, &count) || count != argc)
      return fail(t, STELA_AIR_METADATA, "AIR argument descriptors do not match parameters");
   bool used[AIR_MAX_ARGUMENTS] = {false};
   bool buffer_indices[AIR_MAX_ARGUMENTS] = {false};
   bool shared_indices[AIR_MAX_ARGUMENTS] = {false};
   bool texture_indices[AIR_MAX_TEXTURES] = {false};
   bool sampler_indices[AIR_MAX_SAMPLERS] = {false};
   bool builtins[STELA_AIR_BUILTIN_COUNT] = {false};
   bool attribute_locations[AIR_MAX_VERTEX_ATTRIBUTES] = {false};
   bool object = render && render->entry.stage == STELA_AIR_OBJECT;
   bool mesh_stage = render && render->entry.stage == STELA_AIR_MESH;
   bool compute = !render || object || mesh_stage;
   bool patch = render && render->entry.patch;
   bool payloads = false, meshes = false, grids = false, positions_in_patch = false;
   kernel->field_count = 0;
   kernel->imageblock_size = 0;
   kernel->implicit_imageblock = false;
   for (unsigned a = 0; a < argc; a++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count, index;
      if (!stela_air_md_node(t, args[a], fields, &fields_count) || fields_count < 2 ||
          !stela_air_md_uint(fields[0], &index) || index >= argc || used[index])
         return fail(t, STELA_AIR_METADATA, "invalid/duplicate argument index");
      used[index] = true;
      /* A [[function_constant]] argument's kind follows its predicate. Only
       * arguments known to exist claim their indices: one a false constant
       * leaves absent shares them with those that replace it. */
      bool known = true, absent = false;
      if (stela_air_md_string(fields[1], "air.function_constant")) {
         if (fields_count < 4)
            return fail(t, STELA_AIR_METADATA, "invalid function constant argument predicate");
         if (!argument_predicate(t, fields[2], &known, &absent))
            return false;
         memmove(&fields[1], &fields[3], (fields_count - 3) * sizeof(*fields));
         fields_count -= 2;
      }
      /* An argument its predicate may yet leave out reads nothing. */
      bool claims = known && !absent;
      bool conditional = !known;
      absent = !claims;
      LLVMValueRef param = LLVMGetParam(fn, index);
      unsigned attributes_count = LLVMGetAttributeCountAtIndex(fn, index + 1);
      if (attributes_count > AIR_MAX_METADATA_OPERANDS)
         return fail(t, STELA_AIR_LIMIT, "argument attribute budget exceeded");
      LLVMAttributeRef attributes[AIR_MAX_METADATA_OPERANDS];
      LLVMGetAttributesAtIndex(fn, index + 1, attributes);
      const char *abi_attributes[] = {"sret", "byval", "byref", "inalloca",
         "preallocated", "nest", "swiftself", "swifterror", "elementtype"};
      /* Texture and sampler arrays are passed by value. */
      LLVMTypeRef byval = NULL;
      for (unsigned attribute = 0; attribute < attributes_count; attribute++) {
         if (LLVMIsTypeAttribute(attributes[attribute])) {
            if (byval || LLVMGetEnumAttributeKind(attributes[attribute]) !=
                            LLVMGetEnumAttributeKindForName("byval", strlen("byval")))
               return fail(t, STELA_AIR_ARGUMENT, "unsupported typed parameter attribute");
            byval = LLVMGetTypeAttributeValue(attributes[attribute]);
            continue;
         }
         if (!LLVMIsEnumAttribute(attributes[attribute]))
            continue;
         unsigned kind = LLVMGetEnumAttributeKind(attributes[attribute]);
         for (unsigned k = 0; k < ARRAY_SIZE(abi_attributes); k++) {
            if (kind == LLVMGetEnumAttributeKindForName(abi_attributes[k], strlen(abi_attributes[k])))
               return fail(t, STELA_AIR_ARGUMENT, "unsupported parameter ABI attribute: %s", abi_attributes[k]);
         }
      }
      bool indirect = stela_air_md_string(fields[1], "air.indirect_buffer");
      bool table = stela_air_md_string(fields[1], "air.visible_function_table");
      bool buffer = indirect || table || stela_air_md_string(fields[1], "air.buffer");
      unsigned lanes = 0;
      enum stela_air_builtin builtin = builtin_input(fields[1], render, &lanes);
      bool position = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                      stela_air_md_string(fields[1], "air.position");
      bool varying = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                     stela_air_md_string(fields[1], "air.fragment_input");
      bool barycentric = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                         stela_air_md_string(fields[1], "air.barycentric_coord");
      /* Interpolated fragment inputs, which take sampling and interpolation
       * qualifiers. */
      bool interpolated = position || varying || barycentric;
      /* A stage-in attribute: a vertex function's, a post-tessellation
       * vertex function's per-patch one, or a kernel's. */
      bool vertex_input = render ? render->entry.stage == STELA_AIR_VERTEX &&
                                      stela_air_md_string(fields[1], patch ? "air.patch_input" :
                                                                             "air.vertex_input") :
                                   stela_air_md_string(fields[1], "air.stage_in");
      bool control_points = patch && stela_air_md_string(fields[1], "air.patch_control_point_input");
      bool in_patch = patch && stela_air_md_string(fields[1], "air.position_in_patch");
      bool texture = stela_air_md_string(fields[1], "air.texture");
      bool sampler = stela_air_md_string(fields[1], "air.sampler");
      bool payload = (object || mesh_stage) && stela_air_md_string(fields[1], "air.payload");
      bool mesh = mesh_stage && stela_air_md_string(fields[1], "air.mesh");
      bool grid = object && stela_air_md_string(fields[1], "air.mesh_grid_properties");
      /* A fragment input of a render target's color is programmable
       * blending, which reads the target in raster order. A false predicate
       * leaves it out, and until one is known it reads nothing. */
      if (render && render->entry.stage == STELA_AIR_FRAGMENT &&
          stela_air_md_string(fields[1], "air.render_target")) {
         struct stela_air_stage_io *input = &render->inputs[a];
         *input = (struct stela_air_stage_io){.argument = index, .semantic = STELA_AIR_ATTACHMENT,
                                              .absent = !claims};
         for (unsigned f = 2; f + 1 < fields_count; f++) {
            if (stela_air_md_string(fields[f], "air.arg_type_name") &&
                metadata_text(t, fields[f + 1], &input->type_name, &input->type_name_bytes))
               input->primitive = primitive_type(fields[f + 1], &input->components);
            else if (stela_air_md_string(fields[f], "air.arg_name"))
               metadata_text(t, fields[f + 1], &input->name, &input->name_bytes);
         }
         if (fields_count < 3 || !argument_location(fields[2], &input->location) ||
             input->location >= STELA_AIR_ATTACHMENTS || !input->components ||
             !stage_type_matches(LLVMTypeOf(param), input->primitive, input->components))
            return fail(t, STELA_AIR_METADATA, "invalid render target input");
         input->used = LLVMGetFirstUse(param) != NULL;
         kernel->arguments[a] = (struct stela_air_argument){
            .value = param, .used = input->used, .absent = !claims,
            .name = input->name, .name_bytes = input->name_bytes};
         continue;
      }
      /* A fragment's imageblock data: its pixel's explicit imageblock
       * struct, which the function reads in raster order. */
      if (render && render->entry.stage == STELA_AIR_FRAGMENT &&
          stela_air_md_string(fields[1], "air.imageblock_data")) {
         struct stela_air_stage_io *input = &render->inputs[a];
         *input = (struct stela_air_stage_io){.argument = index,
                                              .semantic = STELA_AIR_IMAGEBLOCK_DATA,
                                              .absent = !claims};
         if (!imageblock_data(t, fields, 2, fields_count, LLVMTypeOf(param), input,
                              &render->entry.imageblock_bytes))
            return false;
         input->used = LLVMGetFirstUse(param) != NULL;
         kernel->arguments[a] = (struct stela_air_argument){
            .value = param, .used = input->used, .absent = !claims,
            .name = input->name, .name_bytes = input->name_bytes};
         continue;
      }
      /* A kernel's imageblock, which only the imageblock functions read:
       * an explicit one's element size is all the translator needs, and an
       * implicit one's calls name the color attachments they access. */
      if (!render && stela_air_md_string(fields[1], "air.imageblock")) {
         unsigned size = 0;
         bool explicit_layout = fields_count > 2 && stela_air_md_string(fields[2], "explicit");
         bool implicit_layout = fields_count > 2 && stela_air_md_string(fields[2], "implicit");
         struct stela_air_argument block = {.value = param, .is_imageblock = true,
                                            .implicit_imageblock = implicit_layout,
                                            .absent = !claims,
                                            .used = LLVMGetFirstUse(param) != NULL ||
                                                    calls_imageblock(fn)};
         for (unsigned f = 2; f + 1 < fields_count; f++) {
            if (stela_air_md_string(fields[f], "air.imageblock_data_size") &&
                !stela_air_md_uint(fields[f + 1], &size))
               size = 0;
            else if (stela_air_md_string(fields[f], "air.arg_name"))
               metadata_text(t, fields[f + 1], &block.name, &block.name_bytes);
            else if (stela_air_md_string(fields[f], "air.arg_type_name"))
               metadata_text(t, fields[f + 1], &block.type_name, &block.type_name_bytes);
         }
         if ((!explicit_layout || !size) && !implicit_layout)
            return fail(t, STELA_AIR_ARGUMENT, "a kernel's imageblock of an unknown layout");
         /* One of each layout, as Metal allows. */
         if (implicit_layout ? kernel->implicit_imageblock : kernel->imageblock_size != 0)
            return fail(t, STELA_AIR_ARGUMENT, "a kernel takes one %s imageblock",
                        implicit_layout ? "implicit" : "explicit");
         if (claims && implicit_layout)
            kernel->implicit_imageblock = true;
         else if (claims)
            kernel->imageblock_size = size;
         kernel->arguments[a] = block;
         continue;
      }
      if (!buffer && !builtin && !interpolated && !vertex_input && !texture && !sampler &&
          !payload && !mesh && !grid && !control_points && !in_patch) {
         unsigned length;
         const char *kind = md_text(fields[1], &length);
         return fail(t, STELA_AIR_ARGUMENT, "unsupported AIR argument kind %.*s at %u",
                     (int)length, kind, index);
      }
      if (byval && !texture && !sampler)
         return fail(t, STELA_AIR_ARGUMENT, "unsupported typed parameter attribute");
      if (claims && builtin && builtins[builtin])
         return fail(t, STELA_AIR_METADATA, "duplicate builtin argument");
      builtins[builtin] |= claims;
      struct stela_air_buffer desc = {.argument = index, .function_table = table};
      struct stela_air_texture texture_desc = {.argument = index};
      struct stela_air_sampler sampler_desc = {.argument = index};
      bool has_access = false;
      struct stela_air_stage_io *io = render ? &render->inputs[a] : NULL;
      if (io) {
         *io = (struct stela_air_stage_io){.argument = index,
            .semantic = buffer ? STELA_AIR_STAGE_BUFFER : builtin ? STELA_AIR_STAGE_BUILTIN :
                        position ? STELA_AIR_POSITION : texture ? STELA_AIR_STAGE_TEXTURE :
                        vertex_input ? STELA_AIR_VERTEX_INPUT :
                        sampler ? STELA_AIR_STAGE_SAMPLER : payload ? STELA_AIR_PAYLOAD :
                        mesh ? STELA_AIR_MESH_OUTPUT : grid ? STELA_AIR_MESH_GRID :
                        control_points ? STELA_AIR_CONTROL_POINTS :
                        in_patch ? STELA_AIR_POSITION_IN_PATCH :
                        barycentric ? STELA_AIR_BARYCENTRIC : STELA_AIR_VARYING};
      }
      unsigned first_field = 2;
      if (varying) {
         if (fields_count < 3 || !metadata_text(t, fields[2], &io->identifier, &io->identifier_bytes))
            return fail(t, STELA_AIR_METADATA, "missing fragment linkage identifier");
         first_field++;
      }
      if (mesh) {
         if (fields_count < 3 || meshes || !mesh_outputs(t, render, fields[2]))
            return fail(t, STELA_AIR_METADATA, "invalid/duplicate mesh argument");
         meshes = true;
         first_field++;
      }
      if (control_points) {
         if (!control_point_input(t, render, io, param, fields, fields_count, attribute_locations))
            return false;
         first_field = fields_count;
      }
      bool unused = false, grouped = false;
      LLVMValueRef struct_info = NULL;
      bool has_location = false, has_as = false, has_size = false, has_align = false;
      bool has_name = false, has_type_name = false, has_buffer_size = false;
      unsigned buffer_size = 0;
      struct stela_air_fields argument_buffer = {0};
      enum stela_air_primitive primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
      unsigned type_components = 0, location = 0, locations = 0;
      const char *name = NULL, *type_name = NULL;
      unsigned name_bytes = 0, type_name_bytes = 0;
      for (unsigned f = first_field; f < fields_count;) {
         LLVMValueRef key = fields[f++];
         if (texture && (stela_air_md_string(key, "air.sample") || stela_air_md_string(key, "air.read") ||
                         stela_air_md_string(key, "air.write") || stela_air_md_string(key, "air.read_write"))) {
            if (has_access)
               return fail(t, STELA_AIR_METADATA, "duplicate texture access");
            texture_desc.access = stela_air_md_string(key, "air.sample") ? STELA_AIR_TEXTURE_SAMPLE :
                                  stela_air_md_string(key, "air.read") ? STELA_AIR_TEXTURE_READ :
                                  stela_air_md_string(key, "air.write") ? STELA_AIR_TEXTURE_WRITE :
                                  STELA_AIR_TEXTURE_READ_WRITE;
            has_access = true;
         } else if ((texture || sampler || vertex_input) && stela_air_md_string(key, "air.location_index")) {
            unsigned *slot = texture ? &texture_desc.index : sampler ? &sampler_desc.index : &location;
            if (has_location || f + 2 > fields_count || !argument_location(fields[f], slot) ||
                !stela_air_md_uint(fields[f + 1], &locations) || !locations)
               return fail(t, STELA_AIR_METADATA, "invalid/duplicate resource or attribute location");
            if (vertex_input && locations != 1)
               return fail(t, STELA_AIR_ARGUMENT, "attribute arrays are unsupported");
            has_location = true;
            f += 2;
         } else if (stela_air_md_string(key, "air.read") || stela_air_md_string(key, "air.write") ||
             stela_air_md_string(key, "air.read_write")) {
            if (!buffer || desc.access)
               return fail(t, STELA_AIR_METADATA, "duplicate/inapplicable buffer access");
            desc.access = stela_air_md_string(key, "air.read") ? STELA_AIR_READ :
                          stela_air_md_string(key, "air.write") ? STELA_AIR_WRITE : STELA_AIR_READ_WRITE;
         } else if (stela_air_md_string(key, "air.location_index")) {
            /* A buffer array's count may be an expression of function
             * constants, as its location may. */
            if (!buffer || has_location || f + 2 > fields_count ||
                !argument_location(fields[f], &desc.index) || !argument_location(fields[f + 1], &locations) ||
                desc.index >= AIR_MAX_ARGUMENTS)
               return fail(t, STELA_AIR_METADATA, "unsupported/duplicate buffer location");
            has_location = true;
            f += 2;
         } else if (stela_air_md_string(key, "air.address_space")) {
            if (!buffer || has_as || f == fields_count || !stela_air_md_uint(fields[f++], &desc.address_space))
               return fail(t, STELA_AIR_METADATA, "invalid buffer address space");
            has_as = true;
         } else if (stela_air_md_string(key, "air.arg_type_size") || stela_air_md_string(key, "air.arg_type_align_size")) {
            bool alignment = stela_air_md_string(key, "air.arg_type_align_size");
            bool *present = alignment ? &has_align : &has_size;
            unsigned *number = alignment ? &desc.type_alignment : &desc.type_size;
            if (!(buffer || payload) || *present || f == fields_count || !stela_air_md_uint(fields[f++], number) ||
                (alignment && (!*number || (*number & (*number - 1)))))
               return fail(t, STELA_AIR_METADATA, "invalid argument size/alignment");
            *present = true;
         } else if (stela_air_md_string(key, "air.arg_name") || stela_air_md_string(key, "air.arg_type_name")) {
            bool *present = stela_air_md_string(key, "air.arg_name") ? &has_name : &has_type_name;
            if (*present || f == fields_count || !fields[f] || !LLVMIsAMDString(fields[f]))
               return fail(t, STELA_AIR_METADATA, "invalid argument reflection string");
            if (present == &has_type_name) {
               primitive = primitive_type(fields[f], &type_components);
               type_name = LLVMGetMDString(fields[f], &type_name_bytes);
            } else {
               name = LLVMGetMDString(fields[f], &name_bytes);
            }
            f++;
            *present = true;
         } else if (buffer && stela_air_md_string(key, "air.buffer_size")) {
            /* A reference's referenced bytes. */
            if (has_buffer_size || f == fields_count || !stela_air_md_uint(fields[f++], &buffer_size))
               return fail(t, STELA_AIR_METADATA, "invalid buffer size");
            has_buffer_size = true;
         } else if ((buffer || payload) && stela_air_md_string(key, "air.struct_type_info")) {
            /* The layout of a structure; only an argument buffer's is
             * interpreted, since its fields are bound resources. */
            if (struct_info || f == fields_count)
               return fail(t, STELA_AIR_METADATA, "invalid structure reflection");
            struct_info = fields[f++];
         } else if (io && interpolated &&
                    (stela_air_md_string(key, "air.center") || stela_air_md_string(key, "air.centroid") ||
                     stela_air_md_string(key, "air.sample"))) {
            if (io->sampling) return fail(t, STELA_AIR_METADATA, "duplicate sampling qualifier");
            io->sampling = stela_air_md_string(key, "air.center") ? STELA_AIR_CENTER :
                           stela_air_md_string(key, "air.centroid") ? STELA_AIR_CENTROID : STELA_AIR_SAMPLE;
         } else if (io && interpolated &&
                    (stela_air_md_string(key, "air.perspective") || stela_air_md_string(key, "air.no_perspective") ||
                     stela_air_md_string(key, "air.flat"))) {
            if (io->interpolation) return fail(t, STELA_AIR_METADATA, "duplicate interpolation qualifier");
            io->interpolation = stela_air_md_string(key, "air.perspective") ? STELA_AIR_PERSPECTIVE :
                                stela_air_md_string(key, "air.no_perspective") ? STELA_AIR_NO_PERSPECTIVE :
                                STELA_AIR_FLAT;
         } else if (stela_air_md_string(key, "air.arg_unused")) {
            if (unused) return fail(t, STELA_AIR_METADATA, "duplicate unused qualifier");
            unused = true;
         } else if (varying && stela_air_md_string(key, "air.interpolation_function")) {
            if (io->interpolant) return fail(t, STELA_AIR_METADATA, "duplicate interpolant qualifier");
            io->interpolant = true;
         } else if (builtin == STELA_AIR_SAMPLE_MASK_IN &&
                    stela_air_md_string(key, "air.post_depth_coverage")) {
            render->entry.post_depth_coverage = true;
         } else if ((buffer || texture) && stela_air_md_string(key, "air.raster_order_group")) {
            /* Every group shares one order, which also orders each group. */
            unsigned group;
            if (grouped || f == fields_count || !stela_air_md_uint(fields[f++], &group))
               return fail(t, STELA_AIR_METADATA, "invalid/duplicate raster order group");
            if (!render || render->entry.stage != STELA_AIR_FRAGMENT)
               return fail(t, STELA_AIR_ARGUMENT, "raster order groups exist only in fragment functions");
            grouped = true;
            render->entry.raster_ordered |= claims;
         } else if (!tool_generated(key)) {
            unsigned length;
            const char *text = md_text(key, &length);
            return fail(t, STELA_AIR_METADATA, "unsupported argument metadata %.*s at %u",
                        (int)length, text, index);
         }
      }
      unsigned components = 0;
      if (texture || sampler) {
         LLVMTypeRef type = LLVMTypeOf(param);
         unsigned space = texture ? 1 : 2;
         /* An array<element, n> argument points to its n handles, in n
          * consecutive locations. */
         const char *element = type_name;
         unsigned element_bytes = type_name_bytes;
         bool array = has_type_name && array_type(&element, &element_bytes, locations);
         LLVMTypeRef handles = LLVMArrayType2(
            LLVMPointerTypeInContext(LLVMGetTypeContext(type), space), locations);
         if (!has_location || !has_type_name || LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             (array ? LLVMGetPointerAddressSpace(type) != 0 || byval != handles :
                      LLVMGetPointerAddressSpace(type) != space || byval || locations != 1))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported texture or sampler %u", index);
         if (texture && (!has_access || !texture_type(element, element_bytes, &texture_desc)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported texture type at %u", index);
         if (sampler && (element_bytes != strlen("sampler") || memcmp(element, "sampler", element_bytes)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported sampler type at %u", index);
         unsigned *slot = texture ? &texture_desc.index : &sampler_desc.index;
         unsigned slots = texture ? AIR_MAX_TEXTURES : AIR_MAX_SAMPLERS;
         bool *indices = texture ? texture_indices : sampler_indices;
         bool in_range = *slot < slots && locations <= slots - *slot;
         if (claims) {
            if (!in_range)
               return fail(t, STELA_AIR_METADATA, "duplicate or out-of-range texture or sampler location");
            for (unsigned i = *slot; i < *slot + locations; i++) {
               if (indices[i])
                  return fail(t, STELA_AIR_METADATA, "duplicate or out-of-range texture or sampler location");
               indices[i] = true;
            }
         } else if (!in_range) {
            /* An absent argument's location expression may name no slot,
             * as one its constructors leave at -1; a read that folding
             * leaves is refused where it binds. */
            *slot = slots;
         }
         *(texture ? &texture_desc.length : &sampler_desc.length) = array ? locations : 0;
         primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
         type_components = 0;
      } else if (buffer) {
         LLVMTypeRef type = LLVMTypeOf(param);
         /* A visible function table is device memory its type implies, and
          * before Metal 3.0 every buffer's type says. */
         if (!has_as && LLVMGetTypeKind(type) == LLVMPointerTypeKind) {
            desc.address_space = LLVMGetPointerAddressSpace(type);
            has_as = true;
         }
         /* A buffer array, metal::array_ref<device T *>, is a thread
          * pointer to the addresses of its buffers, which its count of
          * locations bind; its count may be zero until specialization
          * constructs it. */
         static const char array_ref[] = "array_ref<";
         desc.array = has_type_name && type_name_bytes > strlen(array_ref) &&
                      !memcmp(type_name, array_ref, strlen(array_ref));
         desc.length = desc.array ? locations : 0;
         unsigned param_space = desc.array ? 0 : desc.address_space;
         if (!desc.array && locations != 1)
            return fail(t, STELA_AIR_METADATA, "buffer %u binds %u locations", index, locations);
         /* Device and constant buffers share the buffer indices; render
          * functions have no threadgroup memory, and constant is read-only. */
         if (!has_location || !has_as || !desc.access || desc.address_space < 1 ||
             desc.address_space > (desc.array ? 2 : compute ? 3 : 2) ||
             (desc.address_space == 2 && desc.access != STELA_AIR_READ) ||
             (desc.array && (indirect || !compute)) ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != param_space)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported buffer %u", index);
         bool shared = desc.address_space == 3;
         bool *indices = shared ? shared_indices : buffer_indices;
         unsigned limit = shared ? t->max_threadgroup_buffers :
                          desc.address_space == 2 ? t->max_constant_buffers : t->max_device_buffers;
         unsigned slots = desc.array ? desc.length : 1;
         if ((limit && (desc.index >= limit || slots > limit - desc.index)) ||
             slots > AIR_MAX_ARGUMENTS - desc.index)
            return fail(t, STELA_AIR_METADATA, "duplicate buffer or location exceeds AIR module limit");
         for (unsigned slot = desc.index; slot < desc.index + slots; slot++) {
            if (claims && indices[slot])
               return fail(t, STELA_AIR_METADATA, "duplicate buffer or location exceeds AIR module limit");
            indices[slot] |= claims;
         }
         /* Its loads of addresses read the one field its addresses are. */
         if (desc.array && desc.length) {
            if (kernel->field_count == AIR_MAX_FIELDS)
               return fail(t, STELA_AIR_LIMIT, "argument buffer field budget exceeded");
            struct stela_air_buffer element = desc;
            element.array = false;
            element.length = 0;
            kernel->fields[kernel->field_count] = (struct stela_air_field){
               .kind = STELA_AIR_FIELD_BUFFER, .offset = 0, .size = 8 * desc.length,
               .count = desc.length, .buffer = element};
            argument_buffer = (struct stela_air_fields){kernel->field_count, 1, 8 * desc.length};
            kernel->field_count++;
         }
         /* An array by reference is typed by its element. */
         if (has_buffer_size && desc.type_size && buffer_size % desc.type_size)
            return fail(t, STELA_AIR_ARGUMENT, "buffer %u of %u bytes is no count of %u byte types",
                        index, buffer_size, desc.type_size);
         if (indirect && (shared || !struct_info || !desc.type_size))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported argument buffer %u", index);
         if (indirect && !argument_fields(t, kernel, struct_info, desc.type_size, index, 0,
                                          &argument_buffer))
            return false;
         /* A threadgroup void * declares neither size nor alignment: its
          * bytes are only the length its dispatches set, placed as any
          * threadgroup buffer is, and its accesses aligned as LLVM says, as
          * a device void *'s are. A typed one declares both. */
         if (shared && (has_size != has_align || (has_size && !desc.type_size)))
            return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound threadgroup buffer %u", index);
      } else if (payload) {
         /* An object function writes its payload; its mesh functions read it. */
         LLVMTypeRef type = LLVMTypeOf(param);
         if (payloads || !has_size || !has_align || !desc.type_size ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind || LLVMGetPointerAddressSpace(type) != 6)
            return fail(t, STELA_AIR_ARGUMENT, "invalid/duplicate object payload %u", index);
         payloads = true;
         desc.address_space = 6;
         desc.access = object ? STELA_AIR_READ_WRITE : STELA_AIR_READ;
         primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
         type_components = 0;
      } else if (mesh || grid) {
         LLVMTypeRef type = LLVMTypeOf(param);
         if ((grid && grids) || LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != (mesh ? 7u : 3u))
            return fail(t, STELA_AIR_ARGUMENT, "invalid/duplicate mesh or mesh grid argument %u", index);
         grids |= grid;
         primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
         type_components = 0;
      } else if (position || varying) {
         bool flat = io->interpolation == STELA_AIR_FLAT;
         bool real = primitive == STELA_AIR_FLOAT || primitive == STELA_AIR_HALF;
         LLVMTypeRef type = LLVMTypeOf(param);
         /* An interpolant is sampled where each call says, never flat. */
         bool typed = io->interpolant ?
            real && !flat && io->sampling == STELA_AIR_SAMPLING_NONE &&
               LLVMGetTypeKind(type) == LLVMPointerTypeKind && LLVMGetPointerAddressSpace(type) == 1 :
            flat == (io->sampling == STELA_AIR_SAMPLING_NONE) &&
               stage_type_matches(type, primitive, type_components);
         if (!io->interpolation || !typed || !stage_varying(primitive) || (!real && !flat) ||
             (position && (primitive != STELA_AIR_FLOAT || type_components != 4 ||
                           io->sampling != STELA_AIR_CENTER ||
                           io->interpolation != STELA_AIR_NO_PERSPECTIVE)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported fragment input type/interpolation");
         components = type_components;
      } else if (barycentric) {
         if (!io->sampling || (io->interpolation != STELA_AIR_PERSPECTIVE &&
                               io->interpolation != STELA_AIR_NO_PERSPECTIVE) ||
             primitive != STELA_AIR_FLOAT || type_components > 3 ||
             !stage_type_matches(LLVMTypeOf(param), primitive, type_components))
            return fail(t, STELA_AIR_ARGUMENT, "barycentric coordinates are interpolated float1 to float3");
         components = type_components;
      } else if (vertex_input) {
         if (!has_location || location >= AIR_MAX_VERTEX_ATTRIBUTES ||
             (claims && attribute_locations[location]) || !stage_varying(primitive) ||
             !stage_type_matches(LLVMTypeOf(param), primitive, type_components))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported/duplicate stage-in attribute at %u", index);
         attribute_locations[location] |= claims;
         components = type_components;
      } else if (in_patch) {
         unsigned lanes = render->entry.patch == STELA_AIR_PATCH_QUAD ? 2 : 3;
         if (positions_in_patch || primitive != STELA_AIR_FLOAT || type_components != lanes ||
             !stage_type_matches(LLVMTypeOf(param), primitive, type_components))
            return fail(t, STELA_AIR_ARGUMENT, "position_in_patch must be one float%u", lanes);
         positions_in_patch = true;
         components = type_components;
      } else if (!control_points) {
         /* A scalar, or a vector of two lanes or more. */
         LLVMTypeRef type = LLVMTypeOf(param);
         bool vector = LLVMGetTypeKind(type) == LLVMVectorTypeKind;
         components = vector ? LLVMGetVectorSize(type) : 1;
         type = vector ? LLVMGetElementType(type) : type;
         unsigned width = LLVMGetTypeKind(type) == LLVMIntegerTypeKind ? LLVMGetIntTypeWidth(type) : 0;
         bool typed = builtin == STELA_AIR_FRONT_FACING ? width == 1 :
                      builtin == STELA_AIR_POINT_COORD ? LLVMGetTypeKind(type) == LLVMFloatTypeKind :
                      width == 16 || width == 32;
         if (components > lanes || (vector && components < 2) || !typed)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported builtin type at %u", index);
      }
      if (io) {
         io->buffer = desc; io->primitive = primitive; io->argument_buffer = indirect;
         io->location = location;
         io->components = builtin ? components : type_components;
         io->texture = texture_desc; io->sampler = sampler_desc; io->builtin = builtin;
         io->name = name; io->name_bytes = name_bytes;
         io->type_name = type_name; io->type_name_bytes = type_name_bytes;
         io->used = LLVMGetFirstUse(param) != NULL;
         io->absent = absent;
         io->conditional = conditional;
         io->layout = (const struct stela_air_layout *)struct_info;
         if (unused && io->used)
            return fail(t, STELA_AIR_METADATA, "used stage argument marked unused");
      }
      kernel->arguments[a] = (struct stela_air_argument) {
         .value = param, .layout = struct_info, .buffer = desc, .is_buffer = buffer,
         .components = components,
         .is_argument_buffer = indirect, .fields = argument_buffer,
         .is_payload = payload, .is_mesh = mesh, .is_mesh_grid = grid,
         .is_stage_in = vertex_input, .location = location,
         .texture = texture_desc, .sampler = sampler_desc, .is_texture = texture, .is_sampler = sampler,
         .builtin = builtin,
         .plain_buffer_type = primitive != STELA_AIR_PRIMITIVE_UNKNOWN,
         .name = name, .name_bytes = name_bytes, .type_name = type_name, .type_name_bytes = type_name_bytes,
         .primitive = primitive, .type_components = type_components, .used = LLVMGetFirstUse(param) != NULL,
         .absent = absent, .conditional = conditional,
      };
   }
   kernel->count = argc;
   return true;
}

/* An entry descriptor's fields past its outputs and inputs: a kernel's,
 * object or mesh function's air.max_work_group_size, which *max_threads
 * receives, and an object function's air.max_mesh_work_groups. Stage zero
 * is a kernel. */
static bool
entry_limits(struct stela_air_metadata *m, LLVMValueRef node, enum stela_air_stage stage,
             unsigned *max_threads, unsigned *max_mesh_threadgroups)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned n;
   if (!stela_air_md_node(m, node, fields, &n))
      return false;
   *max_threads = 0;
   if (max_mesh_threadgroups)
      *max_mesh_threadgroups = 0;
   for (unsigned i = 3; i < n; i++) {
      LLVMValueRef pair[AIR_MAX_METADATA_OPERANDS];
      unsigned count, value;
      if (!stela_air_md_node(m, fields[i], pair, &count) || count != 2 ||
          !stela_air_md_uint(pair[1], &value) || !value)
         return fail(m, STELA_AIR_METADATA, "unsupported entry descriptor field");
      unsigned *limit = stela_air_md_string(pair[0], "air.max_work_group_size") ? max_threads :
                        stage == STELA_AIR_OBJECT &&
                        stela_air_md_string(pair[0], "air.max_mesh_work_groups") ?
                           max_mesh_threadgroups : NULL;
      if (!limit || *limit)
         return fail(m, STELA_AIR_METADATA, "unsupported/duplicate entry descriptor field");
      *limit = value;
   }
   return true;
}

/* A fragment entry descriptor's field past its outputs and inputs:
 * "early_fragment_tests". */
static bool
entry_fragment(struct stela_air_metadata *m, LLVMValueRef node, struct stela_air_stage_entry *entry)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned n;
   if (!stela_air_md_node(m, node, fields, &n))
      return false;
   if (n == 3)
      return true;
   if (n != 4 || !stela_air_md_string(fields[3], "early_fragment_tests"))
      return fail(m, STELA_AIR_METADATA, "unsupported fragment entry descriptor field");
   entry->early_fragment_tests = true;
   return true;
}

/* A vertex entry descriptor's field past its outputs and inputs: a
 * post-tessellation function's {"air.patch", "triangle" or "quad"
 * [, "air.patch_control_point", i32 count]}. */
static bool
entry_patch(struct stela_air_metadata *m, LLVMValueRef node, struct stela_air_stage_entry *entry)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS], patch[AIR_MAX_METADATA_OPERANDS];
   unsigned n, count;
   if (!stela_air_md_node(m, node, fields, &n))
      return false;
   if (n == 3)
      return true;
   if (n != 4 || !stela_air_md_node(m, fields[3], patch, &count) || (count != 2 && count != 4) ||
       !stela_air_md_string(patch[0], "air.patch"))
      return fail(m, STELA_AIR_METADATA, "unsupported vertex entry descriptor field");
   entry->patch = stela_air_md_string(patch[1], "triangle") ? STELA_AIR_PATCH_TRIANGLE :
                  stela_air_md_string(patch[1], "quad") ? STELA_AIR_PATCH_QUAD : STELA_AIR_PATCH_NONE;
   if (!entry->patch ||
       (count == 4 && (!stela_air_md_string(patch[2], "air.patch_control_point") ||
                       !stela_air_md_uint(patch[3], &entry->patch_control_points) ||
                       !entry->patch_control_points ||
                       entry->patch_control_points > AIR_MAX_PATCH_CONTROL_POINTS)))
      return fail(m, STELA_AIR_METADATA, "unsupported patch type or control point count");
   return true;
}

bool
stela_air_metadata_kernel(struct stela_air_metadata *t, LLVMValueRef fn,
                           struct stela_air_kernel *kernel)
{
   if (!fn || LLVMIsDeclaration(fn) || LLVMGetFunctionCallConv(fn) != LLVMCCallConv ||
       LLVMGetTypeKind(LLVMGetReturnType(LLVMGlobalGetValueType(fn))) != LLVMVoidTypeKind ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn)))
      return fail(t, STELA_AIR_ARGUMENT, "entry must be a defined nonvariadic void C-convention kernel");
   LLVMValueRef kernels[AIR_MAX_METADATA_OPERANDS], args_node = NULL, selected = NULL;
   unsigned kernel_count;
   if (!stela_air_named_md(t, "air.kernel", kernels, &kernel_count))
      return false;
   for (unsigned i = 0; i < kernel_count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_md_node(t, kernels[i], fields, &count) || count < 3)
         return fail(t, STELA_AIR_METADATA, "invalid air.kernel descriptor");
      if (fields[0] == fn) {
         LLVMValueRef outputs[AIR_MAX_METADATA_OPERANDS];
         unsigned output_count;
         if (args_node || !stela_air_md_node(t, fields[1], outputs, &output_count) || output_count)
            return fail(t, STELA_AIR_METADATA, "duplicate kernel or nonempty compute outputs");
         args_node = fields[2];
         selected = kernels[i];
      }
   }
   if (!args_node)
      return fail(t, STELA_AIR_METADATA, "entry is not an AIR compute kernel");
   return metadata_arguments(t, fn, args_node, kernel, NULL) &&
          entry_limits(t, selected, 0, &kernel->max_threads, NULL);
}

bool
stela_air_metadata_stage(struct stela_air_metadata *m, LLVMValueRef fn,
                         enum stela_air_stage stage, struct stela_air_render *r)
{
   bool compute = stage == STELA_AIR_OBJECT || stage == STELA_AIR_MESH;
   if (!m->render || (stage != STELA_AIR_VERTEX && stage != STELA_AIR_FRAGMENT && !compute) ||
       !fn || !LLVMIsAFunction(fn) || LLVMIsDeclaration(fn) ||
       LLVMGetFunctionCallConv(fn) != LLVMCCallConv || LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn)))
      return fail(m, STELA_AIR_ARGUMENT, "invalid render entry/stage ABI");
   if (!stela_air_metadata_shared_profile(m)) return false;
   if (LLVMPointerSizeForAS(m->layout, 2) != 8)
      return fail(m, STELA_AIR_TARGET, "render constant pointers require 64-bit layout");
   bool threadgroup;
   if (!stela_air_metadata_globals(m, &threadgroup))
      return false;
   /* A kernel of the same module may have threadgroup memory. */
   if (threadgroup && !compute && uses_threadgroup(m, fn))
      return fail(m, STELA_AIR_TARGET, "render functions have no threadgroup memory");
   *r = (struct stela_air_render){0};
   r->entry.stage = stage;
   r->entry.framebuffer_fetch_present = m->framebuffer_fetch_present;
   r->entry.framebuffer_fetch_enabled = m->framebuffer_fetch_enabled;
   r->entry.name = LLVMGetValueName2(fn, &r->entry.name_bytes);
   if (!stage_text(r->entry.name, r->entry.name_bytes))
      return fail(m, STELA_AIR_METADATA, "invalid render entry name");
   LLVMValueRef args = NULL, outputs = NULL, selected = NULL;
   /* In enum stela_air_stage order. */
   const char *lists[] = {"air.vertex", "air.fragment", "air.object", "air.mesh", "air.kernel"};
   for (unsigned list = 0; list < ARRAY_SIZE(lists); list++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_named_md(m, lists[list], nodes, &count)) return false;
      for (unsigned i = 0; i < count; i++) {
         LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
         unsigned fields_count;
         if (!stela_air_md_node(m, nodes[i], fields, &fields_count) || fields_count < 3 ||
             !fields[0] || !LLVMIsAFunction(fields[0]))
            return fail(m, STELA_AIR_METADATA, "invalid stage manifest descriptor");
         if (fields[0] != fn) continue;
         if (args || list + 1 != (unsigned)stage)
            return fail(m, STELA_AIR_METADATA, "duplicate or mismatched selected render stage");
         outputs = fields[1]; args = fields[2]; selected = nodes[i];
      }
   }
   if (!args ||
       !(stage == STELA_AIR_VERTEX ? entry_patch(m, selected, &r->entry) :
         stage == STELA_AIR_FRAGMENT ? entry_fragment(m, selected, &r->entry) :
         entry_limits(m, selected, stage, &r->entry.max_threads, &r->entry.max_mesh_threadgroups)) ||
       !metadata_arguments(m, fn, args, &r->arguments, r))
      return fail(m, STELA_AIR_METADATA, "selected entry is not a supported render stage");
   r->entry.input_count = r->arguments.count;
   r->entry.inputs = r->inputs; r->entry.outputs = r->outputs;
   entry_facts(m, fn, &r->entry.threadgroup_bytes, &r->entry.discards);
   for (unsigned i = 0; i < r->entry.input_count; i++) {
      struct stela_air_stage_io *io = &r->inputs[i];
      /* Control points name their members instead. */
      if (io->semantic != STELA_AIR_CONTROL_POINTS &&
          (!stage_text(io->name, io->name_bytes) || !stage_text(io->type_name, io->type_name_bytes)))
         return fail(m, STELA_AIR_METADATA, "missing/invalid stage argument name/type");
      if (io->semantic == STELA_AIR_VARYING) {
         for (unsigned j = 0; j < i; j++) {
            if (r->inputs[j].semantic == STELA_AIR_VARYING &&
                io->identifier_bytes == r->inputs[j].identifier_bytes &&
                !memcmp(io->identifier, r->inputs[j].identifier, io->identifier_bytes))
               return fail(m, STELA_AIR_METADATA, "duplicate fragment linkage identifier");
         }
      }
   }
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (compute) {
      /* A mesh function's outputs are its mesh argument's. */
      if (LLVMGetTypeKind(LLVMGetReturnType(LLVMGlobalGetValueType(fn))) != LLVMVoidTypeKind ||
          !stela_air_md_node(m, outputs, nodes, &count) || count)
         return fail(m, STELA_AIR_TYPE, "object and mesh functions return nothing");
      return stage == STELA_AIR_OBJECT || r->entry.output_count ||
         fail(m, STELA_AIR_METADATA, "mesh function lacks its mesh");
   }
   /* A void function has no outputs: a fragment function that only has
    * side effects, or a vertex function rasterization is disabled for. */
   LLVMTypeRef result = LLVMGetReturnType(LLVMGlobalGetValueType(fn));
   bool none = LLVMGetTypeKind(result) == LLVMVoidTypeKind;
   if (!stela_air_md_node(m, outputs, nodes, &count) || (!count && !none) ||
       count > AIR_MAX_ARGUMENTS)
      return fail(m, STELA_AIR_LIMIT, "render output budget/shape exceeded");
   if (none) {
      if (count)
         return fail(m, STELA_AIR_TYPE, "render return/output count mismatch");
      r->entry.output_count = 0;
      return true;
   }
   bool aggregate = LLVMGetTypeKind(result) == LLVMStructTypeKind;
   if (aggregate && (LLVMIsOpaqueStruct(result) || !LLVMIsPackedStruct(result) ||
                     LLVMCountStructElementTypes(result) != count))
      return fail(m, STELA_AIR_TYPE, "render return must match ordered packed output leaves");
   if (!aggregate && count != 1)
      return fail(m, STELA_AIR_TYPE, "render return/output count mismatch");
   unsigned positions = 0;
   for (unsigned i = 0; i < count; i++) {
      struct stela_air_stage_io *io = &r->outputs[i];
      io->argument = i;
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned n;
      if (!stela_air_md_node(m, nodes[i], fields, &n) || n < 3)
         return fail(m, STELA_AIR_METADATA, "invalid stage output descriptor");
      if (stela_air_md_string(fields[0], "air.function_constant")) {
         bool known;
         if (n < 5 || !argument_predicate(m, fields[1], &known, &io->absent))
            return fail(m, STELA_AIR_METADATA, "invalid function constant output predicate");
         io->absent |= !known;
         memmove(fields, &fields[2], (n - 2) * sizeof(*fields));
         n -= 2;
      }
      unsigned f = 1;
      bool vertex = stage == STELA_AIR_VERTEX, fragment = stage == STELA_AIR_FRAGMENT;
      if (vertex && stela_air_md_string(fields[0], "air.position")) {
         io->semantic = STELA_AIR_POSITION; positions++;
      } else if (vertex && stela_air_md_string(fields[0], "air.vertex_output")) {
         io->semantic = STELA_AIR_VARYING;
         if (!metadata_text(m, fields[f++], &io->identifier, &io->identifier_bytes)) return false;
      } else if (vertex && stela_air_md_string(fields[0], "air.point_size")) {
         io->semantic = STELA_AIR_POINT_SIZE;
      } else if (vertex && stela_air_md_string(fields[0], "air.render_target_array_index")) {
         io->semantic = STELA_AIR_LAYER;
      } else if (vertex && stela_air_md_string(fields[0], "air.viewport_array_index")) {
         io->semantic = STELA_AIR_VIEWPORT;
      } else if (vertex && stela_air_md_string(fields[0], "air.clip_distance")) {
         io->semantic = STELA_AIR_CLIP_DISTANCE;
         /* Before Metal 2.4 only the type gives the size. */
         LLVMTypeRef type = aggregate ? LLVMStructGetTypeAtIndex(result, i) : result;
         LLVMTypeKind kind = LLVMGetTypeKind(type);
         io->clip_distances = kind == LLVMArrayTypeKind ? LLVMGetArrayLength2(type) :
                              kind == LLVMFloatTypeKind;
         if (f < n && stela_air_md_string(fields[f], "air.clip_distance_array_size") ?
                !clip_distance_size(m, fields, &f, n, io) :
                !io->clip_distances || io->clip_distances > AIR_MAX_CLIP_DISTANCES)
            return fail(m, STELA_AIR_ARGUMENT, "clip distances need an array size of 1 to %u",
                        AIR_MAX_CLIP_DISTANCES);
      } else if (fragment && stela_air_md_string(fields[0], "air.render_target")) {
         io->semantic = STELA_AIR_RENDER_TARGET;
         if (n < 4 || !argument_location(fields[f++], &io->location) ||
             io->location >= AIR_MAX_RENDER_TARGETS)
            return fail(m, STELA_AIR_ARGUMENT, "unsupported attachment/dual-source output");
         /* Dual-source blending writes index 1 of attachment 0. Metal 1 has
          * no index. */
         f += stela_air_md_uint(fields[f], &io->index);
         if (io->index > 1 || (io->index && io->location))
            return fail(m, STELA_AIR_ARGUMENT, "unsupported attachment/dual-source output");
      } else if (fragment && stela_air_md_string(fields[0], "air.depth")) {
         io->semantic = STELA_AIR_DEPTH;
      } else if (fragment && stela_air_md_string(fields[0], "air.sample_mask")) {
         io->semantic = STELA_AIR_SAMPLE_MASK;
      } else if (fragment && stela_air_md_string(fields[0], "air.stencil")) {
         io->semantic = STELA_AIR_STENCIL;
      } else if (fragment && stela_air_md_string(fields[0], "air.imageblock_data")) {
         io->semantic = STELA_AIR_IMAGEBLOCK_DATA;
         LLVMTypeRef type = aggregate ? LLVMStructGetTypeAtIndex(result, i) : result;
         if (!imageblock_data(m, fields, 1, n, type, io, &r->entry.imageblock_bytes))
            return false;
         for (unsigned j = 0; j < i; j++) {
            if (!io->absent && !r->outputs[j].absent && r->outputs[j].semantic == io->semantic)
               return fail(m, STELA_AIR_METADATA, "duplicate render output");
         }
         continue;
      } else return fail(m, STELA_AIR_METADATA, "unsupported stage output semantic");
      if (!output_reflection(m, fields, f, n, io))
         return false;
      LLVMTypeRef leaf = aggregate ? LLVMStructGetTypeAtIndex(result, i) : result;
      bool type = output_type(io);
      if (type && io->semantic == STELA_AIR_CLIP_DISTANCE &&
          LLVMGetTypeKind(leaf) == LLVMArrayTypeKind) {
         type = LLVMGetArrayLength2(leaf) == io->clip_distances;
         leaf = LLVMGetElementType(leaf);
      } else if (io->semantic == STELA_AIR_CLIP_DISTANCE) {
         type = type && io->clip_distances == 1;
      }
      if (!type || !stage_type_matches(leaf, io->primitive, io->components))
         return fail(m, STELA_AIR_TYPE, "unsupported render output type");
      for (unsigned j = 0; j < i; j++) {
         if (!io->absent && !r->outputs[j].absent && same_output(io, &r->outputs[j]))
            return fail(m, STELA_AIR_METADATA, "duplicate render output");
      }
   }
   if (stage == STELA_AIR_VERTEX && positions != 1)
      return fail(m, STELA_AIR_METADATA, "vertex entry requires exactly one position output");
   r->entry.output_count = count;
   return true;
}

bool
stela_air_metadata_stage_map(struct stela_air_metadata *m, const struct stela_air_render *r,
                             const struct stela_air_varying_slot *rows, unsigned count, unsigned max_slots)
{
   if (!max_slots || max_slots > 32 || count > max_slots || (count && !rows))
      return fail(m, STELA_AIR_INPUT, "invalid explicit render varying map/budget");
   for (unsigned i = 0; i < count; i++) {
      const struct stela_air_varying_slot *v = &rows[i];
      if (!stage_text(v->identifier, v->identifier_bytes) || v->location >= max_slots ||
          !stage_varying(v->primitive) || !v->components || v->components > 4)
         return fail(m, STELA_AIR_ARGUMENT, "invalid explicit varying map identifier/type/location");
      for (unsigned j = 0; j < i; j++) {
         if (v->location == rows[j].location || (v->identifier_bytes == rows[j].identifier_bytes &&
             !memcmp(v->identifier, rows[j].identifier, v->identifier_bytes)))
            return fail(m, STELA_AIR_ARGUMENT, "duplicate varying map identifier/location");
      }
   }
   for (unsigned direction = 0; direction < 2; direction++) {
      const struct stela_air_stage_io *io = direction ? r->entry.outputs : r->entry.inputs;
      unsigned n = direction ? r->entry.output_count : r->entry.input_count;
      for (unsigned i = 0; i < n; i++) {
         if (io[i].semantic != STELA_AIR_VARYING || io[i].absent) continue;
         unsigned j;
         for (j = 0; j < count; j++) {
            if (rows[j].identifier_bytes == io[i].identifier_bytes &&
                !memcmp(rows[j].identifier, io[i].identifier, io[i].identifier_bytes)) break;
         }
         if (j == count || rows[j].primitive != io[i].primitive || rows[j].components != io[i].components ||
             (direction && rows[j].per_primitive != io[i].per_primitive))
            return fail(m, STELA_AIR_ARGUMENT, "selected stage linkage missing/type mismatch");
      }
   }
   return true;
}

bool
stela_air_link_stage_io(const struct stela_air_stage_entry *vs,
                        const struct stela_air_stage_entry *fs, unsigned max_slots,
                        struct stela_air_varying_slot *rows, unsigned capacity,
                        unsigned *count, struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   if (!error) error = &local;
   *error = (struct stela_air_error){0};
   struct stela_air_metadata m = {.error = error};
   if (!vs || !fs || (vs->stage != STELA_AIR_VERTEX && vs->stage != STELA_AIR_MESH) ||
       fs->stage != STELA_AIR_FRAGMENT ||
       !max_slots || max_slots > 32 || capacity > AIR_MAX_ARGUMENTS || !count ||
       !rows || vs->output_count > AIR_MAX_ARGUMENTS || fs->input_count > AIR_MAX_ARGUMENTS ||
       (vs->output_count && !vs->outputs) || (fs->input_count && !fs->inputs))
      return fail(&m, STELA_AIR_INPUT, "invalid bounded stage linkage input");
   struct stela_air_varying_slot result[AIR_MAX_ARGUMENTS];
   unsigned n = 0;
   for (unsigned i = 0; i < vs->output_count; i++) {
      const struct stela_air_stage_io *v = &vs->outputs[i];
      if (v->semantic != STELA_AIR_VARYING) continue;
      if (!stage_text(v->identifier, v->identifier_bytes) || !stage_varying(v->primitive) ||
          !v->components || v->components > 4 || n == max_slots || n == capacity)
         return fail(&m, STELA_AIR_LIMIT, "vertex varying type/identifier/slot limit");
      for (unsigned j = 0; j < n; j++) {
         if (v->identifier_bytes == result[j].identifier_bytes &&
             !memcmp(v->identifier, result[j].identifier, v->identifier_bytes))
            return fail(&m, STELA_AIR_METADATA, "duplicate vertex varying map identifier");
      }
      result[n] = (struct stela_air_varying_slot){v->identifier, v->identifier_bytes, v->primitive,
                                                  v->components, n, v->per_primitive};
      n++;
   }
   for (unsigned i = 0; i < fs->input_count; i++) {
      const struct stela_air_stage_io *f = &fs->inputs[i];
      if (f->semantic != STELA_AIR_VARYING || f->absent) continue;
      unsigned j;
      for (j = 0; j < n; j++) {
         if (f->identifier_bytes == result[j].identifier_bytes &&
             stage_text(f->identifier, f->identifier_bytes) &&
             !memcmp(f->identifier, result[j].identifier, f->identifier_bytes)) break;
      }
      if (j == n || f->primitive != result[j].primitive || f->components != result[j].components ||
          !f->interpolation)
         return fail(&m, STELA_AIR_METADATA, "fragment varying missing/mismatched in vertex map");
      for (unsigned k = 0; k < i; k++) {
         const struct stela_air_stage_io *previous = &fs->inputs[k];
         if (previous->semantic == STELA_AIR_VARYING && previous->identifier_bytes == f->identifier_bytes &&
             !memcmp(previous->identifier, f->identifier, f->identifier_bytes))
            return fail(&m, STELA_AIR_METADATA, "duplicate fragment varying map identifier");
      }
   }
   memcpy(rows, result, n * sizeof(*rows)); *count = n;
   return true;
}

static void
inspection_diagnostic(LLVMDiagnosticInfoRef info, void *data)
{
   struct stela_air_metadata *m = data;
   if (LLVMGetDiagInfoSeverity(info) != LLVMDSError)
      return;
   char *message = LLVMGetDiagInfoDescription(info);
   fail(m, STELA_AIR_BITCODE, "%s", message ? message : "LLVM bitcode diagnostic");
   LLVMDisposeMessage(message);
}

/* Whether a name's first `stem` bytes are, or end with, text. */
static bool
stem_is(const char *name, size_t stem, const char *text)
{
   return stem == strlen(text) && !memcmp(name, text, stem);
}
static bool
stem_ends(const char *name, size_t stem, const char *text)
{
   size_t bytes = strlen(text);
   return stem > bytes && !memcmp(name + stem - bytes, text, bytes);
}

/* The module's enum stela_air_command_use, from the AIR command functions
 * its code calls (air_commands.c). Copies carry a command's barrier. */
static unsigned
command_use(LLVMModuleRef module)
{
   static const char *const barriers[] = {
      "air.set_barrier_render_command", "air.set_barrier_compute_command",
      "air.copy_render_command", "air.copy_compute_command",
   };
   unsigned use = 0;
   for (LLVMValueRef fn = LLVMGetFirstFunction(module); fn; fn = LLVMGetNextFunction(fn)) {
      size_t bytes;
      const char *name = LLVMGetValueName2(fn, &bytes);
      const char *dot = bytes > 4 ? memchr(name + 4, '.', bytes - 4) : NULL;
      size_t stem = dot ? (size_t)(dot - name) : bytes;
      if (!LLVMIsDeclaration(fn) || !LLVMGetFirstUse(fn) || stem < 4 || memcmp(name, "air.", 4))
         continue;
      bool command = stem_ends(name, stem, "_render_command") ||
                     stem_ends(name, stem, "_compute_command") ||
                     stem_is(name, stem, "air.get_size_command_buffer");
      if (command)
         use |= STELA_AIR_COMMANDS_ENCODE;
      for (unsigned i = 0; command && i < ARRAY_SIZE(barriers); i++) {
         if (stem_is(name, stem, barriers[i]))
            use |= STELA_AIR_COMMANDS_BARRIERS;
      }
   }
   return use;
}

/* In enum stela_air_stage order after the kernels. */
static const char *const entry_lists[] = {"air.kernel", "air.vertex", "air.fragment",
                                          "air.object", "air.mesh", "air.visible"};

static bool
entry_stage(struct stela_air_metadata *m, const char *entry, unsigned *stage)
{
   bool found = false;
   LLVMValueRef fn = LLVMGetNamedFunction(m->module, entry);
   for (unsigned list = 0; fn && list < ARRAY_SIZE(entry_lists); list++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_named_md(m, entry_lists[list], nodes, &count))
         return false;
      for (unsigned i = 0; i < count; i++) {
         LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
         unsigned fields_count;
         if (!stela_air_md_node(m, nodes[i], fields, &fields_count) || !fields_count)
            return false;
         if (fields[0] != fn)
            continue;
         if (found)
            return fail(m, STELA_AIR_METADATA, "entry listed more than once");
         found = true;
         *stage = list;
      }
   }
   return found || fail(m, STELA_AIR_ARGUMENT, "entry is not a listed AIR function");
}

/* Whether `name` is `stem`, or with `suffixed` `stem.` and more. */
static bool
stitched_read(const char *name, size_t bytes, const char *stem, bool suffixed)
{
   size_t length = strlen(stem);
   return suffixed ? bytes > length + 1 && !memcmp(name, stem, length) && name[length] == '.' :
                     bytes == length && !memcmp(name, stem, length);
}

/* Appends to the *count arguments of args, which hold AIR_MAX_ARGUMENTS, the
 * resources fn binds through air_stitch.c's reads, as a stitched kernel
 * does: each binding once, with the access all its reads take. */
static bool
stitched_arguments(struct stela_air_metadata *m, LLVMValueRef fn,
                   struct stela_air_argument_info *args, unsigned *count)
{
   const char *texture_metadata = STELA_AIR_STITCH_TEXTURE_METADATA;
   unsigned texture_kind = LLVMGetMDKindIDInContext(LLVMGetModuleContext(m->module),
                                                    texture_metadata,
                                                    (unsigned)strlen(texture_metadata));
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = LLVMIsACallInst(inst) ? LLVMGetCalledValue(inst) : NULL;
         size_t bytes = 0;
         const char *name =
            callee && LLVMIsAFunction(callee) ? LLVMGetValueName2(callee, &bytes) : "";
         bool buffer = stitched_read(name, bytes, STELA_AIR_STITCH_BUFFER_ADDRESS_NAME, true);
         bool texture = stitched_read(name, bytes, STELA_AIR_STITCH_TEXTURE_NAME, false);
         bool sampler = stitched_read(name, bytes, STELA_AIR_STITCH_SAMPLER_NAME, false);
         bool threadgroup = stitched_read(name, bytes, STELA_AIR_STITCH_THREADGROUP_NAME, false);
         if (!buffer && !texture && !sampler && !threadgroup)
            continue;
         LLVMValueRef index = LLVMGetNumArgOperands(inst) == 1 ? LLVMGetOperand(inst, 0) : NULL;
         if (!index || !LLVMIsAConstantInt(index) ||
             LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMPointerTypeKind)
            return fail(m, STELA_AIR_INPUT, "a stitched resource of an unknown form");
         unsigned bound = (unsigned)LLVMConstIntGetZExtValue(index);
         unsigned space = LLVMGetPointerAddressSpace(LLVMTypeOf(inst));
         /* Metal names none of them. */
         struct stela_air_argument_info read = {
            .kind = texture ? 3 : sampler ? 4 : 1, .name = "", .type_name = "", .used = true};
         if (texture) {
            /* A texture no texture call takes is never read. */
            LLVMValueRef described = LLVMGetMetadata(inst, texture_kind);
            LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
            unsigned field_count;
            if (!described)
               continue;
            if (!stela_air_md_node(m, described, fields, &field_count) || field_count != 4)
               return fail(m, STELA_AIR_METADATA, "a stitched texture's description");
            for (unsigned i = 0; i < field_count; i++) {
               if (!LLVMIsAConstantInt(fields[i]))
                  return fail(m, STELA_AIR_METADATA, "a stitched texture's description");
            }
            read.texture = (struct stela_air_texture){
               .argument = bound, .index = bound,
               .type = (enum stela_air_texture_type)LLVMConstIntGetZExtValue(fields[0]),
               .access = (enum stela_air_texture_access)LLVMConstIntGetZExtValue(fields[1]),
               .primitive = (enum stela_air_primitive)LLVMConstIntGetZExtValue(fields[2]),
               .depth = LLVMConstIntGetZExtValue(fields[3]) != 0};
         } else if (sampler) {
            read.sampler = (struct stela_air_sampler){.argument = bound, .index = bound};
         } else {
            read.buffer = (struct stela_air_buffer){
               .argument = bound, .index = bound, .address_space = threadgroup ? 3 : space,
               .access = space == 2 ? STELA_AIR_READ : STELA_AIR_READ_WRITE};
         }
         bool held = false;
         for (unsigned i = 0; !held && i < *count; i++) {
            struct stela_air_argument_info *earlier = &args[i];
            if (earlier->kind != read.kind)
               continue;
            if (texture && earlier->texture.index == bound) {
               earlier->texture.access |= read.texture.access;
               held = true;
            } else if (sampler && earlier->sampler.index == bound) {
               held = true;
            } else if (!texture && !sampler && earlier->buffer.index == bound &&
                       (earlier->buffer.address_space == 3) == threadgroup) {
               earlier->buffer.access |= read.buffer.access;
               held = true;
            }
         }
         if (held)
            continue;
         if (*count == AIR_MAX_ARGUMENTS)
            return fail(m, STELA_AIR_LIMIT, "a stitched kernel's resources exceed its arguments");
         args[(*count)++] = read;
      }
   }
   return true;
}

static bool
inspect(const void *bitcode, size_t size, const struct stela_air_constants *constants,
        unsigned max_entries,
        stela_air_visit_entry visit, void *data, struct stela_air_error *error,
        const char *entry_name, enum stela_air_stage stage, stela_air_visit_stage render_visit,
        unsigned *listed_stage)
{
   struct stela_air_error local = {0};
   if (!error)
      error = &local;
   *error = (struct stela_air_error){0};
   struct stela_air_metadata m = {.error = error};
   if (!bitcode || size < 4 || size > AIR_MAX_BITCODE_BYTES ||
       memcmp(bitcode, "BC\xc0\xde", 4) || !max_entries ||
       max_entries > AIR_MAX_METADATA_OPERANDS ||
       (entry_name && (!render_visit || !stage_text(entry_name, strlen(entry_name)))) ||
       ((!entry_name || listed_stage) && !visit))
      return fail(&m, STELA_AIR_INPUT, "invalid AIR inspection input/budget");
   unsigned major, minor, patch;
   LLVMGetVersion(&major, &minor, &patch);
   if (major != 23)
      return fail(&m, STELA_AIR_LLVM_VERSION, "requires LLVM 23 C ABI, found %u.%u.%u", major, minor, patch);
   LLVMContextRef context = LLVMContextCreate();
   if (!context)
      return fail(&m, STELA_AIR_ALLOCATION, "LLVM context unavailable");
   LLVMContextSetDiagnosticHandler(context, inspection_diagnostic, &m);
   LLVMMemoryBufferRef buffer = LLVMCreateMemoryBufferWithMemoryRangeCopy(bitcode, size, "Metal input");
   if (!buffer) {
      LLVMContextDispose(context);
      return fail(&m, STELA_AIR_ALLOCATION, "LLVM buffer unavailable");
   }
   bool parsed = !LLVMParseBitcodeInContext2(context, buffer, &m.module);
   LLVMDisposeMemoryBuffer(buffer);
   bool success = false;
   struct stela_air_constructed_constants prepared = {0};
   struct decoded_entry {
      LLVMValueRef fn;
      const char *name;
      size_t name_bytes;
      struct stela_air_kernel kernel;
   } *entries = NULL;
   if (!parsed || error->kind != STELA_AIR_OK) {
      fail(&m, STELA_AIR_BITCODE, "LLVM refused AIR bitcode");
      goto done;
   }
   if (listed_stage) {
      if (!entry_stage(&m, entry_name, listed_stage))
         goto done;
      stage = (enum stela_air_stage)*listed_stage;
   }
   m.render = stage != 0;
   char *verification = NULL;
   if (LLVMVerifyModule(m.module, LLVMReturnStatusAction, &verification)) {
      fail(&m, STELA_AIR_VERIFY, "%s", verification ? verification : "invalid LLVM module");
      LLVMDisposeMessage(verification);
      goto done;
   }
   LLVMDisposeMessage(verification);
   const char *target = LLVMGetTarget(m.module);
   size_t assembly;
   LLVMGetModuleInlineAsm(m.module, &assembly);
   if (strncmp(target, "air64", 5) || assembly || LLVMGetFirstGlobalAlias(m.module) ||
       LLVMGetFirstGlobalIFunc(m.module)) {
      fail(&m, STELA_AIR_TARGET, "unsupported target/globals/inline assembly");
      goto done;
   }
   if (!stela_air_metadata_layout(&m) || !stela_air_metadata_validate(&m))
      goto done;
   bool ready = constants && stela_air_prepare_constants(&m, constants, &prepared);
   if (!stela_air_inline_calls(&m, NULL, 0, 0))
      goto done;
   if (!stela_air_metadata_target(&m, target)) {
      fail(&m, STELA_AIR_TARGET, "AIR version and target triple disagree");
      goto done;
   }
   struct stela_air_function_constant function_constants[AIR_MAX_FUNCTION_CONSTANTS];
   unsigned constant_count;
   if (!stela_air_metadata_function_constants(&m, function_constants, NULL, &constant_count) ||
       (constants && (!stela_air_specialize_constants(&m, constants->values, constants->count) ||
                      !stela_air_construct_prepared_constants(&m, ready ? &prepared : NULL))))
      goto done;
   struct stela_air_inspection info = {
      .target = target, .target_bytes = strlen(target), .air_minor = m.air_minor,
      .language_major = m.language_major, .language_minor = m.language_minor,
      .denorms_disable = m.denorms_disable, .fast_math = m.fast_math,
      .function_constants = function_constants, .function_constant_count = constant_count,
      .ident = m.ident, .ident_bytes = m.ident_bytes,
      .commands = command_use(m.module),
      .metadata = &m,
   };
   if (m.render) {
      struct stela_air_render render = {.entry = {.stage = stage}};
      if (stage != STELA_AIR_VISIBLE &&
          !stela_air_metadata_stage(&m, LLVMGetNamedFunction(m.module, entry_name), stage, &render)) goto done;
      success = render_visit(&info, &render.entry, data);
      if (!success) fail(&m, STELA_AIR_LIMIT, "AIR stage receiver refused entry");
      goto done;
   }
   LLVMValueRef kernels[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_named_md(&m, "air.kernel", kernels, &count))
      goto done;
   if (!count || count > max_entries) {
      fail(&m, STELA_AIR_LIMIT, "no executable compute entries or entry budget exceeded");
      goto done;
   }
   entries = calloc(count, sizeof(*entries));
   if (!entries) {
      fail(&m, STELA_AIR_ALLOCATION, "entry manifest allocation failed");
      goto done;
   }
   /* Validate the complete manifest BEFORE the first callback. A later invalid
    * entry cannot publish a partially accepted library through this interface. */
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count;
      if (!stela_air_md_node(&m, kernels[i], fields, &fields_count) || fields_count < 3 ||
          !fields[0] || !LLVMIsAFunction(fields[0])) {
         fail(&m, STELA_AIR_METADATA, "invalid AIR kernel manifest entry");
         goto done;
      }
      entries[i].fn = fields[0];
      entries[i].name = LLVMGetValueName2(fields[0], &entries[i].name_bytes);
      if (!entries[i].name_bytes || entries[i].name_bytes > 4096 ||
          memchr(entries[i].name, 0, entries[i].name_bytes)) {
         fail(&m, STELA_AIR_METADATA, "invalid/oversized AIR entry name");
         goto done;
      }
      for (unsigned j = 0; j < i; j++) {
         if (entries[j].fn == entries[i].fn) {
            fail(&m, STELA_AIR_METADATA, "duplicate AIR kernel manifest entry");
            goto done;
         }
      }
      if (!stela_air_metadata_kernel(&m, entries[i].fn, &entries[i].kernel))
         goto done;
   }
   for (unsigned i = 0; i < count; i++) {
      struct stela_air_argument_info args[AIR_MAX_ARGUMENTS];
      for (unsigned a = 0; a < entries[i].kernel.count; a++) {
         const struct stela_air_argument *arg = &entries[i].kernel.arguments[a];
         args[a] = (struct stela_air_argument_info) {
            .buffer = arg->buffer,
            .kind = arg->is_buffer ? 1 : arg->is_texture ? 3 : arg->is_sampler ? 4 :
                    arg->is_stage_in ? 5 : arg->is_imageblock ? 6 : 2,
            .texture = arg->texture, .sampler = arg->sampler, .builtin = arg->builtin,
            .location = arg->location,
            .components = arg->components,
            .plain_buffer_type = arg->plain_buffer_type, .argument_buffer = arg->is_argument_buffer,
            .name = arg->name, .name_bytes = arg->name_bytes,
            .type_name = arg->type_name, .type_name_bytes = arg->type_name_bytes,
            .primitive = arg->primitive, .type_components = arg->type_components, .used = arg->used,
            .absent = arg->absent, .conditional = arg->conditional,
            .layout = (const struct stela_air_layout *)arg->layout,
         };
      }
      unsigned argument_count = entries[i].kernel.count;
      if (!stitched_arguments(&m, entries[i].fn, args, &argument_count))
         goto done;
      struct stela_air_entry entry = {
         .name = entries[i].name, .name_bytes = entries[i].name_bytes,
         .argument_count = argument_count, .arguments = args,
         .reflection_complete = complete_reflection(&m, entries[i].fn, &entries[i].kernel),
         .max_threads = entries[i].kernel.max_threads,
         .imageblock_bytes = entries[i].kernel.imageblock_size,
      };
      bool discards;
      entry_facts(&m, entries[i].fn, &entry.threadgroup_bytes, &discards);
      if (!visit(&info, &entry, data)) {
         fail(&m, STELA_AIR_LIMIT, "AIR manifest receiver refused entry");
         goto done;
      }
   }
   success = true;
done:
   stela_air_release_constructed_constants(&prepared);
   free(entries);
   if (m.module)
      LLVMDisposeModule(m.module);
   LLVMContextDispose(context);
   return success;
}

bool
stela_air_inspect(const void *bitcode, size_t size, const struct stela_air_constants *constants,
                  unsigned max_entries, stela_air_visit_entry visit, void *data,
                  struct stela_air_error *error)
{
   return inspect(bitcode, size, constants, max_entries, visit, data, error, NULL, 0, NULL, NULL);
}

bool
stela_air_inspect_stage(const void *bitcode, size_t size, const struct stela_air_constants *constants,
                        const char *entry,
                         enum stela_air_stage stage, stela_air_visit_stage visit,
                         void *data, struct stela_air_error *error)
{
   if (!entry || stage < STELA_AIR_VERTEX || stage > STELA_AIR_VISIBLE) {
      if (error) *error = (struct stela_air_error){.kind = STELA_AIR_INPUT};
      return false;
   }
   return inspect(bitcode, size, constants, AIR_MAX_METADATA_OPERANDS, NULL, data, error, entry,
                  stage, visit, NULL);
}

bool
stela_air_inspect_entry(const void *bitcode, size_t size, const struct stela_air_constants *constants,
                        const char *entry, unsigned *stage, stela_air_visit_entry kernel_visit,
                        stela_air_visit_stage stage_visit, void *data, struct stela_air_error *error)
{
   if (!entry || !stage) {
      if (error) *error = (struct stela_air_error){.kind = STELA_AIR_INPUT};
      return false;
   }
   return inspect(bitcode, size, constants, AIR_MAX_METADATA_OPERANDS, kernel_visit, data, error,
                  entry, 0, stage_visit, stage);
}

/* Discovery needs globals and named metadata. Leave function bodies to the
 * eager parser and verifier used by inspection and lowering. */
static bool
parse_metadata(struct stela_air_metadata *m, const void *bitcode, size_t size,
             LLVMContextRef *context)
{
   *context = LLVMContextCreate();
   if (!*context)
      return fail(m, STELA_AIR_ALLOCATION, "LLVM context unavailable");
   LLVMContextSetDiagnosticHandler(*context, inspection_diagnostic, m);
   LLVMMemoryBufferRef buffer = LLVMCreateMemoryBufferWithMemoryRangeCopy(bitcode, size, "Metal input");
   bool parsed = buffer && !LLVMGetBitcodeModuleInContext2(*context, buffer, &m->module);
   /* LLVM owns the buffer once it creates the lazy module. */
   if (buffer && !parsed)
      LLVMDisposeMemoryBuffer(buffer);
   return (parsed && m->error->kind == STELA_AIR_OK) ||
      fail(m, STELA_AIR_BITCODE, "LLVM refused AIR bitcode");
}

static void
close_module(struct stela_air_metadata *m, LLVMContextRef context)
{
   if (m->module)
      LLVMDisposeModule(m->module);
   if (context)
      LLVMContextDispose(context);
}

static bool
valid_bitcode(const void *bitcode, size_t size)
{
   return bitcode && size >= 4 && size <= AIR_MAX_BITCODE_BYTES &&
          !memcmp(bitcode, "BC\xc0\xde", 4);
}

bool
stela_air_functions(const void *bitcode, size_t size, stela_air_visit_function visit, void *data,
                    struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   struct stela_air_metadata m = {.error = error ? error : &local};
   *m.error = (struct stela_air_error){0};
   if (!valid_bitcode(bitcode, size) || !visit)
      return fail(&m, STELA_AIR_INPUT, "invalid AIR function list query");
   LLVMContextRef context;
   bool visited = parse_metadata(&m, bitcode, size, &context);
   for (unsigned list = 0; visited && list < ARRAY_SIZE(entry_lists); list++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      visited = stela_air_named_md(&m, entry_lists[list], nodes, &count);
      for (unsigned i = 0; visited && i < count; i++) {
         LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
         unsigned fields_count;
         visited = stela_air_md_node(&m, nodes[i], fields, &fields_count) && fields_count &&
                   fields[0] && LLVMIsAFunction(fields[0]);
         if (visited) {
            size_t name_bytes;
            const char *name = LLVMGetValueName2(fields[0], &name_bytes);
            visited = visit(data, name, name_bytes, list);
         }
      }
   }
   if (!visited && m.error->kind == STELA_AIR_OK)
      fail(&m, STELA_AIR_METADATA, "a function the module lists");
   close_module(&m, context);
   return visited;
}

/* Whether an entry list names fn. */
static bool
listed_entry(struct stela_air_metadata *m, LLVMValueRef fn)
{
   for (unsigned list = 0; list < ARRAY_SIZE(entry_lists); list++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_named_md(m, entry_lists[list], nodes, &count))
         return false;
      for (unsigned i = 0; i < count; i++) {
         LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
         unsigned fields_count;
         if (stela_air_md_node(m, nodes[i], fields, &fields_count) && fields_count &&
             fields[0] == fn)
            return true;
      }
   }
   return false;
}

bool
stela_air_exports(const void *bitcode, size_t size, stela_air_visit_function visit, void *data,
                  struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   struct stela_air_metadata m = {.error = error ? error : &local};
   *m.error = (struct stela_air_error){0};
   if (!valid_bitcode(bitcode, size) || !visit)
      return fail(&m, STELA_AIR_INPUT, "invalid AIR export list query");
   LLVMContextRef context;
   bool visited = parse_metadata(&m, bitcode, size, &context);
   for (LLVMValueRef fn = visited ? LLVMGetFirstFunction(m.module) : NULL; visited && fn;
        fn = LLVMGetNextFunction(fn)) {
      size_t name_bytes;
      const char *name = LLVMGetValueName2(fn, &name_bytes);
      bool intrinsic = (name_bytes > 4 && !memcmp(name, "air.", 4)) ||
                       (name_bytes > 5 && !memcmp(name, "llvm.", 5));
      if (LLVMIsDeclaration(fn) || intrinsic || LLVMGetLinkage(fn) != LLVMExternalLinkage ||
          LLVMGetVisibility(fn) != LLVMDefaultVisibility || listed_entry(&m, fn))
         continue;
      visited = visit(data, name, name_bytes, 0);
   }
   if (!visited && m.error->kind == STELA_AIR_OK)
      fail(&m, STELA_AIR_METADATA, "a function the module exports");
   close_module(&m, context);
   return visited;
}

bool
stela_air_sampler_states(const void *bitcode, size_t size, uint64_t *states, unsigned *count,
                         struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   struct stela_air_metadata m = {.error = error ? error : &local};
   *m.error = (struct stela_air_error){0};
   *count = 0;
   if (!valid_bitcode(bitcode, size))
      return fail(&m, STELA_AIR_INPUT, "invalid AIR sampler state query");
   LLVMContextRef context;
   LLVMValueRef globals[AIR_MAX_SAMPLER_STATES];
   bool listed = parse_metadata(&m, bitcode, size, &context) &&
                 stela_air_metadata_sampler_states(&m, globals, states, count);
   close_module(&m, context);
   return listed;
}
