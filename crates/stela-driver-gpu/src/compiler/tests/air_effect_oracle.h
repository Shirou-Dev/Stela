/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef STELA_AIR_EFFECT_ORACLE_H
#define STELA_AIR_EFFECT_ORACLE_H

#include "compiler/nir/nir_constant_expressions.h"
#include <stdlib.h>
#include <string.h>

/* Authored-test execution only. This follows validated structured NIR and
 * delegates integer ALU semantics to Mesa. No runtime shader path uses it. */
enum air_effect_status {
   AIR_EFFECT_COMPLETE,
   AIR_EFFECT_BUDGET,
   AIR_EFFECT_UNSUPPORTED,
   AIR_EFFECT_UNDEFINED,
   AIR_EFFECT_INVALID,
   AIR_EFFECT_ALLOCATION,
   AIR_EFFECT_TRACE_FULL,
};

/* A store's effect; a shared store's address is its byte offset in shared
 * memory. */
struct air_effect_store {
   bool ssbo, shared;
   uint64_t slot, address;
   unsigned components, bits;
   nir_const_value values[4];
};

struct air_effect_run {
   enum air_effect_status status;
   const char *detail;
   unsigned instructions, stores;
};

struct air_effect_value {
   bool known;
   unsigned components, bits;
   nir_const_value lanes[4];
};

/* A storage image of one layer and sample: four 32-bit words a texel, in
 * rows. */
struct air_effect_image {
   uint32_t width, height;
   uint32_t *texels;
};

/* What an execution reads: little-endian global memory at base, which
 * global loads read and global stores within it update, the push constants,
 * the invocation's linear index in its workgroup and workgroup ID, from
 * which its global ID follows, its scratch memory, if any, and the storage
 * images an image variable's array index names, if any. Image stores are
 * no effects; they change the image. */
struct air_effect_environment {
   uint64_t base;
   uint8_t *bytes;
   size_t size;
   const uint8_t *push;
   size_t push_size;
   uint32_t local_index, workgroup[3];
   uint8_t *scratch;
   size_t scratch_size;
   const struct air_effect_image *images;
   unsigned image_count;
};

/* Whether a value of shape at address lies within size bytes at base, and
 * its offset there. */
static bool
air_effect_within(size_t size, uint64_t base, uint64_t address,
                  const struct air_effect_value *shape, size_t *offset)
{
   uint64_t length = (uint64_t)shape->components * (shape->bits / 8);
   if (address < base || address - base > size || length > size - (address - base))
      return false;
   *offset = (size_t)(address - base);
   return true;
}

static void
air_effect_read(const uint8_t *bytes, struct air_effect_value *value)
{
   for (unsigned lane = 0; lane < value->components; lane++) {
      uint64_t word = 0;
      for (unsigned i = 0; i < value->bits / 8; i++)
         word |= (uint64_t)bytes[lane * (value->bits / 8) + i] << (8 * i);
      value->lanes[lane] = nir_const_value_for_uint(word, value->bits);
   }
}

static void
air_effect_write(uint8_t *bytes, const struct air_effect_value *value)
{
   for (unsigned lane = 0; lane < value->components; lane++) {
      uint64_t word = nir_const_value_as_uint(value->lanes[lane], value->bits);
      for (unsigned i = 0; i < value->bits / 8; i++)
         bytes[lane * (value->bits / 8) + i] = (uint8_t)(word >> (8 * i));
   }
}

static bool
air_effect_shape(const nir_def *def)
{
   return def && def->num_components && def->num_components <= 4 &&
          (def->bit_size == 1 || def->bit_size == 8 || def->bit_size == 16 ||
           def->bit_size == 32 || def->bit_size == 64);
}

static const struct air_effect_value *
air_effect_get(const struct air_effect_value *values, unsigned count,
                const nir_def *def)
{
   if (!air_effect_shape(def) || def->index >= count || !values[def->index].known)
      return NULL;
   return &values[def->index];
}

static bool
air_effect_integer_type(nir_alu_type type)
{
   nir_alu_type base = nir_alu_type_get_base_type(type);
   return base == nir_type_int || base == nir_type_uint || base == nir_type_bool;
}

/* Runs shader in an environment, which may be NULL: then any load is
 * unsupported. */
static struct air_effect_run
air_effect_execute_in(nir_shader *shader, unsigned budget, struct air_effect_store *trace,
                      unsigned capacity, const struct air_effect_environment *memory)
{
   struct air_effect_run run = {.status = AIR_EFFECT_INVALID, .detail = "invalid execution input"};
   struct air_effect_value *values = NULL, *pending = NULL;
#define AIR_EFFECT_FAIL(code, why) do { run.status = code; run.detail = why; goto done; } while (0)
   if (!shader || (!trace && capacity))
      goto done;
   nir_function_impl *impl = NULL;
   unsigned implementations = 0;
   nir_foreach_function_impl(candidate, shader) {
      impl = candidate;
      implementations++;
   }
   if (implementations != 1 || !impl->structured)
      AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "requires one structured entry implementation");
   nir_validate_shader(shader, "test effect executor input");
   nir_validate_ssa_dominance(shader, "test effect executor input dominance");
   nir_index_ssa_defs(impl);
   unsigned count = impl->ssa_alloc;
   size_t storage_count = count ? count : 1;
   if (storage_count > SIZE_MAX / sizeof(*values))
      AIR_EFFECT_FAIL(AIR_EFFECT_ALLOCATION, "SSA execution storage overflow");
   values = calloc(storage_count, sizeof(*values));
   pending = calloc(storage_count, sizeof(*pending));
   if (!values || !pending)
      AIR_EFFECT_FAIL(AIR_EFFECT_ALLOCATION, "SSA execution storage unavailable");
   nir_block *block = nir_start_block(impl), *predecessor = NULL;
   while (block != impl->end_block) {
      /* Empty cycles consume budget too. Exhaustion is never completion. */
      if (run.instructions == budget)
         AIR_EFFECT_FAIL(AIR_EFFECT_BUDGET, "test execution budget exhausted");
      run.instructions++;
      nir_foreach_phi(phi, block) {
         if (run.instructions == budget)
            AIR_EFFECT_FAIL(AIR_EFFECT_BUDGET, "test execution budget exhausted at PHI");
         run.instructions++;
         if (!air_effect_shape(&phi->def) || phi->def.index >= count)
            AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "unsupported PHI shape");
         const struct air_effect_value *source = NULL;
         unsigned matches = 0;
         nir_foreach_phi_src(incoming, phi) {
            if (incoming->pred == predecessor) {
               source = air_effect_get(values, count, incoming->src.ssa);
               matches++;
            }
         }
         if (matches != 1)
            AIR_EFFECT_FAIL(AIR_EFFECT_INVALID, "PHI predecessor does not match executed edge");
         if (!source)
            AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "PHI source is not defined on executed edge");
         if (source->components != phi->def.num_components || source->bits != phi->def.bit_size)
            AIR_EFFECT_FAIL(AIR_EFFECT_INVALID, "PHI source shape mismatch");
         pending[phi->def.index] = *source;
      }
      /* Publish only after ALL incoming PHIs have read the old state. */
      nir_foreach_phi(phi, block)
         values[phi->def.index] = pending[phi->def.index];
      nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_phi)
            continue;
         if (run.instructions == budget)
            AIR_EFFECT_FAIL(AIR_EFFECT_BUDGET, "test execution budget exhausted at instruction");
         run.instructions++;
         nir_def *def = nir_instr_def(instr);
         struct air_effect_value *dest = NULL;
         if (def) {
            if (!air_effect_shape(def) || def->index >= count)
               AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "unsupported executed value shape");
            dest = &values[def->index];
            *dest = (struct air_effect_value){.known = true,
               .components = def->num_components, .bits = def->bit_size};
         }
         switch (instr->type) {
         case nir_instr_type_load_const:
            memcpy(dest->lanes, nir_instr_as_load_const(instr)->value,
                   dest->components * sizeof(*dest->lanes));
            break;
         case nir_instr_type_alu: {
            nir_alu_instr *alu = nir_instr_as_alu(instr);
            const nir_op_info *info = &nir_op_infos[alu->op];
            if (!air_effect_integer_type(info->output_type) ||
                alu->no_signed_wrap || alu->no_unsigned_wrap)
               AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "noninteger or restricted ALU semantics");
            nir_const_value operands[NIR_ALU_MAX_INPUTS][NIR_MAX_VEC_COMPONENTS] = {0};
            nir_const_value *sources[NIR_ALU_MAX_INPUTS] = {0};
            unsigned bit_size = nir_alu_type_get_type_size(info->output_type) ? 0 : dest->bits;
            for (unsigned s = 0; s < info->num_inputs; s++) {
               if (!air_effect_integer_type(info->input_types[s]))
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "noninteger ALU input semantics");
               const struct air_effect_value *source = air_effect_get(values, count, alu->src[s].src.ssa);
               if (!source)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "ALU input is not defined");
               if (!bit_size && !nir_alu_type_get_type_size(info->input_types[s]))
                  bit_size = source->bits;
               unsigned components = nir_ssa_alu_instr_src_components(alu, s);
               if (components > NIR_MAX_VEC_COMPONENTS)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "ALU input component count");
               for (unsigned lane = 0; lane < components; lane++) {
                  unsigned swizzle = alu->src[s].swizzle[lane];
                  if (swizzle >= source->components)
                     AIR_EFFECT_FAIL(AIR_EFFECT_INVALID, "ALU swizzle outside source");
                  operands[s][lane] = source->lanes[swizzle];
               }
               sources[s] = operands[s];
            }
            uint16_t poison = 0;
            nir_eval_const_opcode(alu->op, dest->lanes, &poison, dest->components,
                                  bit_size ? bit_size : 32, sources,
                                  shader->info.float_controls_execution_mode);
            if (poison)
               AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "Mesa ALU evaluation reports poison");
            break;
         }
         case nir_instr_type_intrinsic: {
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            if (memory && (intrinsic->intrinsic == nir_intrinsic_load_local_invocation_index ||
                           intrinsic->intrinsic == nir_intrinsic_load_workgroup_id ||
                           intrinsic->intrinsic == nir_intrinsic_load_global_invocation_id)) {
               const uint16_t *size = shader->info.workgroup_size;
               uint32_t local[3] = {memory->local_index % size[0],
                                    memory->local_index / size[0] % size[1],
                                    memory->local_index / size[0] / size[1]};
               for (unsigned lane = 0; lane < dest->components; lane++) {
                  uint32_t value = memory->workgroup[lane];
                  if (intrinsic->intrinsic == nir_intrinsic_load_local_invocation_index)
                     value = memory->local_index;
                  else if (intrinsic->intrinsic == nir_intrinsic_load_global_invocation_id)
                     value = value * size[lane] + local[lane];
                  dest->lanes[lane] = nir_const_value_for_uint(value, dest->bits);
               }
               break;
            }
            if (memory && (intrinsic->intrinsic == nir_intrinsic_load_global ||
                           intrinsic->intrinsic == nir_intrinsic_load_push_constant)) {
               const struct air_effect_value *at = air_effect_get(values, count, intrinsic->src[0].ssa);
               if (!at || at->components != 1)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "load address is not defined");
               uint64_t address = nir_const_value_as_uint(at->lanes[0], at->bits);
               bool global = intrinsic->intrinsic == nir_intrinsic_load_global;
               size_t offset;
               bool within = global ?
                  air_effect_within(memory->size, memory->base, address, dest, &offset) :
                  air_effect_within(memory->push_size, 0,
                                    address + (uint64_t)nir_intrinsic_base(intrinsic), dest, &offset);
               if (!within)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "load outside the test memory");
               air_effect_read((global ? memory->bytes : memory->push) + offset, dest);
               break;
            }
            /* Constant data is the shader's own bytes. */
            if (intrinsic->intrinsic == nir_intrinsic_load_constant) {
               const struct air_effect_value *at = air_effect_get(values, count, intrinsic->src[0].ssa);
               size_t offset;
               if (!at || at->components != 1)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "constant load offset is not defined");
               if (!air_effect_within(shader->constant_data_size, 0,
                                      nir_const_value_as_uint(at->lanes[0], at->bits) +
                                         (uint64_t)nir_intrinsic_base(intrinsic),
                                      dest, &offset))
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "load outside the shader's constant data");
               air_effect_read((const uint8_t *)shader->constant_data + offset, dest);
               break;
            }
            if (memory && memory->images &&
                (intrinsic->intrinsic == nir_intrinsic_image_deref_size ||
                 intrinsic->intrinsic == nir_intrinsic_image_deref_load ||
                 intrinsic->intrinsic == nir_intrinsic_image_deref_store)) {
               const struct air_effect_value *handle = air_effect_get(values, count, intrinsic->src[0].ssa);
               if (!handle || handle->components != 1)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "image is not defined");
               uint64_t index = nir_const_value_as_uint(handle->lanes[0], handle->bits);
               if (index >= memory->image_count)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "image outside the test images");
               const struct air_effect_image *image = &memory->images[index];
               if (intrinsic->intrinsic == nir_intrinsic_image_deref_size) {
                  const uint32_t size[3] = {image->width, image->height, 1};
                  for (unsigned lane = 0; lane < dest->components && lane < 3; lane++)
                     dest->lanes[lane] = nir_const_value_for_uint(size[lane], dest->bits);
                  break;
               }
               bool load = intrinsic->intrinsic == nir_intrinsic_image_deref_load;
               const struct air_effect_value *coord = air_effect_get(values, count, intrinsic->src[1].ssa);
               /* A single-sampled image's access may leave its sample
                * undefined. */
               const struct air_effect_value *sample = air_effect_get(values, count, intrinsic->src[2].ssa);
               const struct air_effect_value *texel =
                  load ? dest : air_effect_get(values, count, intrinsic->src[3].ssa);
               if (!coord || !texel || coord->components < 2)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "image access is not defined");
               uint64_t x = nir_const_value_as_uint(coord->lanes[0], coord->bits);
               uint64_t y = nir_const_value_as_uint(coord->lanes[1], coord->bits);
               if (x >= image->width || y >= image->height ||
                   (nir_intrinsic_image_array(intrinsic) &&
                    nir_const_value_as_uint(coord->lanes[2], coord->bits)) ||
                   (sample && nir_const_value_as_uint(sample->lanes[0], sample->bits)))
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "image access outside the test image");
               if (texel->components != 4 || texel->bits != 32)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "image texel other than four words");
               uint32_t *words = image->texels + 4 * (y * image->width + x);
               for (unsigned lane = 0; lane < 4; lane++) {
                  if (load)
                     dest->lanes[lane] = nir_const_value_for_uint(words[lane], 32);
                  else
                     words[lane] = (uint32_t)nir_const_value_as_uint(texel->lanes[lane], 32);
               }
               break;
            }
            /* Scratch memory is the invocation's own, so its stores are
             * no effects. */
            if (memory && (intrinsic->intrinsic == nir_intrinsic_load_scratch ||
                           intrinsic->intrinsic == nir_intrinsic_store_scratch)) {
               bool load = intrinsic->intrinsic == nir_intrinsic_load_scratch;
               const struct air_effect_value *stored =
                  load ? dest : air_effect_get(values, count, intrinsic->src[0].ssa);
               const struct air_effect_value *at =
                  air_effect_get(values, count, intrinsic->src[load ? 0 : 1].ssa);
               size_t offset;
               if (!stored || !at || at->components != 1)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "scratch access is not defined");
               if (!air_effect_within(memory->scratch_size, 0,
                                      nir_const_value_as_uint(at->lanes[0], at->bits), stored,
                                      &offset))
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "scratch access outside the test memory");
               if (load)
                  air_effect_read(memory->scratch + offset, dest);
               else
                  air_effect_write(memory->scratch + offset, stored);
               break;
            }
            bool ssbo = intrinsic->intrinsic == nir_intrinsic_store_ssbo;
            bool shared = intrinsic->intrinsic == nir_intrinsic_store_shared;
            if (!ssbo && !shared && intrinsic->intrinsic != nir_intrinsic_store_global)
               AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "unevaluated intrinsic on executed path");
            const struct air_effect_value *stored = air_effect_get(values, count, intrinsic->src[0].ssa);
            const struct air_effect_value *address = air_effect_get(values, count, intrinsic->src[ssbo ? 2 : 1].ssa);
            const struct air_effect_value *slot = ssbo ? air_effect_get(values, count, intrinsic->src[1].ssa) : NULL;
            if (!stored || !address || (ssbo && !slot))
               AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "store source is not defined");
            if (stored->bits == 1 || nir_intrinsic_write_mask(intrinsic) != BITFIELD_MASK(stored->components) ||
                address->components != 1 || (address->bits != 32 && address->bits != 64) ||
                (ssbo && (slot->components != 1 || slot->bits != 32)))
               AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "partial/sub-byte store or invalid address shape");
            if (run.stores == capacity)
               AIR_EFFECT_FAIL(AIR_EFFECT_TRACE_FULL, "effect trace capacity exhausted");
            struct air_effect_store *effect = &trace[run.stores++];
            *effect = (struct air_effect_store){.ssbo = ssbo, .shared = shared,
               .slot = slot ? nir_const_value_as_uint(slot->lanes[0], slot->bits) : 0,
               .address = nir_const_value_as_uint(address->lanes[0], address->bits) +
                          (shared ? (uint64_t)nir_intrinsic_base(intrinsic) : 0),
               .components = stored->components, .bits = stored->bits};
            memcpy(effect->values, stored->lanes, stored->components * sizeof(*effect->values));
            size_t offset;
            if (memory && !ssbo && !shared &&
                air_effect_within(memory->size, memory->base, effect->address, stored, &offset))
               air_effect_write(memory->bytes + offset, stored);
            break;
         }
         case nir_instr_type_jump: {
            nir_jump_type jump = nir_instr_as_jump(instr)->type;
            if (jump != nir_jump_return && jump != nir_jump_break && jump != nir_jump_continue)
               AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "unevaluated jump kind");
            break;
         }
         case nir_instr_type_undef:
            /* Only a use of the value is undefined. */
            dest->known = false;
            break;
         case nir_instr_type_deref: {
            /* An image variable, or an element of an array of them: its
             * index among the test images. */
            nir_deref_instr *deref = nir_instr_as_deref(instr);
            nir_deref_instr *parent = nir_deref_instr_parent(deref);
            bool element = deref->deref_type == nir_deref_type_array && parent &&
                           parent->deref_type == nir_deref_type_var;
            if (!memory || !memory->images || !nir_deref_mode_is(deref, nir_var_image) ||
                (!element && deref->deref_type != nir_deref_type_var))
               AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "unevaluated deref on executed path");
            uint64_t index = 0;
            if (element) {
               const struct air_effect_value *at = air_effect_get(values, count, deref->arr.index.ssa);
               if (!at || at->components != 1)
                  AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "image index is not defined");
               index = nir_const_value_as_uint(at->lanes[0], at->bits);
            }
            dest->lanes[0] = nir_const_value_for_uint(index, dest->bits);
            break;
         }
         default:
            AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "unevaluated instruction on executed path");
         }
      }
      nir_block *next = block->successors[0];
      /* A terminal jump overrides any unreachable lexical CF after it. */
      nir_if *branch = nir_block_ends_in_jump(block) ? NULL : nir_block_get_following_if(block);
      if (branch) {
         const struct air_effect_value *condition = air_effect_get(values, count, branch->condition.ssa);
         if (!condition)
            AIR_EFFECT_FAIL(AIR_EFFECT_UNDEFINED, "branch condition is not defined");
         if (condition->bits != 1 || condition->components != 1)
            AIR_EFFECT_FAIL(AIR_EFFECT_UNSUPPORTED, "branch condition requires scalar bool");
         next = condition->lanes[0].b ? nir_if_first_then_block(branch) : nir_if_first_else_block(branch);
         if (next != block->successors[0] && next != block->successors[1])
            AIR_EFFECT_FAIL(AIR_EFFECT_INVALID, "branch target is not an actual successor");
      }
      if (!next)
         AIR_EFFECT_FAIL(AIR_EFFECT_INVALID, "executed block has no successor");
      predecessor = block;
      block = next;
   }
   run.status = AIR_EFFECT_COMPLETE;
   run.detail = "reached implementation end block";
done:
   free(pending);
   free(values);
   return run;
#undef AIR_EFFECT_FAIL
}

static struct air_effect_run
air_effect_execute(nir_shader *shader, unsigned budget,
                    struct air_effect_store *trace, unsigned capacity)
{
   return air_effect_execute_in(shader, budget, trace, capacity, NULL);
}

#endif
