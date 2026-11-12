/*
 * Libraries, functions and what they reflect. Metal's own reflection classes
 * have no public initializers, so these answer the same selectors themselves.
 */
#include "Bundle.h"

static NSString *text_at(const uint8_t *bytes, uint32_t offset, uint32_t length)
{
	return [[NSString alloc] initWithBytes:bytes + offset length:length encoding:NSUTF8StringEncoding];
}

/* An `MTLDataType`'s packed bytes, of the scalars and vectors constants can be. */
static NSUInteger data_type_bytes(NSUInteger type)
{
	static const struct {
		NSUInteger first, element;
	} kinds[] = {
		{MTLDataTypeFloat, 4}, {MTLDataTypeHalf, 2},  {MTLDataTypeInt, 4},
		{MTLDataTypeUInt, 4},  {MTLDataTypeShort, 2}, {MTLDataTypeUShort, 2},
		{MTLDataTypeChar, 1},  {MTLDataTypeUChar, 1}, {MTLDataTypeBool, 1},
		{MTLDataTypeLong, 8},  {MTLDataTypeULong, 8},
	};
	for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		if (type >= kinds[i].first && type < kinds[i].first + 4) {
			return (type - kinds[i].first + 1) * kinds[i].element;
		}
	}
	return 0;
}

@implementation StelaGPUAttribute
@end

@implementation StelaGPUFunctionConstant
@end

Class objc_getClass(const char *name);

@implementation StelaGPUType

- (NSUInteger)dataType
{
	return _dataType;
}

/* Metal gives an array of textures or samplers no stride, since its
 * elements are resources rather than bytes; the encoder still steps
 * through their slots. */
- (NSUInteger)stride
{
	NSUInteger element = self.elementType;
	return element == MTLDataTypeTexture || element == MTLDataTypeSampler ? 0 : _stride;
}

/* One class serves every type, each of which is the kind of Metal's class
 * its data type names: what applications tell types apart by. */
- (BOOL)isKindOfClass:(Class)class
{
	const char *name = _dataType == MTLDataTypeStruct  ? "MTLStructType" :
			   _dataType == MTLDataTypeArray   ? "MTLArrayType" :
			   _dataType == MTLDataTypePointer ? "MTLPointerType" :
			   _dataType == MTLDataTypeTexture ? "MTLTextureReferenceType" :
							     NULL;
	if (class && (class == objc_getClass("MTLType") || (name && class == objc_getClass(name)))) {
		return YES;
	}
	return [super isKindOfClass:class];
}

- (NSArray *)members
{
	return _members;
}

- (id)memberByName:(NSString *)name
{
	for (NSUInteger i = 0; i < _members.count; i++) {
		StelaGPUMember *member = [_members objectAtIndex:i];
		if ([member.name isEqualToString:name]) {
			return member;
		}
	}
	return nil;
}

/* A pointer to a scalar or a vector has no element type. */
- (id)elementArrayType
{
	return _element && _element->_dataType == MTLDataTypeArray ? _element : nil;
}

- (id)elementStructType
{
	return _element && _element->_dataType == MTLDataTypeStruct ? _element : nil;
}

- (id)elementPointerType
{
	return _element && _element->_dataType == MTLDataTypePointer ? _element : nil;
}

- (id)elementTextureReferenceType
{
	return _element && _element->_dataType == MTLDataTypeTexture ? _element : nil;
}

- (id)elementIndirectCommandBufferType
{
	return nil;
}

@end

@implementation StelaGPUMember

- (id)structType
{
	return _type && _type->_dataType == MTLDataTypeStruct ? _type : nil;
}

- (id)arrayType
{
	return _type && _type->_dataType == MTLDataTypeArray ? _type : nil;
}

- (id)pointerType
{
	return _type && _type->_dataType == MTLDataTypePointer ? _type : nil;
}

- (id)textureReferenceType
{
	return _type && _type->_dataType == MTLDataTypeTexture ? _type : nil;
}

- (id)tensorReferenceType
{
	return nil;
}

@end

@implementation StelaGPUBinding

- (BOOL)isUsed
{
	return _used;
}

/* One class holds every kind of binding; each conforms to its own kind's
 * protocol, as applications tell the kinds apart by. */
- (BOOL)conformsToProtocol:(id)protocol
{
	if (protocol == @protocol(MTLBufferBinding)) {
		return self.type == MTLBindingTypeBuffer;
	}
	if (protocol == @protocol(MTLTextureBinding)) {
		return self.type == MTLBindingTypeTexture;
	}
	if (protocol == @protocol(MTLThreadgroupBinding)) {
		return self.type == MTLBindingTypeThreadgroupMemory;
	}
	if (protocol == @protocol(MTLObjectPayloadBinding)) {
		return self.type == MTLBindingTypeObjectPayload;
	}
	return [super conformsToProtocol:protocol];
}

/* Every binding here is one of the function's own arguments. */
- (BOOL)isArgument
{
	return YES;
}

/* `MTLArgument`, which the deprecated reflection answers with the same
 * objects: its type and index values are its binding's. */
- (BOOL)isActive
{
	return _used;
}

- (id)bufferStructType
{
	return _typeInfo ? _typeInfo->_element : nil;
}

- (id)bufferPointerType
{
	return _typeInfo;
}

@end

/* Runs a call whose answer's length is variable until its buffer held it. */
static void *read_variable(StelaGate *gate, uint32_t operation, void *request, size_t request_bytes, StelaSpan *out,
			   void *response, size_t response_bytes, const uint64_t *length)
{
	size_t capacity = 16 * 1024;
	for (;;) {
		void *bytes = calloc(1, capacity);
		if (!bytes) {
			return NULL;
		}
		*out = stela_span(bytes, capacity);
		StelaSpans spans = {.writes = out, .write_count = 1};
		StelaFailure failure;
		uint32_t status = stela_gate_call(gate, operation, request, request_bytes, response,
						  response_bytes, spans, &failure);
		if (status != StelaStatusOk) {
			stela_report("a service answer", &failure);
			free(bytes);
			return NULL;
		}
		if (*length <= capacity) {
			return bytes;
		}
		capacity = *length;
		free(bytes);
	}
}

@implementation StelaGPUReflection

static StelaGPUType *type_at(NSArray *types, uint32_t index)
{
	return index == STELA_NO_TYPE ? nil : [types objectAtIndex:index];
}

+ (NSArray *)bindingsOfFunction:(StelaGPUFunction *)function
{
	StelaFunctionBindingsRequest request = {.function = function->_handle};
	StelaFunctionBindingsResponse response = {};
	const uint8_t *bytes = read_variable(&function->_device->_gate, StelaOperationFunctionBindings, &request,
					     sizeof(request), &request.out, &response, sizeof(response),
					     &response.length);
	if (!bytes) {
		return [NSArray array];
	}
	const StelaBindingInfo *bindings = (const void *)bytes;
	const StelaTypeInfo *types = (const void *)(bindings + response.binding_count);
	const StelaMemberInfo *members = (const void *)(types + response.type_count);

	/* Each type comes after its element and members. */
	NSMutableArray *objects = [NSMutableArray arrayWithCapacity:response.type_count + 1];
	for (uint32_t i = 0; i < response.type_count; i++) {
		const StelaTypeInfo *info = &types[i];
		StelaGPUType *type = [StelaGPUType new];
		type->_dataType = info->data_type;
		type.elementType = info->element_data_type;
		type->_element = type_at(objects, info->element);
		type.arrayLength = info->length;
		type->_stride = info->stride;
		type.argumentIndexStride = info->argument_index_stride;
		type.access = info->access;
		type.alignment = info->alignment;
		type.dataSize = info->data_size;
		type.elementIsArgumentBuffer = info->element_is_argument_buffer != 0;
		type.textureType = info->texture_type;
		type.textureDataType = info->element_data_type;
		type.isDepthTexture = info->depth != 0;
		NSMutableArray *list = [NSMutableArray arrayWithCapacity:info->member_count];
		for (uint32_t j = 0; j < info->member_count; j++) {
			const StelaMemberInfo *record = &members[info->first_member + j];
			StelaGPUMember *member = [StelaGPUMember new];
			member.name = text_at(bytes, record->name, record->name_length);
			member.dataType = record->data_type;
			member.offset = record->offset;
			member.argumentIndex = record->argument_index;
			member->_type = type_at(objects, record->ty);
			[list addObject:member];
		}
		type->_members = list;
		[objects addObject:type];
	}

	NSMutableArray *list = [NSMutableArray arrayWithCapacity:response.binding_count];
	for (uint32_t i = 0; i < response.binding_count; i++) {
		const StelaBindingInfo *info = &bindings[i];
		StelaGPUBinding *binding = [StelaGPUBinding new];
		binding.name = text_at(bytes, info->name, info->name_length);
		binding.type = info->binding_type;
		binding.access = info->access;
		/* A payload has no argument table slot, which Metal reports as UINT32_MAX. */
		binding.index = info->binding_type == MTLBindingTypeObjectPayload ? UINT32_MAX : info->index;
		binding->_used = info->used != 0;
		binding.arrayLength = info->array_length;
		binding.bufferAlignment = info->alignment;
		binding.threadgroupMemoryAlignment = info->alignment;
		binding.objectPayloadAlignment = info->alignment;
		binding.bufferDataSize = info->data_size;
		binding.threadgroupMemoryDataSize = info->data_size;
		binding.objectPayloadDataSize = info->data_size;
		binding->_typeInfo = type_at(objects, info->ty);
		binding.bufferDataType = binding->_typeInfo ? binding->_typeInfo.elementType : MTLDataTypeNone;
		binding.textureType = binding->_typeInfo ? binding->_typeInfo.textureType : 0;
		binding.textureDataType = binding->_typeInfo ? binding->_typeInfo.textureDataType : MTLDataTypeNone;
		binding.isDepthTexture = binding->_typeInfo ? binding->_typeInfo.isDepthTexture : NO;
		[list addObject:binding];
	}
	free((void *)bytes);
	return list;
}

@end

/* Argument encoders: an index's offset, and how far an array's elements stride. */
typedef struct {
	NSUInteger index, offset;
} StelaArgumentSlot;

/* `NSDataReadingMappedIfSafe`: a system library runs to hundreds of megabytes. */
#define STELA_DATA_MAPPED 1

/* A universal library's header, big endian: magic, then `count` slices of cpu
 * type, subtype, offset, size and alignment. Its AIR slice is the one a device
 * other than Apple's own compiles; the rest are code for Apple's GPUs. */
#define UNIVERSAL_MAGIC 0xcafebabeu
#define UNIVERSAL_SLICE_WORDS 5

static uint32_t big_endian(const uint8_t *bytes, size_t word)
{
	uint32_t value;
	memcpy(&value, bytes + word * sizeof(value), sizeof(value));
	return __builtin_bswap32(value);
}

/* Narrows a universal library to its AIR slice; any other library stays as it is. */
static void air_slice(const void **bytes, NSUInteger *length)
{
	const uint8_t *data = *bytes;
	if (*length < 2 * sizeof(uint32_t) || big_endian(data, 0) != UNIVERSAL_MAGIC) {
		return;
	}
	size_t count = big_endian(data, 1);
	if (count > (*length / sizeof(uint32_t) - 2) / UNIVERSAL_SLICE_WORDS) {
		return;
	}
	for (size_t i = 0; i < count; i++) {
		size_t word = 2 + i * UNIVERSAL_SLICE_WORDS;
		uint64_t offset = big_endian(data, word + 2), size = big_endian(data, word + 3);
		if (big_endian(data, word) == CPU_TYPE_AIR64 && offset + size <= *length) {
			*bytes = data + offset;
			*length = size;
			return;
		}
	}
}

@implementation StelaGPUArgumentEncoder (Sizes)

- (NSUInteger)encodedLength
{
	return _encodedLength;
}

- (NSUInteger)alignment
{
	return _alignment;
}

@end

@implementation StelaGPUArgumentEncoder {
	StelaGPUDevice *_device;
	NSMutableData *_slotBytes;
	uint8_t *_base;
	id _buffer;
	/* The pointers to structs, and the index of each. */
	NSMutableArray *_pointers;
	NSMutableData *_pointerIndices;
}

- (instancetype)initWithDevice:(StelaGPUDevice *)device
		encodedLength:(NSUInteger)length
		    alignment:(NSUInteger)alignment
{
	self = [super init];
	if (self) {
		_device = device;
		_encodedLength = length;
		_alignment = alignment;
		_slotBytes = [NSMutableData dataWithLength:0];
		_pointers = [NSMutableArray arrayWithCapacity:1];
		_pointerIndices = [NSMutableData dataWithLength:0];
	}
	return self;
}

- (id)device
{
	return _device;
}

- (void)addSlotAt:(NSUInteger)index offset:(NSUInteger)offset
{
	StelaArgumentSlot slot = {index, offset};
	[_slotBytes appendBytes:&slot length:sizeof(slot)];
}

/* Adds the arguments of `type`, at `offset` from `index`. */
- (void)addType:(StelaGPUType *)type offset:(NSUInteger)offset index:(NSUInteger)index
{
	if (type->_dataType == MTLDataTypeArray) {
		for (NSUInteger i = 0; i < type.arrayLength; i++) {
			NSUInteger at = offset + i * type->_stride;
			NSUInteger slot = index + i * type.argumentIndexStride;
			if (type->_element) {
				[self addType:type->_element offset:at index:slot];
			} else {
				[self addSlotAt:slot offset:at];
			}
		}
		return;
	}
	if (type->_dataType != MTLDataTypeStruct) {
		/* A pointer to a struct is encoded through an encoder of its own. */
		if (type->_dataType == MTLDataTypePointer && type->_element &&
		    type->_element->_dataType == MTLDataTypeStruct) {
			[_pointers addObject:type];
			[_pointerIndices appendBytes:&index length:sizeof(index)];
		}
		[self addSlotAt:index offset:offset];
		return;
	}
	for (NSUInteger i = 0; i < type->_members.count; i++) {
		StelaGPUMember *member = [type->_members objectAtIndex:i];
		if (member->_type) {
			[self addType:member->_type offset:offset + member.offset index:index + member.argumentIndex];
		} else {
			[self addSlotAt:index + member.argumentIndex offset:offset + member.offset];
		}
	}
}

- (uint8_t *)slot:(NSUInteger)index
{
	const StelaArgumentSlot *slots = _slotBytes.bytes;
	NSUInteger count = _slotBytes.length / sizeof(*slots);
	for (NSUInteger i = 0; i < count; i++) {
		if (slots[i].index == index) {
			return _base + slots[i].offset;
		}
	}
	return NULL;
}

- (void)store:(uint64_t)value atIndex:(NSUInteger)index
{
	uint8_t *at = [self slot:index];
	if (at) {
		memcpy(at, &value, sizeof(value));
	}
}

- (void)setArgumentBuffer:(StelaGPUBuffer *)buffer offset:(NSUInteger)offset
{
	_buffer = buffer;
	_base = (uint8_t *)buffer->_contents + offset;
}

- (void)setArgumentBuffer:(StelaGPUBuffer *)buffer startOffset:(NSUInteger)offset arrayElement:(NSUInteger)element
{
	[self setArgumentBuffer:buffer offset:offset + element * _encodedLength];
}

- (void)setBuffer:(StelaGPUBuffer *)buffer offset:(NSUInteger)offset atIndex:(NSUInteger)index
{
	[self store:buffer ? buffer->_gpuAddress + offset : 0 atIndex:index];
}

- (void)setBuffers:(const id __unsafe_unretained[])buffers
	   offsets:(const NSUInteger[])offsets
	 withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setBuffer:buffers[i] offset:offsets[i] atIndex:range.location + i];
	}
}

- (void)setTexture:(StelaGPUTexture *)texture atIndex:(NSUInteger)index
{
	[self store:texture ? texture->_resourceID : 0 atIndex:index];
}

- (void)setTextures:(const id __unsafe_unretained[])textures withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setTexture:textures[i] atIndex:range.location + i];
	}
}

- (void)setSamplerState:(StelaGPUSampler *)sampler atIndex:(NSUInteger)index
{
	[self store:sampler ? sampler->_resourceID : 0 atIndex:index];
}

- (void)setSamplerStates:(const id __unsafe_unretained[])samplers withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setSamplerState:samplers[i] atIndex:range.location + i];
	}
}

- (void)setRenderPipelineState:(StelaGPURenderPipeline *)pipeline atIndex:(NSUInteger)index
{
	[self store:pipeline ? pipeline->_resourceID : 0 atIndex:index];
}

- (void)setRenderPipelineStates:(const id __unsafe_unretained[])pipelines withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setRenderPipelineState:pipelines[i] atIndex:range.location + i];
	}
}

- (void)setComputePipelineState:(StelaGPUComputePipeline *)pipeline atIndex:(NSUInteger)index
{
	[self store:pipeline ? pipeline->_resourceID : 0 atIndex:index];
}

- (void)setComputePipelineStates:(const id __unsafe_unretained[])pipelines withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setComputePipelineState:pipelines[i] atIndex:range.location + i];
	}
}

- (void)setIndirectCommandBuffer:(StelaGPUIndirectCommandBuffer *)buffer atIndex:(NSUInteger)index
{
	[self store:buffer ? [buffer gpuResourceID]._impl : 0 atIndex:index];
}

- (void)setIndirectCommandBuffers:(const id __unsafe_unretained[])buffers withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setIndirectCommandBuffer:buffers[i] atIndex:range.location + i];
	}
}

/* A table's gpuResourceID, the address its argument binds. */
- (void)setVisibleFunctionTable:(StelaGPUFunctionTable *)table atIndex:(NSUInteger)index
{
	[self store:table ? table->_gpuAddress : 0 atIndex:index];
}

- (void)setVisibleFunctionTables:(const id __unsafe_unretained[])tables withRange:(NSRange)range
{
	for (NSUInteger i = 0; i < range.length; i++) {
		[self setVisibleFunctionTable:tables[i] atIndex:range.location + i];
	}
}

- (void *)constantDataAtIndex:(NSUInteger)index
{
	return [self slot:index];
}

/* The encoder of the struct the pointer at `index` points to, which a
 * pointer type sizes and aligns as its element; nil for any other index. */
- (id)newArgumentEncoderForBufferAtIndex:(NSUInteger)index
{
	const NSUInteger *indices = _pointerIndices.bytes;
	StelaGPUType *pointer = nil;
	for (NSUInteger i = 0; i < _pointers.count; i++) {
		if (indices[i] == index) {
			pointer = [_pointers objectAtIndex:i];
		}
	}
	if (!pointer) {
		return nil;
	}
	StelaGPUArgumentEncoder *encoder = [[StelaGPUArgumentEncoder alloc] initWithDevice:_device
									     encodedLength:pointer.dataSize
										 alignment:pointer.alignment];
	[encoder addType:pointer->_element offset:0 index:0];
	return encoder;
}

@end

/* The encoder of the argument buffer a reflected buffer binding points to. */
static id encoder_of_binding(StelaGPUDevice *device, StelaGPUBinding *binding)
{
	StelaGPUType *structure = binding->_typeInfo ? binding->_typeInfo->_element : nil;
	if (!structure) {
		return nil;
	}
	StelaGPUArgumentEncoder *encoder = [[StelaGPUArgumentEncoder alloc] initWithDevice:device
									     encodedLength:binding.bufferDataSize
										 alignment:binding.bufferAlignment];
	[encoder addType:structure offset:0 index:0];
	return encoder;
}

@implementation StelaGPUFunction

- (instancetype)initWithLibrary:(StelaGPULibrary *)library handle:(uint64_t)handle name:(NSString *)name
{
	self = [super initWithDevice:library->_device handle:handle];
	if (!self) {
		return nil;
	}
	_library = library;
	_name = [name copy];
	StelaFunctionReflectionRequest request = {.function = handle};
	StelaFunctionReflectionResponse response = {};
	const uint8_t *bytes = read_variable(&_device->_gate, StelaOperationFunctionReflection, &request,
					     sizeof(request), &request.out, &response, sizeof(response),
					     &response.length);
	if (!bytes) {
		return nil;
	}
	_functionType = response.function_type;
	_patchType = response.patch_type;
	_patchControlPointCount = response.patch_control_points ? (NSInteger)response.patch_control_points : -1;
	memcpy(_bitCodeHash, response.bitcode_hash, sizeof(_bitCodeHash));

	const StelaConstantInfo *constants = (const void *)bytes;
	const StelaAttributeInfo *attributes = (const void *)(constants + response.constant_count);
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
	for (uint32_t i = 0; i < response.constant_count; i++) {
		StelaGPUFunctionConstant *constant = [StelaGPUFunctionConstant new];
		constant.name = text_at(bytes, constants[i].name, constants[i].name_length);
		constant.type = constants[i].data_type;
		constant.index = constants[i].index;
		constant.required = constants[i].required != 0;
		[dictionary setObject:constant forKey:constant.name];
	}
	_constants = dictionary;
	NSMutableArray *list = [NSMutableArray arrayWithCapacity:response.attribute_count];
	for (uint32_t i = 0; i < response.attribute_count; i++) {
		StelaGPUAttribute *attribute = [StelaGPUAttribute new];
		attribute.name = text_at(bytes, attributes[i].name, attributes[i].name_length);
		attribute.attributeType = attributes[i].data_type;
		attribute.attributeIndex = attributes[i].index;
		attribute.active = attributes[i].active != 0;
		/* A post-tessellation function's control points are not per patch. */
		attribute.patchControlPointData = attributes[i].patch_control_point != 0;
		attribute.patchData = _patchType != 0 && !attribute.patchControlPointData;
		[list addObject:attribute];
	}
	_attributes = list;
	free((void *)bytes);
	return self;
}

- (NSString *)name
{
	return _name;
}

- (NSUInteger)functionType
{
	return _functionType;
}

- (NSUInteger)patchType
{
	return _patchType;
}

- (NSInteger)patchControlPointCount
{
	return _patchControlPointCount;
}

- (NSArray *)vertexAttributes
{
	return _functionType == MTLFunctionTypeVertex ? _attributes : nil;
}

/* A vertex function's attributes are its stage inputs too. */
- (NSArray *)stageInputAttributes
{
	return _functionType == MTLFunctionTypeVertex || _functionType == MTLFunctionTypeKernel ? _attributes : nil;
}

- (NSDictionary *)functionConstantsDictionary
{
	return _constants;
}

- (NSUInteger)options
{
	return 0;
}

- (id)newArgumentEncoderWithBufferIndex:(NSUInteger)index
{
	NSArray *bindings = [StelaGPUReflection bindingsOfFunction:self];
	for (NSUInteger i = 0; i < bindings.count; i++) {
		StelaGPUBinding *binding = [bindings objectAtIndex:i];
		if (binding.type == MTLBindingTypeBuffer && binding.index == index) {
			return encoder_of_binding(_device, binding);
		}
	}
	return nil;
}

- (id)newArgumentEncoderWithBufferIndex:(NSUInteger)index reflection:(id *)reflection
{
	if (reflection) {
		*reflection = nil;
		NSArray *bindings = [StelaGPUReflection bindingsOfFunction:self];
		for (NSUInteger i = 0; i < bindings.count; i++) {
			StelaGPUBinding *binding = [bindings objectAtIndex:i];
			if (binding.type == MTLBindingTypeBuffer && binding.index == index) {
				*reflection = binding;
			}
		}
	}
	return [self newArgumentEncoderWithBufferIndex:index];
}

@end

@implementation StelaGPULibrary

/* The names `operation` lists of the library. */
- (NSArray *)namesFrom:(uint32_t)operation
{
	StelaLibraryFunctionNamesRequest request = {.library = _handle};
	StelaLength response = {};
	const char *names = read_variable(&_device->_gate, operation, &request, sizeof(request), &request.out,
					  &response, sizeof(response), &response.length);
	NSMutableArray *list = [NSMutableArray arrayWithCapacity:8];
	if (names) {
		for (size_t at = 0; at < response.length; at += strlen(names + at) + 1) {
			[list addObject:[NSString stringWithUTF8String:names + at]];
		}
		free((void *)names);
	}
	return list;
}

- (NSArray *)functionNames
{
	return [self namesFrom:StelaOperationLibraryFunctionNames];
}

/* Metal's SPI: the functions the library declares extern, which name none of
 * its own and which Core Image looks its stitchable functions up by. */
- (NSArray *)externFunctionNames
{
	return [self namesFrom:StelaOperationLibraryExternFunctionNames];
}

/* Where an install name puts a dynamic library, into path: beside the
 * library at loader that links it, beside the executable, or at an absolute
 * path. NO for a name that says none of those. */
static BOOL install_path(const char *name, NSString *loader, char *path, size_t size)
{
	static const char loaderPath[] = "@loader_path/", executablePath[] = "@executable_path/";
	char directory[1024];
	const char *rest;
	if (!strncmp(name, loaderPath, sizeof(loaderPath) - 1)) {
		if (!loader || strlcpy(directory, loader.UTF8String, sizeof(directory)) >= sizeof(directory)) {
			return NO;
		}
		rest = name + sizeof(loaderPath) - 1;
	} else if (!strncmp(name, executablePath, sizeof(executablePath) - 1)) {
		uint32_t length = sizeof(directory);
		if (_NSGetExecutablePath(directory, &length) != 0) {
			return NO;
		}
		rest = name + sizeof(executablePath) - 1;
	} else {
		return name[0] == '/' && strlcpy(path, name, size) < size;
	}
	char *slash = strrchr(directory, '/');
	if (!slash) {
		return NO;
	}
	slash[1] = 0;
	return (size_t)snprintf(path, size, "%s%s", directory, rest) < size;
}

- (NSArray *)libraries:(NSArray *)preloaded withLinked:(NSError **)error
{
	NSMutableArray *libraries = [NSMutableArray arrayWithCapacity:preloaded.count + 1];
	for (NSUInteger i = 0; i < preloaded.count; i++) {
		[libraries addObject:preloaded[i]];
	}
	return [self link:libraries error:error] ? libraries : nil;
}

/* Adds to libraries the dynamic libraries this one links, and theirs, that
 * none there already provides. */
- (BOOL)link:(NSMutableArray *)libraries error:(NSError **)error
{
	/* The lock guards the names and loaded libraries, never a load, which
	 * links further libraries under their own locks. */
	os_unfair_lock_lock(&_linkLock);
	if (!_linkedNames) {
		_linkedNames = [self namesFrom:StelaOperationLibraryLinkedNames];
		_linked = [NSMutableDictionary dictionary];
	}
	NSArray *names = _linkedNames;
	os_unfair_lock_unlock(&_linkLock);
	for (NSUInteger i = 0; i < names.count; i++) {
		NSString *name = names[i];
		/* A library of that install name resolves its imports. */
		BOOL provided = NO;
		for (NSUInteger j = 0; j < libraries.count; j++) {
			provided |= [[libraries[j] installName] isEqualToString:name];
		}
		if (provided) {
			continue;
		}
		os_unfair_lock_lock(&_linkLock);
		StelaGPULibrary *library = _linked[name];
		os_unfair_lock_unlock(&_linkLock);
		if (!library) {
			char path[1024];
			BOOL placed = install_path(name.UTF8String, _path, path, sizeof(path));
			library = placed ? [_device dynamicLibraryAtPath:[NSString stringWithUTF8String:path] error:NULL]
					 : nil;
			if (!library) {
				StelaFailure failure = {};
				snprintf(failure.reason, sizeof(failure.reason), "the dynamic library %s it links %s",
					 name.UTF8String, placed ? "did not load" : "is at no place its install name says");
				stela_report("a library's linked dynamic library", &failure);
				if (error) {
					*error = stela_error(MTLDynamicLibraryDomain,
							     placed ? MTLDynamicLibraryErrorDependencyLoadFailure
								    : MTLDynamicLibraryErrorUnresolvedInstallName,
							     &failure);
				}
				return NO;
			}
			os_unfair_lock_lock(&_linkLock);
			/* Another pipeline may have loaded it meanwhile. */
			StelaGPULibrary *loaded = _linked[name];
			if (loaded) {
				library = loaded;
			} else {
				[_linked setObject:library forKey:name];
			}
			os_unfair_lock_unlock(&_linkLock);
		}
		[libraries addObject:library];
		if (![library link:libraries error:error]) {
			return NO;
		}
	}
	return YES;
}

/* What the library says of itself, once: a library's bytes never change. */
- (void)identify
{
	if (_identified) {
		return;
	}
	StelaLibraryIdentityRequest request = {.library = _handle};
	StelaLibraryIdentityResponse response = {};
	char *name = read_variable(&_device->_gate, StelaOperationLibraryIdentity, &request, sizeof(request),
				   &request.out, &response, sizeof(response), &response.length);
	if (name) {
		_type = response.library_type;
		_installName = response.length ? [[NSString alloc] initWithBytes:name
									  length:response.length
									encoding:NSUTF8StringEncoding]
					       : nil;
		free(name);
	}
	_identified = YES;
}

- (NSUInteger)type
{
	[self identify];
	return _type;
}

- (NSString *)installName
{
	[self identify];
	return _installName;
}

/* `MTLDynamicLibrary`: a dynamic library is the library it was made from. */
- (BOOL)serializeToURL:(NSURL *)url error:(NSError **)error
{
	StelaLibraryDataRequest request = {.library = _handle};
	StelaLength response = {};
	void *bytes = read_variable(&_device->_gate, StelaOperationLibraryData, &request, sizeof(request), &request.out,
				    &response, sizeof(response), &response.length);
	if (!bytes) {
		if (error) {
			StelaFailure failure = {.reason = "the library's bytes"};
			*error = stela_error(MTLDynamicLibraryDomain, MTLDynamicLibraryErrorUnsupported, &failure);
		}
		return NO;
	}
	NSData *data = [NSData dataWithBytesNoCopy:bytes length:response.length freeWhenDone:YES];
	return [data writeToURL:url options:NSDataWritingAtomic error:error];
}

- (id)newFunctionWithName:(NSString *)name constantValues:(id)values error:(NSError **)error
{
	return [self newFunctionWithName:name constantValues:values specializedName:nil error:error];
}

/* `specialized`, when not nil, is the function's name: pipelines that link a
 * visible function resolve calls of that name to it. */
- (id)newFunctionWithName:(NSString *)name
	   constantValues:(id)values
	  specializedName:(NSString *)specialized
		    error:(NSError **)error
{
	if (values && !([values respondsToSelector:@selector(newIndexedConstantArray)] &&
			[values respondsToSelector:@selector(newNamedConstantArray)])) {
		StelaFailure failure = {.reason = "constant values that keep no array of themselves"};
		stela_report([[NSString stringWithFormat:@"function %@", name] UTF8String], &failure);
		if (error) {
			*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorUnsupported, &failure);
		}
		return nil;
	}
	NSArray *indexed = values ? [values newIndexedConstantArray] : [NSArray array];
	NSArray *named = values ? [values newNamedConstantArray] : [NSArray array];
	NSUInteger count = indexed.count + named.count;
	StelaConstantRecord *records = calloc(count + 1, sizeof(*records));
	StelaSpan *spans = calloc(2 * count + 3, sizeof(*spans));
	const char *utf8 = name.UTF8String;
	const char *alias = specialized.length ? specialized.UTF8String : NULL;
	size_t used = 0;
	spans[used++] = stela_span(utf8, strlen(utf8));
	for (NSUInteger i = 0; i < count; i++) {
		BOOL byName = i >= indexed.count;
		id constant = byName ? [named objectAtIndex:i - indexed.count] : [indexed objectAtIndex:i];
		const char *key = byName ? [constant name].UTF8String : NULL;
		NSUInteger type = [constant dataType];
		records[i] = (StelaConstantRecord){
			.data_type = type,
			.index = byName ? 0 : [constant index],
			.name = key ? stela_span(key, strlen(key)) : stela_span(NULL, 0),
			.value = stela_span([constant data], data_type_bytes(type)),
		};
		spans[used++] = records[i].name;
		spans[used++] = records[i].value;
	}
	StelaNewFunctionRequest request = {
		.library = _handle,
		.name = spans[0],
		.constants = stela_span(records, count * sizeof(*records)),
		/* Without values, the function is as the library holds it. */
		.specialized = values != nil,
		.specialized_name = alias ? stela_span(alias, strlen(alias)) : stela_span(NULL, 0),
	};
	spans[used++] = request.constants;
	if (alias) {
		spans[used++] = request.specialized_name;
	}
	StelaHandle response = {};
	StelaFailure failure;
	StelaSpans touched = {.reads = spans, .read_count = used};
	uint32_t status = STELA_CALL_SPANS(&_device->_gate, NewFunction, &request, &response, touched, &failure);
	free(spans);
	free(records);
	if (status != StelaStatusOk) {
		/* A name the library lacks is Metal's nil, which callers probing
		 * libraries expect. A function it holds but this device cannot
		 * take is unsupported, or failed to compile, as Metal says of a
		 * specialization: never a name it lacks, which it lists. */
		NSInteger code = MTLLibraryErrorFunctionNotFound;
		if (status != StelaStatusDeclined) {
			stela_report([[NSString stringWithFormat:@"function %@", name] UTF8String], &failure);
			code = status == StelaStatusUnsupported ? MTLLibraryErrorUnsupported : MTLLibraryErrorCompileFailure;
		}
		if (error) {
			*error = stela_error(MTLLibraryErrorDomain, code, &failure);
		}
		return nil;
	}
	return [[StelaGPUFunction alloc] initWithLibrary:self handle:response.handle name:alias ? specialized : name];
}

- (id)newFunctionWithName:(NSString *)name
{
	return [self newFunctionWithName:name constantValues:nil error:NULL];
}

/* `MTLFunctionReflection`: the bindings of the function as the library
 * holds it, which carries no user annotation. */
- (id)reflectionForFunctionWithName:(NSString *)name
{
	StelaGPUFunction *function = [self newFunctionWithName:name];
	if (!function) {
		return nil;
	}
	StelaGPUFunctionReflection *reflection = [StelaGPUFunctionReflection new];
	reflection.bindings = [StelaGPUReflection bindingsOfFunction:function];
	return reflection;
}

- (void)newFunctionWithName:(NSString *)name
	     constantValues:(id)values
	  completionHandler:(void (^)(id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		NSError *error = nil;
		id function = [self newFunctionWithName:name constantValues:values error:&error];
		handler(function, error);
	});
}

/* A descriptor's specialized name, when it has one, is the function's name,
 * by which stitched graphs name it and pipelines link it. Functions compile
 * into the pipelines linking them, so its archives and options add nothing. */
- (id)newFunctionWithDescriptor:(id)descriptor error:(NSError **)error
{
	return [self newFunctionWithName:[descriptor name]
			  constantValues:[descriptor constantValues]
			 specializedName:[descriptor specializedName]
				   error:error];
}

- (void)newFunctionWithDescriptor:(id)descriptor completionHandler:(void (^)(id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		NSError *error = nil;
		id function = [self newFunctionWithDescriptor:descriptor error:&error];
		handler(function, error);
	});
}

- (id)newIntersectionFunctionWithDescriptor:(id)descriptor error:(NSError **)error
{
	if (error) {
		StelaFailure failure = {.reason = "intersection functions"};
		*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorUnsupported, &failure);
	}
	(void)descriptor;
	return nil;
}

@end

/* An archive's failure, in its domain, from a pipeline's. */
static BOOL add_failed(NSError **error, NSInteger code, NSError *failure)
{
	if (error) {
		*error = [NSError errorWithDomain:MTLBinaryArchiveDomain code:code userInfo:failure.userInfo];
	}
	return NO;
}

@implementation StelaGPUBinaryArchive

- (BOOL)addComputePipelineFunctionsWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSError *failure = nil;
	id pipeline = [_device computePipeline:descriptor options:0 reflection:NULL archive:_handle error:&failure];
	return pipeline ? YES : add_failed(error, MTLBinaryArchiveErrorCompilationFailure, failure);
}

- (BOOL)addRenderPipelineFunctionsWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSError *failure = nil;
	id pipeline = [_device renderPipeline:descriptor options:0 reflection:NULL archive:_handle error:&failure];
	return pipeline ? YES : add_failed(error, MTLBinaryArchiveErrorCompilationFailure, failure);
}

- (BOOL)addMeshRenderPipelineFunctionsWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSError *failure = nil;
	id pipeline = [_device meshPipeline:descriptor options:0 reflection:NULL archive:_handle error:&failure];
	return pipeline ? YES : add_failed(error, MTLBinaryArchiveErrorCompilationFailure, failure);
}

- (BOOL)addTileRenderPipelineFunctionsWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSError *failure = nil;
	id pipeline = [_device tilePipeline:descriptor options:0 reflection:NULL archive:_handle error:&failure];
	return pipeline ? YES : add_failed(error, MTLBinaryArchiveErrorCompilationFailure, failure);
}

/* A visible function compiles into the stages linking it: only its pipelines are kept. */
- (BOOL)addFunctionWithDescriptor:(id)descriptor library:(StelaGPULibrary *)library error:(NSError **)error
{
	NSError *failure = nil;
	id function = [library newFunctionWithDescriptor:descriptor error:&failure];
	return function ? YES : add_failed(error, MTLBinaryArchiveErrorUnexpectedElement, failure);
}

/* A stitched library's functions, like a visible function, compile into the
 * pipelines linking them: the library is checked and only those are kept. */
- (BOOL)addLibraryWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSError *failure = nil;
	id library = [_device newLibraryWithStitchedDescriptor:descriptor error:&failure];
	return library ? YES : add_failed(error, MTLBinaryArchiveErrorCompilationFailure, failure);
}

- (BOOL)serializeToURL:(NSURL *)url error:(NSError **)error
{
	StelaArchiveDataRequest request = {.archive = _handle};
	StelaLength response = {};
	void *bytes = read_variable(&_device->_gate, StelaOperationArchiveData, &request, sizeof(request), &request.out,
				    &response, sizeof(response), &response.length);
	if (!bytes) {
		if (error) {
			StelaFailure failure = {.reason = "the archive's bytes"};
			*error = stela_error(MTLBinaryArchiveDomain, MTLBinaryArchiveErrorInternalError, &failure);
		}
		return NO;
	}
	NSData *data = [NSData dataWithBytesNoCopy:bytes length:response.length freeWhenDone:YES];
	return [data writeToURL:url options:NSDataWritingAtomic error:error];
}

@end

@implementation StelaGPUDevice (Libraries)

- (id)newBinaryArchiveWithDescriptor:(id)descriptor error:(NSError **)error
{
	NSURL *url = [descriptor url];
	NSData *data = nil;
	if (url) {
		NSError *failure = nil;
		data = [NSData dataWithContentsOfURL:url options:0 error:&failure];
		if (!data) {
			add_failed(error, MTLBinaryArchiveErrorInvalidFile, failure);
			return nil;
		}
	}
	StelaNewArchiveRequest request = {.data = stela_span(data.bytes, data.length)};
	StelaHandle response = {};
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.data, .read_count = 1};
	if (STELA_CALL_SPANS(&_gate, NewArchive, &request, &response, spans, &failure) != StelaStatusOk) {
		if (error) {
			*error = stela_error(MTLBinaryArchiveDomain, MTLBinaryArchiveErrorInternalError, &failure);
		}
		return nil;
	}
	return [[StelaGPUBinaryArchive alloc] initWithDevice:self handle:response.handle];
}

- (id)libraryWithBytes:(const void *)bytes length:(NSUInteger)length error:(NSError **)error
{
	air_slice(&bytes, &length);
	StelaNewLibraryRequest request = {.data = stela_span(bytes, length)};
	StelaHandle response = {};
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.data, .read_count = 1};
	if (STELA_CALL_SPANS(&_gate, NewLibrary, &request, &response, spans, &failure) != StelaStatusOk) {
		if (error) {
			*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorInternal, &failure);
		}
		return nil;
	}
	return [[StelaGPULibrary alloc] initWithDevice:self handle:response.handle];
}

- (id)newLibraryWithData:(dispatch_data_t)data error:(NSError **)error
{
	const void *bytes = NULL;
	size_t size = 0;
	dispatch_data_t map = dispatch_data_create_map(data, &bytes, &size);
	id library = [self libraryWithBytes:bytes length:size error:error];
	dispatch_release(map);
	return library;
}

- (id)newLibraryWithURL:(NSURL *)url error:(NSError **)error
{
	NSData *data = [NSData dataWithContentsOfURL:url options:STELA_DATA_MAPPED error:error];
	if (!data) {
		StelaFailure failure = {.reason = "the file did not read"};
		stela_report([[NSString stringWithFormat:@"a library at %@", url] UTF8String], &failure);
		return nil;
	}
	StelaGPULibrary *library = [self libraryWithBytes:data.bytes length:data.length error:error];
	if (library) {
		library->_path = [NSString stringWithUTF8String:url.fileSystemRepresentation];
	}
	return library;
}

- (id)newLibraryWithFile:(NSString *)path error:(NSError **)error
{
	NSData *data = [NSData dataWithContentsOfFile:path options:STELA_DATA_MAPPED error:error];
	StelaGPULibrary *library = data ? [self libraryWithBytes:data.bytes length:data.length error:error] : nil;
	if (library) {
		library->_path = path;
	}
	return library;
}

- (id)newDefaultLibraryWithBundle:(id)bundle error:(NSError **)error
{
	NSURL *url = [bundle URLForResource:@"default" withExtension:@"metallib"];
	if (!url) {
		if (error) {
			StelaFailure failure = {.reason = "the bundle has no default.metallib"};
			stela_report([[NSString stringWithFormat:@"a default library of %@", bundle] UTF8String], &failure);
			*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorFileNotFound, &failure);
		}
		return nil;
	}
	return [self newLibraryWithURL:url error:error];
}

- (id)newDefaultLibrary
{
	return [self newDefaultLibraryWithBundle:[NSBundle mainBundle] error:NULL];
}

- (id)dynamicLibrary:(StelaGPULibrary *)library error:(NSError **)error
{
	if (!(_capabilities->flags & StelaFlags_DYNAMIC_LIBRARIES)) {
		if (error) {
			StelaFailure failure = {.reason = "this device loads no dynamic libraries"};
			*error = stela_error(MTLDynamicLibraryDomain, MTLDynamicLibraryErrorUnsupported, &failure);
		}
		return nil;
	}
	if ([library type] != MTLLibraryTypeDynamic) {
		if (error) {
			StelaFailure failure = {.reason = "the library is not a dynamic library"};
			*error = stela_error(MTLDynamicLibraryDomain, MTLDynamicLibraryErrorInvalidFile, &failure);
		}
		return nil;
	}
	return library;
}

- (id)newDynamicLibrary:(StelaGPULibrary *)library error:(NSError **)error
{
	return [self dynamicLibrary:library error:error];
}

- (id)newDynamicLibraryWithURL:(NSURL *)url error:(NSError **)error
{
	NSData *data = [NSData dataWithContentsOfURL:url options:0 error:error];
	StelaGPULibrary *library = data ? [self libraryWithBytes:data.bytes length:data.length error:error] : nil;
	if (library) {
		library->_path = [NSString stringWithUTF8String:url.fileSystemRepresentation];
	}
	return library ? [self dynamicLibrary:library error:error] : nil;
}

- (id)dynamicLibraryAtPath:(NSString *)path error:(NSError **)error
{
	NSData *data = [NSData dataWithContentsOfFile:path options:0 error:error];
	StelaGPULibrary *library = data ? [self libraryWithBytes:data.bytes length:data.length error:error] : nil;
	if (library) {
		library->_path = path;
	}
	return library ? [self dynamicLibrary:library error:error] : nil;
}

- (id)newLibraryWithSource:(NSString *)source options:(id)options error:(NSError **)error
{
	options = options ?: [NSClassFromString(@"MTLCompileOptions") new];
	NSData *air = stela_compile_source(source, options, error);
	if (!air) {
		return nil;
	}
	BOOL dynamic = [options libraryType] == MTLLibraryTypeDynamic;
	const char *install_name = dynamic ? [options installName].UTF8String : NULL;
	NSArray *libraries = [options libraries];
	uint64_t handles[libraries.count + 1];
	for (NSUInteger i = 0; i < libraries.count; i++) {
		handles[i] = ((StelaGPULibrary *)libraries[i])->_handle;
	}
	StelaNewSourceLibraryRequest request = {
		.air = stela_span(air.bytes, air.length),
		.install_name = stela_span(install_name, install_name ? strlen(install_name) : 0),
		.libraries = stela_span(handles, libraries.count * sizeof(*handles)),
		// Narrowing conversions' rounding, an option since macOS 27.
		.conversion_rounding = [options respondsToSelector:@selector(floatingPointConversionRoundingMode)]
			? [options floatingPointConversionRoundingMode]
			: 0,
	};
	StelaHandle response = {};
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.air, .read_count = 3};
	if (STELA_CALL_SPANS(&_gate, NewSourceLibrary, &request, &response, spans, &failure) != StelaStatusOk) {
		if (error) {
			*error = stela_error(MTLLibraryErrorDomain, MTLLibraryErrorInternal, &failure);
		}
		return nil;
	}
	StelaGPULibrary *library = [[StelaGPULibrary alloc] initWithDevice:self handle:response.handle];
	return dynamic ? [self dynamicLibrary:library error:error] : library;
}

- (void)newLibraryWithSource:(NSString *)source options:(id)options completionHandler:(void (^)(id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		NSError *error = nil;
		id library = [self newLibraryWithSource:source options:options error:&error];
		handler(library, error);
	});
}

- (id)newArgumentEncoderWithBufferBinding:(StelaGPUBinding *)binding
{
	return encoder_of_binding(self, binding);
}

- (id)newArgumentEncoderWithArguments:(NSArray *)arguments
{
	NSUInteger count = arguments.count;
	StelaArgumentRecord *records = calloc(count, sizeof(*records));
	uint32_t *offsets = calloc(count, sizeof(*offsets));
	for (NSUInteger i = 0; i < count; i++) {
		id argument = [arguments objectAtIndex:i];
		records[i] = (StelaArgumentRecord){
			.data_type = [argument dataType],
			.index = (uint32_t)[argument index],
			.array_length = (uint32_t)[argument arrayLength],
			.constant_block_alignment = (uint32_t)[argument constantBlockAlignment],
		};
	}
	StelaArgumentLayoutRequest request = {
		.arguments = stela_span(records, count * sizeof(*records)),
		.out = stela_span(offsets, count * sizeof(*offsets)),
	};
	StelaArgumentLayoutResponse response = {};
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.arguments, .read_count = 1, .writes = &request.out, .write_count = 1};
	StelaGPUArgumentEncoder *encoder = nil;
	if (STELA_CALL_SPANS(&_gate, ArgumentLayout, &request, &response, spans, &failure) != StelaStatusOk) {
		stela_report("an argument encoder's layout", &failure);
	} else {
		encoder = [[StelaGPUArgumentEncoder alloc] initWithDevice:self
							    encodedLength:response.encoded_length
								alignment:response.alignment];
		for (NSUInteger i = 0; i < count; i++) {
			/* Every array element of an argument buffer is a pointer or a resource ID. */
			NSUInteger length = records[i].array_length ? records[i].array_length : 1;
			for (NSUInteger j = 0; j < length; j++) {
				[encoder addSlotAt:records[i].index + j offset:offsets[i] + j * sizeof(uint64_t)];
			}
		}
	}
	free(records);
	free(offsets);
	return encoder;
}

@end
