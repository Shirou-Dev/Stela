/*
 * What the bundle uses of macOS, declared here since no SDK takes part in the
 * build. Values are the public headers'; classes and selectors exist in the
 * running system, which the Objective-C runtime resolves by name.
 */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef bool BOOL;
#define YES true
#define NO false
#define nil ((id)0)

typedef unsigned long NSUInteger;
typedef long NSInteger;
typedef double CFTimeInterval;
typedef unsigned int mach_port_t;
typedef unsigned int io_object_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_service_t;
typedef int kern_return_t;
typedef mach_port_t task_t;
typedef unsigned long long mach_vm_address_t;
typedef unsigned long long mach_vm_size_t;
typedef struct IONotificationPort *IONotificationPortRef;
typedef struct dispatch_queue_s *dispatch_queue_t;
typedef struct dispatch_data_s *dispatch_data_t;
typedef struct dispatch_group_s *dispatch_group_t;
typedef const void *CFTypeRef;
typedef struct __IOSurface *IOSurfaceRef;
typedef const struct __CFString *CFStringRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef const struct objc_method *Method;
typedef void (*IMP)(void);

struct NSRange {
	NSUInteger location, length;
};
typedef struct NSRange NSRange;

/* Foundation. */
@class NSArray, NSError, NSString, NSURL;

/* Clang lays a direct subclass out from this interface, so it states `isa`. */
__attribute__((objc_root_class)) @interface NSObject {
	Class isa;
}
+ (instancetype)alloc;
- (instancetype)init;
+ (instancetype)new;
- (void)dealloc;
- (BOOL)conformsToProtocol:(id)protocol;
- (Class)class;
+ (Class)class;
- (BOOL)isKindOfClass:(Class)type;
- (id)copy;
- (NSString *)description;
@end

@interface NSString : NSObject
+ (instancetype)stringWithUTF8String:(const char *)text;
+ (instancetype)stringWithFormat:(NSString *)format, ...;
- (BOOL)isEqualToString:(NSString *)other;
- (instancetype)initWithBytes:(const void *)bytes length:(NSUInteger)length encoding:(NSUInteger)encoding;
- (NSRange)rangeOfCharacterFromSet:(id)set;
- (NSString *)stringByReplacingOccurrencesOfString:(NSString *)target withString:(NSString *)replacement;
@property(readonly) const char *UTF8String;
@property(readonly) NSInteger integerValue;
@property(readonly) NSUInteger length;
@end

#define NSUTF8StringEncoding 4
#define NSNotFound ((NSUInteger)0x7fffffffffffffff)

@interface NSMutableString : NSString
- (void)appendFormat:(NSString *)format, ...;
@end

@interface NSCharacterSet : NSObject
+ (instancetype)characterSetWithCharactersInString:(NSString *)characters;
@end

@interface NSFileManager : NSObject
+ (instancetype)defaultManager;
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;
@end

@interface NSArray : NSObject
+ (instancetype)array;
+ (instancetype)arrayWithObjects:(const id __unsafe_unretained[])objects count:(NSUInteger)count;
- (id)objectAtIndexedSubscript:(NSUInteger)index;
- (id)objectAtIndex:(NSUInteger)index;
- (NSUInteger)indexOfObjectIdenticalTo:(id)object;
@property(readonly) NSUInteger count;
@end

@interface NSMutableSet : NSObject
+ (instancetype)setWithCapacity:(NSUInteger)capacity;
- (void)addObject:(id)object;
- (void)removeObject:(id)object;
- (void)removeAllObjects;
- (BOOL)containsObject:(id)object;
@property(readonly) NSArray *allObjects;
@property(readonly) NSUInteger count;
@end

@interface NSMutableArray : NSArray
+ (instancetype)arrayWithCapacity:(NSUInteger)capacity;
- (void)addObject:(id)object;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)removeLastObject;
- (void)removeAllObjects;
@end

@interface NSDictionary : NSObject
+ (instancetype)dictionaryWithObjects:(const id __unsafe_unretained[])objects
			      forKeys:(const id __unsafe_unretained[])keys
				count:(NSUInteger)count;
- (id)objectForKey:(id)key;
- (id)objectForKeyedSubscript:(id)key;
@property(readonly) NSArray *allKeys;
@property(readonly) NSUInteger count;
@end

@interface NSMutableDictionary : NSDictionary
+ (instancetype)dictionary;
- (void)setObject:(id)object forKey:(id)key;
@end

@interface NSValue : NSObject
+ (instancetype)valueWithNonretainedObject:(id)object;
@property(readonly) id nonretainedObjectValue;
@end

@interface NSNumber : NSValue
+ (NSNumber *)numberWithUnsignedLongLong:(unsigned long long)value;
@property(readonly) unsigned long long unsignedLongLongValue;
@end

@interface NSError : NSObject
+ (instancetype)errorWithDomain:(NSString *)domain code:(NSInteger)code userInfo:(NSDictionary *)information;
@property(readonly) NSDictionary *userInfo;
@end

enum {
	NSDataWritingAtomic = 1,
};

@interface NSData : NSObject
+ (instancetype)dataWithBytes:(const void *)bytes length:(NSUInteger)length;
+ (instancetype)dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length freeWhenDone:(BOOL)free;
+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSUInteger)options error:(NSError **)error;
+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSUInteger)options error:(NSError **)error;
- (BOOL)writeToURL:(NSURL *)url options:(NSUInteger)options error:(NSError **)error;
@property(readonly) const void *bytes;
@property(readonly) NSUInteger length;
@end

@interface NSMutableData : NSData
+ (instancetype)dataWithLength:(NSUInteger)length;
- (void)appendBytes:(const void *)bytes length:(NSUInteger)length;
@property(readonly) void *mutableBytes;
@end

@interface NSCoder : NSObject
- (void)encodeBytes:(const uint8_t *)bytes length:(NSUInteger)length forKey:(NSString *)key;
- (const uint8_t *)decodeBytesForKey:(NSString *)key returnedLength:(NSUInteger *)length;
- (void)encodeObject:(id)object forKey:(NSString *)key;
- (id)decodeObjectOfClass:(Class)type forKey:(NSString *)key;
@end

@interface NSBundle : NSObject
+ (instancetype)mainBundle;
@end

@interface NSURL : NSObject
@property(readonly) const char *fileSystemRepresentation;
@end

extern NSString *const NSLocalizedDescriptionKey;
void NSLog(NSString *format, ...);
Class NSClassFromString(NSString *name);

/* The Objective-C runtime. */
Method class_getInstanceMethod(Class class, SEL selector);

/* libsystem, IOKit and libdispatch. */
extern mach_port_t mach_task_self_;
#define mach_task_self() mach_task_self_
#define KERN_SUCCESS 0
#define VM_FLAGS_ANYWHERE 1
#define kIOReturnSuccess 0
#define kIOMapAnywhere 1u
#define kIOMapDefaultCache 0u
/* Slot 0 of an async reference is the kernel's, for the reply port. */
#define kOSAsyncRef64Count 8
#define kIOAsyncCalloutFuncIndex 1
#define kIOAsyncCalloutRefconIndex 2

typedef void (*IOAsyncCallback1)(void *reference, int result, void *argument);
typedef void (*IOAsyncCallback)(void *reference, int result, void **arguments, uint32_t count);

void arc4random_buf(void *bytes, size_t length);
size_t strlcpy(char *to, const char *from, size_t size);
kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t IOServiceOpen(io_service_t service, task_t owner, uint32_t type, io_connect_t *connect);
kern_return_t IOServiceClose(io_connect_t connect);
kern_return_t IOConnectMapMemory64(io_connect_t connect, uint32_t type, task_t task,
				   mach_vm_address_t *address, mach_vm_size_t *size, uint32_t options);
kern_return_t IOConnectUnmapMemory64(io_connect_t connect, uint32_t type, task_t task, mach_vm_address_t address);
kern_return_t IOConnectCallScalarMethod(io_connect_t connect, uint32_t selector, const uint64_t *input,
					uint32_t inputs, uint64_t *output, uint32_t *outputs);
kern_return_t IOConnectCallAsyncScalarMethod(io_connect_t connect, uint32_t selector, mach_port_t port,
					     uint64_t *reference, uint32_t references,
					     const uint64_t *input, uint32_t inputs, uint64_t *output,
					     uint32_t *outputs);
kern_return_t IOObjectRetain(io_object_t object);
kern_return_t IOObjectRelease(io_object_t object);
CFTypeRef IORegistryEntryCreateCFProperty(io_service_t entry, CFStringRef key, const void *allocator, uint32_t options);
kern_return_t IORegistryEntrySetCFProperty(io_service_t entry, CFStringRef key, CFTypeRef value);
kern_return_t IORegistryEntryGetRegistryEntryID(io_service_t entry, uint64_t *identifier);
IONotificationPortRef IONotificationPortCreate(mach_port_t main);
mach_port_t IONotificationPortGetMachPort(IONotificationPortRef port);
void IONotificationPortSetDispatchQueue(IONotificationPortRef port, dispatch_queue_t queue);
void IONotificationPortDestroy(IONotificationPortRef port);
extern const mach_port_t kIOMainPortDefault;

CFTypeRef CFRetain(CFTypeRef object);
void CFRelease(CFTypeRef object);
kern_return_t IOSurfaceLock(IOSurfaceRef surface, uint32_t options, uint32_t *seed);
kern_return_t IOSurfaceUnlock(IOSurfaceRef surface, uint32_t options, uint32_t *seed);
void *IOSurfaceGetBaseAddress(IOSurfaceRef surface);
void *IOSurfaceGetBaseAddressOfPlane(IOSurfaceRef surface, size_t plane);
size_t IOSurfaceGetBytesPerRowOfPlane(IOSurfaceRef surface, size_t plane);
size_t IOSurfaceGetElementHeightOfPlane(IOSurfaceRef surface, size_t plane);
size_t IOSurfaceGetWidthOfPlane(IOSurfaceRef surface, size_t plane);
size_t IOSurfaceGetAllocSize(IOSurfaceRef surface);
size_t IOSurfaceGetWidth(IOSurfaceRef surface);
size_t IOSurfaceGetHeight(IOSurfaceRef surface);
size_t IOSurfaceGetBytesPerElement(IOSurfaceRef surface);
size_t IOSurfaceGetBytesPerRow(IOSurfaceRef surface);
size_t IOSurfaceGetPlaneCount(IOSurfaceRef surface);
uint32_t IOSurfaceGetPixelFormat(IOSurfaceRef surface);
uint32_t IOSurfaceGetID(IOSurfaceRef surface);
uint32_t IOSurfaceGetSeed(IOSurfaceRef surface);
IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
CFTypeRef IOSurfaceCopyValue(IOSurfaceRef surface, CFStringRef key);
mach_port_t IOSurfaceCreateMachPort(IOSurfaceRef surface);
IOSurfaceRef IOSurfaceLookupFromMachPort(mach_port_t port);
kern_return_t mach_port_deallocate(task_t task, mach_port_t name);

/* A kernel event IOSurface keeps, which Apple's Metal shared events are and
 * which IOSurface clients and the display share by its mach port. */
@interface IOSurfaceSharedEvent : NSObject
- (instancetype)initWithOptions:(uint64_t)options;
- (instancetype)initWithMachPort:(mach_port_t)port;
- (mach_port_t)eventPort;
- (uint64_t)signaledValue;
- (void)setSignaledValue:(uint64_t)value;
- (BOOL)waitUntilSignaledValue:(uint64_t)value timeoutMS:(uint64_t)milliseconds;
- (void)notifyListener:(id)listener atValue:(uint64_t)value block:(void (^)(id, uint64_t))block;
@end

#define OBJC_ASSOCIATION_RETAIN_NONATOMIC 1
void objc_setAssociatedObject(id object, const void *key, id value, uintptr_t policy);
id objc_getAssociatedObject(id object, const void *key);

#define DISPATCH_TIME_NOW (0ull)
#define DISPATCH_TIME_FOREVER (~0ull)
typedef struct dispatch_queue_attr_s *dispatch_queue_attr_t;
typedef struct dispatch_semaphore_s *dispatch_semaphore_t;
extern struct dispatch_queue_attr_s _dispatch_queue_attr_concurrent;
#define DISPATCH_QUEUE_CONCURRENT (&_dispatch_queue_attr_concurrent)
#define QOS_CLASS_USER_INITIATED 0x19
#define QOS_CLASS_DEFAULT 0x15
#define QOS_CLASS_UTILITY 0x11
dispatch_queue_t dispatch_queue_create(const char *label, const void *attributes);
dispatch_queue_attr_t dispatch_queue_attr_make_with_qos_class(dispatch_queue_attr_t attributes, unsigned qos,
							      int priority);
dispatch_semaphore_t dispatch_semaphore_create(long value);
long dispatch_semaphore_wait(dispatch_semaphore_t semaphore, uint64_t timeout);
long dispatch_semaphore_signal(dispatch_semaphore_t semaphore);
uint64_t dispatch_time(uint64_t when, int64_t delta);
void dispatch_barrier_async(dispatch_queue_t queue, void (^block)(void));
dispatch_queue_t dispatch_get_global_queue(long priority, unsigned long flags);
dispatch_group_t dispatch_group_create(void);
void dispatch_group_enter(dispatch_group_t group);
void dispatch_group_leave(dispatch_group_t group);
long dispatch_group_wait(dispatch_group_t group, uint64_t timeout);
void dispatch_release(void *object);
void dispatch_async(dispatch_queue_t queue, void (^block)(void));
void dispatch_once(long *predicate, void (^block)(void));
dispatch_data_t dispatch_data_create_map(dispatch_data_t data, const void **buffer, size_t *size);

uint64_t mach_absolute_time(void);
typedef struct {
	uint32_t numer, denom;
} mach_timebase_info_data_t;
kern_return_t mach_timebase_info(mach_timebase_info_data_t *information);

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *pointer, size_t size);
void free(void *pointer);
void *memcpy(void *to, const void *from, size_t size);
void *memset(void *to, int value, size_t size);
int memcmp(const void *a, const void *b, size_t size);
size_t strlen(const char *text);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t size);
long strtol(const char *text, char **end, int base);
char *getenv(const char *name);
int usleep(unsigned int microseconds);
const char *getprogname(void);
int getpid(void);
void abort(void) __attribute__((noreturn));
int sscanf(const char *text, const char *format, ...);
int sysctlbyname(const char *name, void *value, size_t *size, void *new_value, size_t new_size);

#define RTLD_NOW 0x2
#define RTLD_LOCAL 0x4
#define O_RDONLY 0
#define O_CLOEXEC 0x1000000
#define EINTR 4
int snprintf(char *text, size_t size, const char *format, ...);
int dprintf(int file, const char *format, ...);
char *strchr(const char *text, int character);
char *strstr(const char *text, const char *part);
char *strrchr(const char *text, int character);
int _NSGetExecutablePath(char *path, uint32_t *size);
void *memchr(const void *bytes, int value, size_t length);
int open(const char *path, int flags, ...);
int close(int file);
long pread(int file, void *bytes, size_t length, long long offset);
int *__error(void);

void *dlopen(const char *path, int mode);
void *dlsym(void *library, const char *symbol);
typedef struct {
	const char *dli_fname;
	void *dli_fbase;
	const char *dli_sname;
	void *dli_saddr;
} Dl_info;
int dladdr(const void *address, Dl_info *info);
int backtrace(void **frames, int size);

typedef struct {
	uint32_t opaque;
} os_unfair_lock;
#define OS_UNFAIR_LOCK_INIT ((os_unfair_lock){0})
void os_unfair_lock_lock(os_unfair_lock *lock);
void os_unfair_lock_unlock(os_unfair_lock *lock);
