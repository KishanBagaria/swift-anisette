#ifndef CAnisette_H
#define CAnisette_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct anisette_library anisette_library;
typedef struct anisette_engine anisette_engine;
typedef struct anisette_cancellation anisette_cancellation;
typedef void (*anisette_code_callback)(void *, uint64_t, uint32_t);

anisette_library *anisette_library_open(const char *path);
const char *anisette_library_error(void);
void anisette_library_close(anisette_library *library);
anisette_cancellation *anisette_cancellation_create(void);
void anisette_cancellation_cancel(anisette_cancellation *cancellation);
bool anisette_cancellation_is_cancelled(anisette_cancellation *cancellation);
void anisette_cancellation_destroy(anisette_cancellation *cancellation);
int anisette_engine_open(anisette_library *library, anisette_cancellation *cancellation, anisette_engine **engine);
void anisette_engine_close(anisette_engine *engine);
int anisette_engine_map(anisette_engine *engine, uint64_t address, size_t size);
int anisette_engine_read(anisette_engine *engine, uint64_t address, void *bytes, size_t size);
int anisette_engine_write(anisette_engine *engine, uint64_t address, const void *bytes, size_t size);
int anisette_engine_register_read(anisette_engine *engine, int reg, void *value);
int anisette_engine_register_write(anisette_engine *engine, int reg, const void *value);
int anisette_engine_hook(anisette_engine *engine, uint64_t begin, uint64_t end, anisette_code_callback callback, void *context);
int anisette_engine_start(anisette_engine *engine, uint64_t begin, uint64_t end, uint64_t timeout);
int anisette_engine_stop(anisette_engine *engine);
const char *anisette_engine_error(anisette_engine *engine, int code);
int anisette_inflate(const void *source, size_t source_size, void *destination, size_t *destination_size);
uint32_t anisette_crc32(const void *source, size_t source_size);
size_t anisette_lzfse_decode(const void *source, size_t source_size, void *destination, size_t destination_size, bool lzvn);
#endif
