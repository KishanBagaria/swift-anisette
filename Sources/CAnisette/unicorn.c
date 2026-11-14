// A typed bridge to Unicorn 2.1's C ABI. No guest code executes in the host process.
#include "CAnisette.h"
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <zlib.h>
#include <lzfse.h>

struct anisette_library {
    void *handle;
    unsigned (*version)(unsigned *, unsigned *);
    int (*open)(int, int, void **);
    int (*close)(void *);
    int (*ctl)(void *, unsigned, ...);
    int (*query)(void *, int, size_t *);
    int (*mem_map)(void *, uint64_t, size_t, unsigned);
    int (*mem_read)(void *, uint64_t, void *, size_t);
    int (*mem_write)(void *, uint64_t, const void *, size_t);
    int (*reg_read)(void *, int, void *);
    int (*reg_write)(void *, int, const void *);
    int (*hook_add)(void *, size_t *, int, void *, void *, uint64_t, uint64_t, ...);
    int (*emu_start)(void *, uint64_t, uint64_t, uint64_t, size_t);
    int (*emu_stop)(void *);
    const char *(*strerror)(int);
};
struct anisette_cancellation { atomic_bool cancelled; };
struct anisette_engine {
    anisette_library *library;
    void *handle;
    anisette_cancellation *cancellation;
    anisette_code_callback callback;
    void *context;
};

anisette_library *anisette_library_open(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return NULL;
    anisette_library *library = calloc(1, sizeof(*library));
    if (!library) { dlclose(handle); return NULL; }
    library->handle = handle;
#define LOAD(field, symbol) do { *(void **)(&library->field) = dlsym(handle, symbol); if (!library->field) goto fail; } while (0)
    LOAD(version, "uc_version"); LOAD(open, "uc_open"); LOAD(close, "uc_close");
    LOAD(ctl, "uc_ctl"); LOAD(query, "uc_query");
    LOAD(mem_map, "uc_mem_map"); LOAD(mem_read, "uc_mem_read"); LOAD(mem_write, "uc_mem_write");
    LOAD(reg_read, "uc_reg_read"); LOAD(reg_write, "uc_reg_write"); LOAD(hook_add, "uc_hook_add");
    LOAD(emu_start, "uc_emu_start"); LOAD(emu_stop, "uc_emu_stop"); LOAD(strerror, "uc_strerror");
#undef LOAD
    unsigned major, minor;
    library->version(&major, &minor);
    if (major != 2 || minor != 1) goto fail;
    return library;
fail:
    anisette_library_close(library);
    return NULL;
}
const char *anisette_library_error(void) { const char *error = dlerror(); return error ? error : "Incompatible Unicorn library (expected 2.1)"; }
void anisette_library_close(anisette_library *library) { if (library) { dlclose(library->handle); free(library); } }
anisette_cancellation *anisette_cancellation_create(void) { return calloc(1, sizeof(anisette_cancellation)); }
void anisette_cancellation_cancel(anisette_cancellation *c) { atomic_store(&c->cancelled, true); }
bool anisette_cancellation_is_cancelled(anisette_cancellation *c) { return atomic_load(&c->cancelled); }
void anisette_cancellation_destroy(anisette_cancellation *c) { free(c); }

static void cancellation_hook(void *uc, uint64_t address, uint32_t size, void *user) {
    (void)uc; (void)address; (void)size;
    anisette_engine *engine = user;
    if (anisette_cancellation_is_cancelled(engine->cancellation)) engine->library->emu_stop(engine->handle);
}
static void code_hook(void *uc, uint64_t address, uint32_t size, void *user) {
    (void)uc;
    anisette_engine *engine = user;
    engine->callback(engine->context, address, size);
}
int anisette_engine_open(anisette_library *library, anisette_cancellation *cancellation, anisette_engine **result) {
    anisette_engine *engine = calloc(1, sizeof(*engine));
    if (!engine) return 1;
    engine->library = library; engine->cancellation = cancellation;
    int error = library->open(2, 0, &engine->handle); // UC_ARCH_ARM64, UC_MODE_ARM
    if (error) { free(engine); return error; }
    error = library->ctl(engine->handle, (1u << 30) | (1u << 26) | 7u, 3u); // UC_CPU_ARM64_MAX
    if (!error) error = library->ctl(engine->handle, (1u << 30) | (1u << 26) | 13u, 4u << 20);
    size_t page_size;
    if (!error) error = library->query(engine->handle, 2, &page_size);
    size_t hook;
    if (!error) error = library->hook_add(engine->handle, &hook, 8, cancellation_hook, engine, 1, 0); // UC_HOOK_BLOCK
    if (error) { anisette_engine_close(engine); return error; }
    *result = engine; return 0;
}
void anisette_engine_close(anisette_engine *e) { if (e) { e->library->close(e->handle); free(e); } }
int anisette_engine_map(anisette_engine *e, uint64_t a, size_t n) { return e->library->mem_map(e->handle, a, n, 7); }
int anisette_engine_read(anisette_engine *e, uint64_t a, void *p, size_t n) { return e->library->mem_read(e->handle, a, p, n); }
int anisette_engine_write(anisette_engine *e, uint64_t a, const void *p, size_t n) { return e->library->mem_write(e->handle, a, p, n); }
int anisette_engine_register_read(anisette_engine *e, int r, void *p) { return e->library->reg_read(e->handle, r, p); }
int anisette_engine_register_write(anisette_engine *e, int r, const void *p) { return e->library->reg_write(e->handle, r, p); }
int anisette_engine_hook(anisette_engine *e, uint64_t a, uint64_t b, anisette_code_callback callback, void *context) {
    e->callback = callback; e->context = context; size_t hook;
    return e->library->hook_add(e->handle, &hook, 4, code_hook, e, a, b); // UC_HOOK_CODE
}
int anisette_engine_start(anisette_engine *e, uint64_t a, uint64_t b, uint64_t timeout) { return e->library->emu_start(e->handle, a, b, timeout, 0); }
int anisette_engine_stop(anisette_engine *e) { return e->library->emu_stop(e->handle); }
const char *anisette_engine_error(anisette_engine *e, int code) { return e->library->strerror(code); }
int anisette_inflate(const void *source, size_t n, void *destination, size_t *size) {
    z_stream stream = {0};
    stream.next_in = (Bytef *)source; stream.avail_in = (uInt)n;
    stream.next_out = destination; stream.avail_out = (uInt)*size;
    int error = inflateInit2(&stream, -MAX_WBITS);
    if (error != Z_OK) return error;
    error = inflate(&stream, Z_FINISH); *size = stream.total_out; inflateEnd(&stream);
    return error == Z_STREAM_END ? 0 : error;
}
uint32_t anisette_crc32(const void *source, size_t n) { return (uint32_t)crc32(crc32(0, Z_NULL, 0), source, (uInt)n); }
size_t anisette_lzfse_decode(const void *source, size_t n, void *destination, size_t size, bool lzvn) {
    if (!lzvn) return lzfse_decode_buffer(destination, size, source, n, NULL);
    return lzvn_decode_buffer(destination, size, source, n);
}
