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

#if defined(__linux__) && defined(__aarch64__)
typedef struct anisette_kvm anisette_kvm;

typedef enum {
    ANISETTE_KVM_REG_X0 = 0, // x<n> is ANISETTE_KVM_REG_X0 + n for n in 0...30.
    ANISETTE_KVM_REG_SP_EL0 = 31,
    ANISETTE_KVM_REG_PC,
    ANISETTE_KVM_REG_PSTATE,
    ANISETTE_KVM_REG_SP_EL1,
    ANISETTE_KVM_REG_ELR_EL1,
    ANISETTE_KVM_REG_SPSR_EL1,
    ANISETTE_KVM_REG_FPSR,
    ANISETTE_KVM_REG_FPCR,
    ANISETTE_KVM_REG_ID_AA64MMFR0_EL1,
    ANISETTE_KVM_REG_SCTLR_EL1,
    ANISETTE_KVM_REG_CPACR_EL1,
    ANISETTE_KVM_REG_TTBR0_EL1,
    ANISETTE_KVM_REG_TCR_EL1,
    ANISETTE_KVM_REG_ESR_EL1,
    ANISETTE_KVM_REG_FAR_EL1,
    ANISETTE_KVM_REG_MAIR_EL1,
    ANISETTE_KVM_REG_VBAR_EL1,
    ANISETTE_KVM_REG_CONTEXTIDR_EL1,
    ANISETTE_KVM_REG_TPIDR_EL0,
    ANISETTE_KVM_REG_TPIDRRO_EL0,
    ANISETTE_KVM_REG_TPIDR_EL1,
} anisette_kvm_reg;

typedef enum {
    ANISETTE_KVM_EXIT_UNKNOWN = 0,
    ANISETTE_KVM_EXIT_INTR = 1,
    ANISETTE_KVM_EXIT_DEBUG = 2,
    ANISETTE_KVM_EXIT_MMIO = 3,
    ANISETTE_KVM_EXIT_SYSTEM_EVENT = 4,
    ANISETTE_KVM_EXIT_FAIL_ENTRY = 5,
    ANISETTE_KVM_EXIT_INTERNAL_ERROR = 6,
    ANISETTE_KVM_EXIT_SHUTDOWN = 7,
} anisette_kvm_exit_kind;

typedef struct {
    anisette_kvm_exit_kind kind;
    uint32_t raw_reason;
    uint64_t syndrome;
    uint64_t detail;
} anisette_kvm_exit;

int anisette_kvm_setup_worker_thread(int *kick_signal_out);
int anisette_kvm_pin_cpus(const int *cpus, size_t count);
anisette_kvm *anisette_kvm_create(int kick_signal, char *error_buf, size_t error_buf_size);
void anisette_kvm_destroy(anisette_kvm *kvm);
uint32_t anisette_kvm_ipa_bits(const anisette_kvm *kvm);
uint32_t anisette_kvm_max_memslots(const anisette_kvm *kvm);
void *anisette_kvm_alloc_slab(size_t size);
void anisette_kvm_free_slab(void *ptr, size_t size);
int anisette_kvm_map_region(anisette_kvm *kvm, uint32_t slot, uint64_t ipa, void *host, uint64_t size);
void anisette_kvm_icache_invalidate(void *addr, size_t size);
int anisette_kvm_get_reg(anisette_kvm *kvm, anisette_kvm_reg reg, uint64_t *value);
int anisette_kvm_set_reg(anisette_kvm *kvm, anisette_kvm_reg reg, uint64_t value);
int anisette_kvm_get_vreg(anisette_kvm *kvm, unsigned index, void *value16);
int anisette_kvm_set_vreg(anisette_kvm *kvm, unsigned index, const void *value16);
int anisette_kvm_run(anisette_kvm *kvm, anisette_kvm_exit *exit_out);
void anisette_kvm_drain_kick(int kick_signal);
uint64_t anisette_kvm_monotonic_ns(void);
/// Arms the deadline timer at an absolute `CLOCK_MONOTONIC` time; 0 disarms it.
int anisette_kvm_set_deadline(anisette_kvm *kvm, uint64_t deadline_ns);
#endif
#endif
