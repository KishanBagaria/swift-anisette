// Typed Linux ARM64 /dev/kvm shim for swift-anisette.
#if defined(__linux__) && defined(__aarch64__)
#define _GNU_SOURCE
#include "CAnisette.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef KVM_CAP_ARM_VM_IPA_SIZE
#define KVM_CAP_ARM_VM_IPA_SIZE 165
#endif

#ifndef KVM_VM_TYPE_ARM_IPA_SIZE
#define KVM_VM_TYPE_ARM_IPA_SIZE(ipa_bits) ((unsigned long)(ipa_bits) & 0xffUL)
#endif

#ifndef sigev_notify_thread_id
#ifdef __GLIBC__
#define sigev_notify_thread_id _sigev_un._tid
#else
#define sigev_notify_thread_id __sev_fields.__tid
#endif
#endif

#define CORE_REG(size, field) (KVM_REG_ARM64 | (size) | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(field))

struct anisette_kvm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    struct kvm_run *run;
    size_t run_size;
    uint32_t ipa_bits;
    uint32_t max_memslots;
    timer_t deadline_timer;
    bool has_deadline_timer;
};

static void kick_signal_handler(int signo) {
    (void)signo;
}

static void set_error(char *buf, size_t size, int err, const char *step) {
    if (buf && size > 0) {
        if (err != 0) {
            snprintf(buf, size, "%s: %s", step, strerror(err));
        } else {
            snprintf(buf, size, "%s", step);
        }
    }
}

int anisette_kvm_setup_worker_thread(int *kick_signal_out) {
    int sig = SIGUSR1;
#ifdef SIGRTMIN
    if (SIGRTMIN + 1 <= SIGRTMAX && SIGRTMIN + 1 <= 64) {
        sig = SIGRTMIN + 1;
    }
#endif

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = kick_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Explicitly omit SA_RESTART so KVM_RUN returns EINTR.
    if (sigaction(sig, &sa, NULL) != 0) {
        return -1;
    }

    sigset_t block_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, sig);
    if (pthread_sigmask(SIG_BLOCK, &block_set, NULL) != 0) {
        return -1;
    }

    if (kick_signal_out) *kick_signal_out = sig;
    return 0;
}

int anisette_kvm_pin_cpus(const int *cpus, size_t count) {
    if (!cpus || count == 0) return 0;

    int max_cpu = -1;
    for (size_t i = 0; i < count; i++) {
        if (cpus[i] < 0) {
            errno = EINVAL;
            return -1;
        }
        if (cpus[i] > max_cpu) max_cpu = cpus[i];
    }

    size_t num_cpus = (size_t)max_cpu + 1;
    cpu_set_t *set = CPU_ALLOC(num_cpus);
    if (!set) {
        errno = ENOMEM;
        return -1;
    }
    size_t set_size = CPU_ALLOC_SIZE(num_cpus);
    CPU_ZERO_S(set_size, set);
    for (size_t i = 0; i < count; i++) {
        CPU_SET_S((size_t)cpus[i], set_size, set);
    }
    int rc = sched_setaffinity(0, set_size, set);
    int saved = errno;
    CPU_FREE(set);
    errno = saved;
    return rc;
}

static int configure_signal_mask(int vcpu_fd, int kick_signal) {
    sigset_t current;
    if (pthread_sigmask(SIG_SETMASK, NULL, &current) != 0) {
        return -1;
    }
    sigdelset(&current, kick_signal);

    // Linux kernel checks kvm_signal_mask.len against kernel sizeof(sigset_t) (8 bytes on arm64),
    // not glibc's 128-byte userspace sigset_t.
    struct {
        struct kvm_signal_mask header;
        uint64_t mask;
    } ksm;
    memset(&ksm, 0, sizeof(ksm));
    ksm.header.len = 8;
    uint64_t bits = 0;
    for (int sig = 1; sig <= 64; sig++) {
        if (sigismember(&current, sig) == 1) {
            bits |= (1ULL << (sig - 1));
        }
    }
    ksm.mask = bits;
    return ioctl(vcpu_fd, KVM_SET_SIGNAL_MASK, &ksm.header);
}

anisette_kvm *anisette_kvm_create(int kick_signal, char *error_buf, size_t error_buf_size) {
    if (error_buf && error_buf_size > 0) error_buf[0] = '\0';

    anisette_kvm *kvm = calloc(1, sizeof(*kvm));
    if (!kvm) {
        set_error(error_buf, error_buf_size, ENOMEM, "allocate KVM state");
        return NULL;
    }
    kvm->kvm_fd = -1;
    kvm->vm_fd = -1;
    kvm->vcpu_fd = -1;
    kvm->run = MAP_FAILED;

    kvm->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm->kvm_fd < 0) {
        set_error(error_buf, error_buf_size, errno, "open /dev/kvm");
        goto fail;
    }

    int api_version = ioctl(kvm->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api_version != KVM_API_VERSION) {
        set_error(error_buf, error_buf_size, api_version < 0 ? errno : ENOTSUP,
                  "KVM_GET_API_VERSION mismatch");
        goto fail;
    }

    int debug_cap = ioctl(kvm->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_GUEST_DEBUG);
    if (debug_cap <= 0) {
        set_error(error_buf, error_buf_size, debug_cap < 0 ? errno : ENOTSUP,
                  "KVM_CAP_SET_GUEST_DEBUG unsupported");
        goto fail;
    }

    int ipa_cap = ioctl(kvm->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
    unsigned long vm_type = 0;
    uint32_t ipa_bits = 40;
    if (ipa_cap > 0) {
        ipa_bits = ipa_cap > 48 ? 48u : (uint32_t)ipa_cap;
        if (ipa_bits < 32) {
            set_error(error_buf, error_buf_size, ENOTSUP, "KVM IPA size below 32 bits");
            goto fail;
        }
        vm_type = KVM_VM_TYPE_ARM_IPA_SIZE(ipa_bits);
    }
    kvm->ipa_bits = ipa_bits;

    kvm->vm_fd = ioctl(kvm->kvm_fd, KVM_CREATE_VM, vm_type);
    if (kvm->vm_fd < 0) {
        set_error(error_buf, error_buf_size, errno, "KVM_CREATE_VM");
        goto fail;
    }

    int memslots = ioctl(kvm->vm_fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS);
    if (memslots <= 0) {
        memslots = ioctl(kvm->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS);
    }
    kvm->max_memslots = memslots > 0 ? (uint32_t)memslots : 509u;

    int run_size = ioctl(kvm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (run_size <= 0) {
        set_error(error_buf, error_buf_size, run_size < 0 ? errno : EINVAL, "KVM_GET_VCPU_MMAP_SIZE");
        goto fail;
    }
    kvm->run_size = (size_t)run_size;

    kvm->vcpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, 0);
    if (kvm->vcpu_fd < 0) {
        set_error(error_buf, error_buf_size, errno, "KVM_CREATE_VCPU");
        goto fail;
    }

    struct kvm_vcpu_init init;
    memset(&init, 0, sizeof(init));
    if (ioctl(kvm->vm_fd, KVM_ARM_PREFERRED_TARGET, &init) < 0) {
        set_error(error_buf, error_buf_size, errno, "KVM_ARM_PREFERRED_TARGET");
        goto fail;
    }
    if (ioctl(kvm->vcpu_fd, KVM_ARM_VCPU_INIT, &init) < 0) {
        set_error(error_buf, error_buf_size, errno, "KVM_ARM_VCPU_INIT");
        goto fail;
    }

    struct kvm_guest_debug dbg;
    memset(&dbg, 0, sizeof(dbg));
    dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    if (ioctl(kvm->vcpu_fd, KVM_SET_GUEST_DEBUG, &dbg) < 0) {
        set_error(error_buf, error_buf_size, errno, "KVM_SET_GUEST_DEBUG");
        goto fail;
    }

    if (configure_signal_mask(kvm->vcpu_fd, kick_signal) < 0) {
        set_error(error_buf, error_buf_size, errno, "KVM_SET_SIGNAL_MASK");
        goto fail;
    }

    // Deadline expiry kicks this (the worker) thread out of KVM_RUN with the kick signal.
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = kick_signal;
    sev.sigev_notify_thread_id = (pid_t)syscall(SYS_gettid);
    if (timer_create(CLOCK_MONOTONIC, &sev, &kvm->deadline_timer) != 0) {
        set_error(error_buf, error_buf_size, errno, "timer_create");
        goto fail;
    }
    kvm->has_deadline_timer = true;

    kvm->run = mmap(NULL, kvm->run_size, PROT_READ | PROT_WRITE, MAP_SHARED, kvm->vcpu_fd, 0);
    if (kvm->run == MAP_FAILED) {
        set_error(error_buf, error_buf_size, errno, "mmap kvm_run");
        goto fail;
    }

    return kvm;

fail:
    anisette_kvm_destroy(kvm);
    return NULL;
}

void anisette_kvm_destroy(anisette_kvm *kvm) {
    if (!kvm) return;
    if (kvm->has_deadline_timer) timer_delete(kvm->deadline_timer);
    if (kvm->run != MAP_FAILED && kvm->run_size > 0) {
        munmap(kvm->run, kvm->run_size);
    }
    if (kvm->vcpu_fd >= 0) close(kvm->vcpu_fd);
    if (kvm->vm_fd >= 0) close(kvm->vm_fd);
    if (kvm->kvm_fd >= 0) close(kvm->kvm_fd);
    free(kvm);
}

uint32_t anisette_kvm_ipa_bits(const anisette_kvm *kvm) {
    return kvm ? kvm->ipa_bits : 0;
}

uint32_t anisette_kvm_max_memslots(const anisette_kvm *kvm) {
    return kvm ? kvm->max_memslots : 0;
}

void *anisette_kvm_alloc_slab(size_t size) {
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return ptr == MAP_FAILED ? NULL : ptr;
}

void anisette_kvm_free_slab(void *ptr, size_t size) {
    if (ptr && size > 0) {
        munmap(ptr, size);
    }
}

int anisette_kvm_map_region(anisette_kvm *kvm, uint32_t slot, uint64_t ipa, void *host, uint64_t size) {
    struct kvm_userspace_memory_region region;
    memset(&region, 0, sizeof(region));
    region.slot = slot;
    region.flags = 0;
    region.guest_phys_addr = ipa;
    region.memory_size = size;
    region.userspace_addr = (uint64_t)(uintptr_t)host;
    return ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
}

void anisette_kvm_icache_invalidate(void *addr, size_t size) {
    if (addr && size > 0) {
        __builtin___clear_cache((char *)addr, (char *)addr + size);
    }
}

static uint64_t reg_id(anisette_kvm_reg reg) {
    if (reg <= ANISETTE_KVM_REG_X0 + 30) {
        return CORE_REG(KVM_REG_SIZE_U64, regs.regs[0]) + 2 * (uint64_t)reg;
    }
    switch (reg) {
    case ANISETTE_KVM_REG_SP_EL0: return CORE_REG(KVM_REG_SIZE_U64, regs.sp);
    case ANISETTE_KVM_REG_PC: return CORE_REG(KVM_REG_SIZE_U64, regs.pc);
    case ANISETTE_KVM_REG_PSTATE: return CORE_REG(KVM_REG_SIZE_U64, regs.pstate);
    case ANISETTE_KVM_REG_SP_EL1: return CORE_REG(KVM_REG_SIZE_U64, sp_el1);
    case ANISETTE_KVM_REG_ELR_EL1: return CORE_REG(KVM_REG_SIZE_U64, elr_el1);
    case ANISETTE_KVM_REG_SPSR_EL1: return CORE_REG(KVM_REG_SIZE_U64, spsr[KVM_SPSR_EL1]);
    case ANISETTE_KVM_REG_FPSR: return CORE_REG(KVM_REG_SIZE_U32, fp_regs.fpsr);
    case ANISETTE_KVM_REG_FPCR: return CORE_REG(KVM_REG_SIZE_U32, fp_regs.fpcr);
    case ANISETTE_KVM_REG_ID_AA64MMFR0_EL1: return ARM64_SYS_REG(3, 0, 0, 7, 0);
    case ANISETTE_KVM_REG_SCTLR_EL1: return ARM64_SYS_REG(3, 0, 1, 0, 0);
    case ANISETTE_KVM_REG_CPACR_EL1: return ARM64_SYS_REG(3, 0, 1, 0, 2);
    case ANISETTE_KVM_REG_TTBR0_EL1: return ARM64_SYS_REG(3, 0, 2, 0, 0);
    case ANISETTE_KVM_REG_TCR_EL1: return ARM64_SYS_REG(3, 0, 2, 0, 2);
    case ANISETTE_KVM_REG_ESR_EL1: return ARM64_SYS_REG(3, 0, 5, 2, 0);
    case ANISETTE_KVM_REG_FAR_EL1: return ARM64_SYS_REG(3, 0, 6, 0, 0);
    case ANISETTE_KVM_REG_MAIR_EL1: return ARM64_SYS_REG(3, 0, 10, 2, 0);
    case ANISETTE_KVM_REG_VBAR_EL1: return ARM64_SYS_REG(3, 0, 12, 0, 0);
    case ANISETTE_KVM_REG_CONTEXTIDR_EL1: return ARM64_SYS_REG(3, 0, 13, 0, 1);
    case ANISETTE_KVM_REG_TPIDR_EL0: return ARM64_SYS_REG(3, 3, 13, 0, 2);
    case ANISETTE_KVM_REG_TPIDRRO_EL0: return ARM64_SYS_REG(3, 3, 13, 0, 3);
    case ANISETTE_KVM_REG_TPIDR_EL1: return ARM64_SYS_REG(3, 0, 13, 0, 4);
    default: return 0;
    }
}

static int one_reg(anisette_kvm *kvm, unsigned long request, uint64_t id, void *value) {
    struct kvm_one_reg reg = { .id = id, .addr = (uint64_t)(uintptr_t)value };
    return ioctl(kvm->vcpu_fd, request, &reg);
}

int anisette_kvm_get_reg(anisette_kvm *kvm, anisette_kvm_reg reg, uint64_t *value) {
    uint64_t id = reg_id(reg);
    if ((id & KVM_REG_SIZE_MASK) != KVM_REG_SIZE_U32) return one_reg(kvm, KVM_GET_ONE_REG, id, value);
    uint32_t narrow = 0;
    int rc = one_reg(kvm, KVM_GET_ONE_REG, id, &narrow);
    *value = narrow;
    return rc;
}

int anisette_kvm_set_reg(anisette_kvm *kvm, anisette_kvm_reg reg, uint64_t value) {
    uint64_t id = reg_id(reg);
    if ((id & KVM_REG_SIZE_MASK) != KVM_REG_SIZE_U32) return one_reg(kvm, KVM_SET_ONE_REG, id, &value);
    uint32_t narrow = (uint32_t)value;
    return one_reg(kvm, KVM_SET_ONE_REG, id, &narrow);
}

int anisette_kvm_get_vreg(anisette_kvm *kvm, unsigned index, void *value16) {
    return one_reg(kvm, KVM_GET_ONE_REG, CORE_REG(KVM_REG_SIZE_U128, fp_regs.vregs[0]) + 4 * (uint64_t)index, value16);
}

int anisette_kvm_set_vreg(anisette_kvm *kvm, unsigned index, const void *value16) {
    return one_reg(kvm, KVM_SET_ONE_REG, CORE_REG(KVM_REG_SIZE_U128, fp_regs.vregs[0]) + 4 * (uint64_t)index,
                   (void *)value16);
}

int anisette_kvm_run(anisette_kvm *kvm, anisette_kvm_exit *exit_out) {
    memset(exit_out, 0, sizeof(*exit_out));
    kvm->run->immediate_exit = 0;

    int rc = ioctl(kvm->vcpu_fd, KVM_RUN, 0);
    if (rc < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            exit_out->kind = ANISETTE_KVM_EXIT_INTR;
            exit_out->raw_reason = KVM_EXIT_INTR;
            return 0;
        }
        return -1;
    }

    uint32_t reason = kvm->run->exit_reason;
    exit_out->raw_reason = reason;
    switch (reason) {
    case KVM_EXIT_INTR:
        exit_out->kind = ANISETTE_KVM_EXIT_INTR;
        break;
    case KVM_EXIT_DEBUG: {
        exit_out->kind = ANISETTE_KVM_EXIT_DEBUG;
        uint64_t syndrome = (uint64_t)kvm->run->debug.arch.hsr;
#ifdef KVM_DEBUG_ARCH_HSR_HIGH_VALID
        if (kvm->run->flags & KVM_DEBUG_ARCH_HSR_HIGH_VALID) {
            syndrome |= ((uint64_t)kvm->run->debug.arch.hsr_high) << 32;
        }
#endif
        exit_out->syndrome = syndrome;
        exit_out->detail = kvm->run->debug.arch.far;
        break;
    }
    case KVM_EXIT_MMIO:
        exit_out->kind = ANISETTE_KVM_EXIT_MMIO;
        exit_out->detail = kvm->run->mmio.phys_addr;
        break;
    case KVM_EXIT_SYSTEM_EVENT:
        exit_out->kind = ANISETTE_KVM_EXIT_SYSTEM_EVENT;
        exit_out->detail = kvm->run->system_event.type;
        break;
    case KVM_EXIT_FAIL_ENTRY:
        exit_out->kind = ANISETTE_KVM_EXIT_FAIL_ENTRY;
        exit_out->detail = kvm->run->fail_entry.hardware_entry_failure_reason;
        break;
    case KVM_EXIT_INTERNAL_ERROR:
        exit_out->kind = ANISETTE_KVM_EXIT_INTERNAL_ERROR;
        exit_out->detail = kvm->run->internal.suberror;
        break;
    case KVM_EXIT_SHUTDOWN:
        exit_out->kind = ANISETTE_KVM_EXIT_SHUTDOWN;
        break;
    default:
        exit_out->kind = ANISETTE_KVM_EXIT_UNKNOWN;
        break;
    }
    return 0;
}

void anisette_kvm_drain_kick(int kick_signal) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, kick_signal);
    struct timespec zero = { 0, 0 };
    while (sigtimedwait(&set, NULL, &zero) > 0) {
        // Drain any queued real-time kick signals.
    }
}

uint64_t anisette_kvm_monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int anisette_kvm_set_deadline(anisette_kvm *kvm, uint64_t deadline_ns) {
    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    spec.it_value.tv_sec = (time_t)(deadline_ns / 1000000000ULL);
    spec.it_value.tv_nsec = (long)(deadline_ns % 1000000000ULL);
    return timer_settime(kvm->deadline_timer, TIMER_ABSTIME, &spec, NULL);
}
#else
typedef int anisette_kvm_unused;
#endif
