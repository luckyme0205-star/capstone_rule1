/*
 * ini_probe.c  --  Reverse-engineering tool for the dynamic Inclusive / Non-Inclusive ("INI")
 *                  L2 <-> L3 policy of Intel Raptor Lake (13th Gen Core, e.g. i9-13900K).
 *
 * Build : gcc -O2 -pthread -o ini_probe ini_probe.c -lm        (or: make)
 * Run   : sudo ./ini_probe <command> [options]                 (./ini_probe help)
 *
 * ---------------------------------------------------------------------------------------------
 * Hypotheses taken from the reference documents and the command that tests each of them
 *
 *  H1  US 12,693,977 B2 (Intel, "Dynamic inclusive and non-inclusive caching policy"):
 *      policy chosen at runtime by comparing the NUMBER OF ACTIVE CORES with a threshold;
 *      the threshold may come from a logistic-regression model over telemetry
 *      (stalls, queue occupancy, prefetcher data, SoC active-core count).
 *        -> sweep (active-core count), timeline (switch latency), grid + fit (decision boundary)
 *  H2  US 9,378,148 B2 ("Adaptive hierarchical cache policy"): inclusive iff
 *      LLC capacity / core-cache capacity > ~5..10.  On a hybrid part the "core cache" may be
 *      the L2 of the ACTIVE cores only (P-core 2 MB each, E-core cluster 4 MB shared).
 *        -> sweep --order P / Epack / Espread / Psmt  (count-based vs capacity-based)
 *  H3  US 12,111,762 B2 ("Dynamic inclusive last level cache", DIL + SRP): per-line inclusion:
 *      LLC hit to an earlier MLC eviction while LHC > thr -> shared copy kept in LLC and the
 *      clean shared victim is silently dropped.
 *        -> probe -w l3,dram  (re-use vs streaming), grid
 *  H4  FLEXclusion (ISCA'12): set-dueling leader sets decide the mode.
 *        -> setscan (per-LLC-set-index indicator)
 *  H5  Yan et al. (S&P'19), Kim et al. (arXiv 2503.10074): snoop-filter / directory, latency
 *      classes, cross-core presence.
 *        -> xsnp indicator, calib
 *
 * Indicators (what "inclusive" means operationally)
 *  I1 "pmu"  (P-core only): fraction of L2 fills whose victim was dropped SILENTLY
 *            = L2_LINES_OUT.SILENT / L2_LINES_IN.ALL on a read-only workload.
 *            Inclusive -> clean victims dropped silently (~1).  Non-inclusive -> clean victims
 *            are written back to the L3 (~0).  (US12693977 col.1, US12111762 FIG.5, FLEXclusion T.1)
 *  I2 "ivt"  (timing only): inclusion-victim test.  Hot set X is kept in L2 while a stream Y
 *            churns the L3.  Strict inclusion -> L3 evictions back-invalidate X -> some X
 *            re-accesses take DRAM latency.  Non-inclusive -> ~0 DRAM-latency accesses.
 *  I3 "xsnp" (2 cores): probe core A reads X (clean, E state); helper core B then reads X.
 *            Inclusive -> B is served by the L3 after a snoop without forwarding (XSNP_NO_FWD).
 *            Non-inclusive -> the line must be forwarded from A's L2 (XSNP_FWD / HIT_E_F).
 * ---------------------------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/perf_event.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define VERSION "1.1"
#define MAXCPU 256
#define MAXEV 10
#define MAXST 16
#define HBINS 4096
#define KB (1UL << 10)
#define MB (1UL << 20)
#define HUGE2M (2UL << 20)
#define NEV(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* ============================== small utilities ============================== */
static int g_verbose = 0;
static volatile sig_atomic_t g_stop = 0;
static volatile uint64_t g_sink;
static double g_tsc_ghz = 0;
static int g_has_clflushopt = 0, g_has_cldemote = 0;

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...) {
  va_list ap;
  fflush(stdout);
  fprintf(stderr, "ERROR: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(1);
}
static void warnf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void warnf(const char *fmt, ...) {
  va_list ap;
  fflush(stdout);
  fprintf(stderr, "WARN: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}
static double now_s(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}
static void sleep_ms(double ms) {
  if (ms <= 0) return;
  struct timespec t;
  t.tv_sec = (time_t)(ms / 1000.0);
  t.tv_nsec = (long)((ms - (double)t.tv_sec * 1000.0) * 1e6);
  while (nanosleep(&t, &t) != 0 && errno == EINTR && !g_stop) {
  }
}
static inline uint64_t rdtsc_begin(void) {
  unsigned lo, hi;
  __asm__ __volatile__("lfence\n\trdtsc\n\tlfence" : "=a"(lo), "=d"(hi)::"memory");
  return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t rdtsc_end(void) {
  unsigned lo, hi, aux;
  __asm__ __volatile__("rdtscp\n\tlfence" : "=a"(lo), "=d"(hi), "=c"(aux)::"memory");
  return ((uint64_t)hi << 32) | lo;
}
static inline void cpu_pause(void) { __asm__ __volatile__("pause" ::: "memory"); }
static inline void mfence(void) { __asm__ __volatile__("mfence" ::: "memory"); }
static double sdiv(double a, double b) { return b > 0 ? a / b : NAN; }
/* main indicator: share of L2 evictions that were silent (clean drop) vs written back (non-silent).
   On RPL L2_LINES_OUT.NON_SILENT DOES count clean write-backs, and L2_LINES_IN.ALL is not a reliable denominator. */
static double silfrac(double sil, double nsil) { return (sil + nsil) > 0 ? sil / (sil + nsil) : NAN; }

static uint64_t g_rng = 0x243F6A8885A308D3ULL;
static inline uint64_t rng64(void) {
  uint64_t x = g_rng;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return g_rng = x;
}
static void shuffle_u32(uint32_t *a, size_t n) {
  if (n < 2) return;
  for (size_t i = n - 1; i > 0; i--) {
    size_t j = (size_t)(rng64() % (i + 1));
    uint32_t t = a[i];
    a[i] = a[j];
    a[j] = t;
  }
}
static int read_file(const char *path, char *buf, size_t n) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t r = read(fd, buf, n - 1);
  close(fd);
  if (r < 0) return -1;
  buf[r] = 0;
  while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == ' ')) buf[--r] = 0;
  return (int)r;
}
static long read_long(const char *path, long dflt) {
  char b[64];
  if (read_file(path, b, sizeof b) < 0) return dflt;
  return strtol(b, NULL, 0);
}
static int write_file(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t r = write(fd, s, strlen(s));
  close(fd);
  return r < 0 ? -1 : 0;
}
static long parse_size(const char *s) {
  char *e;
  double v = strtod(s, &e);
  switch (*e) {
    case 'k': case 'K': v *= 1024.0; break;
    case 'm': case 'M': v *= 1024.0 * 1024; break;
    case 'g': case 'G': v *= 1024.0 * 1024 * 1024; break;
    default: break;
  }
  return (long)v;
}
static int parse_cpulist(const char *s, int *out, int max) {
  int n = 0;
  const char *p = s;
  while (p && *p) {
    while (*p == ',' || *p == ' ' || *p == '+') p++;
    if (!*p) break;
    char *e;
    long a = strtol(p, &e, 10);
    if (e == p) break;
    long b = a;
    p = e;
    if (*p == '-') {
      p++;
      b = strtol(p, &e, 10);
      p = e;
    }
    for (long i = a; i <= b && n < max; i++) out[n++] = (int)i;
  }
  return n;
}
static void cpus_str(const int *v, int n, char *buf, size_t sz) {
  size_t o = 0;
  buf[0] = 0;
  for (int i = 0; i < n && o + 8 < sz; i++) o += (size_t)snprintf(buf + o, sz - o, "%s%d", i ? "+" : "", v[i]);
  if (n == 0) snprintf(buf, sz, "-");
}
static int pin_self(int cpu) {
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s);
  return pthread_setaffinity_np(pthread_self(), sizeof s, &s);
}

/* ============================== configuration ============================== */
typedef struct {
  int probe, helper;
  char method[64], workload[64], wlist[2048], schedule[1024];
  size_t ws, dram_ws, stride;
  int mlp, alu, seq;
  char active[1024], order[32], order_list[1024], nlist[512];
  int nactive;
  char spin[16], activate_by[16], idle_max[16], idle_cpus[1024];
  double settle_ms, meas_ms, warm_ms;
  int reps;
  char out[512];
  long long pf_msr;
  double window_us, duration_ms;
  int telemetry, updown;
  char features[512], label[64];
  double thr, lambda;
  char cpus[1024];
  double interval_ms, dur_s;
  int set_group, pages, slice_kb, ss_steps, xs_lines, xs_rounds, ivt_x, ivt_y;
  int no_thp;
} cfg_t;
static cfg_t C;

static void cfg_defaults(void) {
  memset(&C, 0, sizeof C);
  C.probe = -1;
  C.helper = -1;
  strcpy(C.workload, "l3");
  C.stride = 64;
  C.mlp = 8;
  C.nactive = -1;
  strcpy(C.order, "PE");
  strcpy(C.spin, "alu");
  strcpy(C.activate_by, "spin");
  C.settle_ms = 300;
  C.meas_ms = 30;
  C.warm_ms = 20;
  C.reps = 3;
  C.pf_msr = -1;
  C.window_us = 200;
  strcpy(C.label, "sil_frac");
  C.thr = 0.5;
  C.lambda = 1e-2;
  C.interval_ms = 500;
  C.set_group = 2;
  C.pages = 8;
  C.slice_kb = 3072;
  C.ss_steps = 2000;
  C.xs_lines = 2048;
  C.xs_rounds = 40;
  C.ivt_x = 4;
  C.ivt_y = 8;
}

/* ============================== topology ============================== */
typedef struct {
  int ncpu, hybrid;
  int online[MAXCPU];
  char type[MAXCPU]; /* 'P' (Core), 'E' (Atom) */
  int core_key[MAXCPU], l2_key[MAXCPU], sib[MAXCPU];
  long l2_size[MAXCPU];
  int l2_ways[MAXCPU], l2_sets[MAXCPU];
  long l3_size;
  int l3_ways, l3_sets;
} topo_t;
static topo_t T;

static int cache_index(int cpu, int level) {
  char p[256], b[64];
  for (int i = 0; i < 10; i++) {
    snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cache/index%d/level", cpu, i);
    if (read_file(p, b, sizeof b) < 0) continue;
    if (atoi(b) != level) continue;
    snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cache/index%d/type", cpu, i);
    if (read_file(p, b, sizeof b) >= 0 && strcmp(b, "Instruction") == 0) continue;
    return i;
  }
  return -1;
}
static long cache_attr(int cpu, int idx, const char *attr) {
  char p[256], b[256];
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cache/index%d/%s", cpu, idx, attr);
  if (read_file(p, b, sizeof b) < 0) return -1;
  return parse_size(b);
}
static void topo_init(void) {
  char buf[4096], path[256];
  int list[MAXCPU], n;
  memset(&T, 0, sizeof T);
  for (int i = 0; i < MAXCPU; i++) {
    T.sib[i] = -1;
    T.core_key[i] = i;
    T.l2_key[i] = i;
    T.type[i] = '?';
  }
  if (read_file("/sys/devices/system/cpu/online", buf, sizeof buf) >= 0)
    n = parse_cpulist(buf, list, MAXCPU);
  else {
    n = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (n > MAXCPU) n = MAXCPU;
    for (int i = 0; i < n; i++) list[i] = i;
  }
  for (int i = 0; i < n; i++) {
    if (list[i] < 0 || list[i] >= MAXCPU) continue;
    T.online[list[i]] = 1;
    if (list[i] + 1 > T.ncpu) T.ncpu = list[i] + 1;
  }
  int pc[MAXCPU], ec[MAXCPU], np = 0, ne = 0;
  if (read_file("/sys/devices/cpu_core/cpus", buf, sizeof buf) >= 0) np = parse_cpulist(buf, pc, MAXCPU);
  if (read_file("/sys/devices/cpu_atom/cpus", buf, sizeof buf) >= 0) ne = parse_cpulist(buf, ec, MAXCPU);
  for (int i = 0; i < np; i++)
    if (pc[i] >= 0 && pc[i] < MAXCPU) T.type[pc[i]] = 'P';
  for (int i = 0; i < ne; i++)
    if (ec[i] >= 0 && ec[i] < MAXCPU) T.type[ec[i]] = 'E';
  if (!np && !ne) { /* fall back to CPUID.1AH (hybrid core type) on every CPU */
    unsigned maxl = __get_cpuid_max(0, NULL);
    cpu_set_t old;
    pthread_getaffinity_np(pthread_self(), sizeof old, &old);
    for (int c = 0; c < T.ncpu; c++) {
      if (!T.online[c]) continue;
      if (maxl >= 0x1a && pin_self(c) == 0) {
        unsigned a, b, cc, d;
        __cpuid_count(0x1a, 0, a, b, cc, d);
        unsigned ct = a >> 24;
        if (ct == 0x20) T.type[c] = 'E';
        else if (ct == 0x40) T.type[c] = 'P';
        if (ct == 0x20) ne++;
        if (ct == 0x40) np++;
      }
    }
    pthread_setaffinity_np(pthread_self(), sizeof old, &old);
  }
  T.hybrid = np > 0 && ne > 0;
  for (int c = 0; c < T.ncpu; c++) {
    if (!T.online[c]) continue;
    if (T.type[c] == '?') T.type[c] = 'P';
    snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", c);
    if (read_file(path, buf, sizeof buf) >= 0) {
      int m = parse_cpulist(buf, list, MAXCPU), mn = c;
      for (int j = 0; j < m; j++) {
        if (list[j] < mn) mn = list[j];
        if (list[j] != c) T.sib[c] = list[j];
      }
      T.core_key[c] = mn;
    }
    int i2 = cache_index(c, 2);
    if (i2 >= 0) {
      snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", c, i2);
      if (read_file(path, buf, sizeof buf) >= 0) {
        int m = parse_cpulist(buf, list, MAXCPU), mn = c;
        for (int j = 0; j < m; j++)
          if (list[j] < mn) mn = list[j];
        T.l2_key[c] = mn;
      }
      T.l2_size[c] = cache_attr(c, i2, "size");
      T.l2_ways[c] = (int)cache_attr(c, i2, "ways_of_associativity");
      T.l2_sets[c] = (int)cache_attr(c, i2, "number_of_sets");
    }
    if (!T.l3_size) {
      int i3 = cache_index(c, 3);
      if (i3 >= 0) {
        T.l3_size = cache_attr(c, i3, "size");
        T.l3_ways = (int)cache_attr(c, i3, "ways_of_associativity");
        T.l3_sets = (int)cache_attr(c, i3, "number_of_sets");
      }
    }
  }
}
static long l2_of(int cpu) { return T.l2_size[cpu] > 0 ? T.l2_size[cpu] : (long)(2 * MB); }
static long l3_of(void) { return T.l3_size > 0 ? T.l3_size : (long)(36 * MB); }
static int l2_sets_of(int cpu) { return T.l2_sets[cpu] > 0 ? T.l2_sets[cpu] : 2048; }

static void detect_features(void) {
  unsigned a, b, c, d;
  if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
    g_has_clflushopt = (b >> 23) & 1;
    g_has_cldemote = (c >> 25) & 1;
  }
}
static void tsc_calibrate(void) {
  uint64_t t0 = rdtsc_begin();
  double s0 = now_s();
  sleep_ms(100);
  uint64_t t1 = rdtsc_end();
  double s1 = now_s();
  g_tsc_ghz = (double)(t1 - t0) / ((s1 - s0) * 1e9);
}

/* ============================== memory & kernels ============================== */
static double huge_backing(void *p, size_t sz) {
  FILE *f = fopen("/proc/self/smaps", "r");
  if (!f) return -1;
  char line[512];
  int in = 0;
  unsigned long long sum_kb = 0;
  uintptr_t pa = (uintptr_t)p, pe = pa + sz;
  while (fgets(line, sizeof line, f)) {
    unsigned long long a, b;
    char c;
    if (sscanf(line, "%llx-%llx %c", &a, &b, &c) == 3) {
      in = (a < pe && b > pa);
      continue;
    }
    if (in && strncmp(line, "AnonHugePages:", 14) == 0) {
      unsigned long long kb;
      if (sscanf(line + 14, "%llu", &kb) == 1) sum_kb += kb;
    }
  }
  fclose(f);
  double fr = (double)sum_kb * 1024.0 / (double)sz;
  return fr > 1.0 ? 1.0 : fr;
}
static size_t round2m(size_t s) { return (s + HUGE2M - 1) & ~(HUGE2M - 1); }
/* huge: 0 = normal pages, 1 = THP (madvise), 2 = try hugetlbfs first, then THP */
static void *alloc_mem(size_t size, int huge, double *huge_frac) {
  size_t sz = round2m(size);
  void *p = MAP_FAILED;
  if (huge == 2) p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
  int hugetlb = (p != MAP_FAILED);
  if (p == MAP_FAILED) {
    void *q = mmap(NULL, sz + HUGE2M, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) die("mmap(%zu MB) failed: %s", sz >> 20, strerror(errno));
    uintptr_t a = ((uintptr_t)q + HUGE2M - 1) & ~(uintptr_t)(HUGE2M - 1);
    if (a > (uintptr_t)q) munmap(q, a - (uintptr_t)q);
    uintptr_t qe = (uintptr_t)q + sz + HUGE2M;
    if (qe > a + sz) munmap((void *)(a + sz), qe - (a + sz));
    p = (void *)a;
    if (huge && !C.no_thp) madvise(p, sz, MADV_HUGEPAGE);
  }
  for (size_t i = 0; i < sz; i += 4096) ((volatile char *)p)[i] = 0;
  if (huge_frac) *huge_frac = hugetlb ? 1.0 : huge_backing(p, sz);
  return p;
}
static void free_mem(void *p, size_t size) {
  if (p) munmap(p, round2m(size));
}
static void flush_range(const void *p, size_t n) {
  const char *c = (const char *)p, *e = c + n;
  if (g_has_clflushopt)
    for (; c < e; c += 64) __asm__ __volatile__("clflushopt %0" ::"m"(*(const volatile char *)c));
  else
    for (; c < e; c += 64) __asm__ __volatile__("clflush %0" ::"m"(*(const volatile char *)c));
  mfence();
}
/* K independent pointer chains (memory-level parallelism = K), optional dependent ALU work per step */
#define DEF_CHASE(K)                                                                  \
  static uint64_t chase##K(char **h, uint64_t steps, int alu) {                       \
    char *p[K];                                                                       \
    uint64_t x = 1;                                                                   \
    for (int i = 0; i < K; i++) p[i] = h[i];                                          \
    for (uint64_t s = 0; s < steps; s++) {                                            \
      for (int i = 0; i < K; i++) p[i] = *(char *volatile *)p[i];                     \
      for (int a = 0; a < alu; a++) {                                                 \
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;                      \
        __asm__ __volatile__("" : "+r"(x));                                           \
      }                                                                               \
    }                                                                                 \
    for (int i = 0; i < K; i++) h[i] = p[i];                                          \
    return x;                                                                         \
  }
DEF_CHASE(1)
DEF_CHASE(2)
DEF_CHASE(3)
DEF_CHASE(4)
DEF_CHASE(6)
DEF_CHASE(8)
DEF_CHASE(12)
DEF_CHASE(16)
static int mlp_norm(int k) {
  static const int ok[] = {1, 2, 3, 4, 6, 8, 12, 16};
  int best = 1;
  for (int i = 0; i < 8; i++)
    if (ok[i] <= k) best = ok[i];
  return best;
}
static uint64_t chase(char **h, int k, uint64_t steps, int alu) {
  switch (k) {
    case 1: return chase1(h, steps, alu);
    case 2: return chase2(h, steps, alu);
    case 3: return chase3(h, steps, alu);
    case 4: return chase4(h, steps, alu);
    case 6: return chase6(h, steps, alu);
    case 8: return chase8(h, steps, alu);
    case 12: return chase12(h, steps, alu);
    default: return chase16(h, steps, alu);
  }
}
static uint64_t stream_read(const char *p, size_t bytes, size_t stride) {
  uint64_t s = 0;
  for (size_t o = 0; o + 4 * stride <= bytes; o += 4 * stride)
    s += *(const volatile uint64_t *)(p + o) + *(const volatile uint64_t *)(p + o + stride) +
         *(const volatile uint64_t *)(p + o + 2 * stride) + *(const volatile uint64_t *)(p + o + 3 * stride);
  return s;
}
/* one dependent load per step, each timed with fenced rdtsc / rdtscp, latency histogram in TSC ticks */
static void chase_timed_hist(char **head, size_t steps, uint32_t *hist) {
  char *p = *head;
  for (size_t i = 0; i < steps; i++) {
    uint64_t t0 = rdtsc_begin();
    p = *(char *volatile *)p;
    uint64_t t1 = rdtsc_end();
    uint64_t d = t1 - t0;
    if (d >= HBINS) d = HBINS - 1;
    hist[d]++;
  }
  *head = p;
}
static uint64_t hist_total(const uint32_t *h) {
  uint64_t n = 0;
  for (int i = 0; i < HBINS; i++) n += h[i];
  return n;
}
static double hist_quantile(const uint32_t *h, double q) {
  uint64_t n = hist_total(h);
  if (!n) return NAN;
  uint64_t k = (uint64_t)(q * (double)(n - 1)), c = 0;
  for (int i = 0; i < HBINS; i++) {
    c += h[i];
    if (c > k) return i;
  }
  return HBINS - 1;
}
static double hist_mean(const uint32_t *h) {
  double s = 0;
  uint64_t n = 0;
  for (int i = 0; i < HBINS; i++) {
    s += (double)i * h[i];
    n += h[i];
  }
  return n ? s / (double)n : NAN;
}
static uint64_t hist_ge(const uint32_t *h, uint32_t thr) {
  uint64_t n = 0;
  for (uint32_t i = thr; i < HBINS; i++) n += h[i];
  return n;
}

/* ---- workload buffers: one random (or sequential) cycle through all lines; K heads spaced evenly ---- */
enum { WL_L3 = 0, WL_DRAM = 1 };
typedef struct {
  int kind, seq;
  size_t ws, stride, nlines;
  char *buf;
  uint32_t *perm;
  double huge_frac;
} wbuf_t;
typedef struct {
  int kind, mlp, alu, seq;
  size_t ws, stride;
  char label[96];
  wbuf_t *b;
  char *h[16];
} wl_t;
static wbuf_t *g_wb[16];
static int g_nwb = 0;

static wbuf_t *wbuf_get(int kind, size_t ws, size_t stride, int seq) {
  for (int i = 0; i < g_nwb; i++)
    if (g_wb[i]->kind == kind && g_wb[i]->ws == ws && g_wb[i]->stride == stride && g_wb[i]->seq == seq) return g_wb[i];
  if (g_nwb == 16) die("too many distinct workload buffers");
  wbuf_t *b = calloc(1, sizeof *b);
  b->kind = kind;
  b->ws = ws;
  b->stride = stride;
  b->seq = seq;
  b->nlines = ws / stride;
  if (b->nlines < 64) die("working set too small");
  if (b->nlines > 0xffffffffUL) die("working set too large");
  b->buf = alloc_mem(ws, 1, &b->huge_frac);
  b->perm = malloc(b->nlines * sizeof(uint32_t));
  if (!b->perm) die("malloc");
  for (size_t i = 0; i < b->nlines; i++) b->perm[i] = (uint32_t)i;
  if (!seq) shuffle_u32(b->perm, b->nlines);
  for (size_t i = 0; i < b->nlines; i++) {
    char *cur = b->buf + (size_t)b->perm[i] * stride;
    *(char **)cur = b->buf + (size_t)b->perm[(i + 1) % b->nlines] * stride;
  }
  flush_range(b->buf, b->nlines * stride); /* lines must be CLEAN before measuring */
  g_wb[g_nwb++] = b;
  return b;
}
static size_t default_ws(int kind, int cpu) {
  size_t l2 = (size_t)l2_of(cpu), l3 = (size_t)l3_of();
  if (kind == WL_L3) {
    size_t ws = 4 * l2;
    if (ws > l3 / 2) ws = l3 / 2;
    return round2m(ws);
  }
  size_t ws = 8 * l3;
  if (ws < 256 * MB) ws = 256 * MB;
  return round2m(ws);
}
static void wl_setup(wl_t *w, int cpu) {
  if (!w->ws) w->ws = default_ws(w->kind, cpu);
  if (!w->stride) w->stride = 64;
  w->mlp = mlp_norm(w->mlp < 1 ? 1 : w->mlp);
  w->b = wbuf_get(w->kind, w->ws, w->stride, w->seq);
  for (int i = 0; i < w->mlp; i++) w->h[i] = w->b->buf + (size_t)w->b->perm[(w->b->nlines / (size_t)w->mlp) * (size_t)i] * w->stride;
  snprintf(w->label, sizeof w->label, "%s:ws=%zuK:mlp=%d:alu=%d:%s:stride=%zu", w->kind == WL_L3 ? "l3" : "dram", w->ws / KB, w->mlp,
           w->alu, w->seq ? "seq" : "rand", w->stride);
}
static int wl_parse(const char *spec, wl_t *w) {
  memset(w, 0, sizeof *w);
  w->mlp = C.mlp;
  w->alu = C.alu;
  w->seq = C.seq;
  w->stride = C.stride;
  char tmp[256];
  snprintf(tmp, sizeof tmp, "%s", spec);
  char *save = NULL, *tok = strtok_r(tmp, ":", &save);
  if (!tok) return -1;
  if (!strcasecmp(tok, "l3")) {
    w->kind = WL_L3;
    w->ws = C.ws;
  } else if (!strcasecmp(tok, "dram")) {
    w->kind = WL_DRAM;
    w->ws = C.dram_ws;
  } else
    return -1;
  while ((tok = strtok_r(NULL, ":", &save))) {
    char *eq = strchr(tok, '=');
    if (!eq) {
      if (!strcasecmp(tok, "seq")) w->seq = 1;
      else if (!strcasecmp(tok, "rand")) w->seq = 0;
      else return -1;
      continue;
    }
    *eq = 0;
    const char *k = tok, *v = eq + 1;
    if (!strcasecmp(k, "ws")) w->ws = (size_t)parse_size(v);
    else if (!strcasecmp(k, "mlp")) w->mlp = atoi(v);
    else if (!strcasecmp(k, "alu")) w->alu = atoi(v);
    else if (!strcasecmp(k, "stride")) w->stride = (size_t)parse_size(v);
    else if (!strcasecmp(k, "seq")) w->seq = atoi(v);
    else return -1;
  }
  return 0;
}
static uint64_t wl_run(wl_t *w, uint64_t steps) { return chase(w->h, w->mlp, steps, w->alu); }
static uint64_t wl_run_ms(wl_t *w, double ms) {
  if (ms <= 0) return 0;
  double t0 = now_s(), lim = ms * 1e-3;
  uint64_t steps = 0;
  do {
    g_sink += wl_run(w, 512);
    steps += 512;
  } while (now_s() - t0 < lim && !g_stop);
  return steps;
}

/* ============================== PMU (perf_event_open, hybrid aware) ============================== */
typedef struct {
  const char *name;
  uint64_t cfg;
} evdef_t;
#define EVC(e, u, c) ((uint64_t)(e) | ((uint64_t)(u) << 8) | ((uint64_t)(c) << 24))

/* Golden Cove / Raptor Cove (P-core) encodings: Intel perfmon "Alder Lake P-core events" */
/* G1: the essential group -- exactly 4 events that are restricted to counters 0-3, always counted together */
static const evdef_t EV_P_L2[] = {
    {"L2_LINES_IN.ALL", EVC(0x25, 0x1f, 0)},
    {"L2_LINES_OUT.SILENT", EVC(0x26, 0x01, 0)},
    {"L2_LINES_OUT.NON_SILENT", EVC(0x26, 0x02, 0)},
    {"L2_LINES_OUT.USELESS_HWPF", EVC(0x26, 0x04, 0)},
};
enum { E_IN, E_SIL, E_NSIL, E_USELESS };
/* G0: auxiliary group (fixed counters + any-counter events); may be multiplexed, values are scaled */
static const evdef_t EV_P_AUX[] = {
    {"CPU_CLK_UNHALTED.THREAD", EVC(0x3c, 0x00, 0)},
    {"INST_RETIRED.ANY", EVC(0xc0, 0x00, 0)},
    {"CPU_CLK_UNHALTED.REF_TSC", 0x0300}, /* fixed-counter pseudo encoding */
    {"LONGEST_LAT_CACHE.REFERENCE", EVC(0x2e, 0x4f, 0)},
    {"LONGEST_LAT_CACHE.MISS", EVC(0x2e, 0x41, 0)},
};
enum { A_CYC, A_INST, A_REFC, A_LLCREF, A_LLCMISS };
static const evdef_t EV_P_TEL1[] = {
    {"CYCLE_ACTIVITY.STALLS_TOTAL", EVC(0xa3, 0x04, 4)},
    {"CYCLE_ACTIVITY.STALLS_L3_MISS", EVC(0xa3, 0x06, 6)},
    {"OFFCORE_REQUESTS_OUTSTANDING.DATA_RD", EVC(0x20, 0x08, 0)},
    {"OFFCORE_REQUESTS_OUTSTANDING.CYCLES_WITH_DATA_RD", EVC(0x20, 0x08, 1)},
    {"CPU_CLK_UNHALTED.THREAD", EVC(0x3c, 0x00, 0)},
};
static const evdef_t EV_P_TEL2[] = {
    {"OFFCORE_REQUESTS.DATA_RD", EVC(0x21, 0x08, 0)},
    {"MEM_LOAD_RETIRED.L3_HIT", EVC(0xd1, 0x04, 0)},
    {"MEM_LOAD_RETIRED.L3_MISS", EVC(0xd1, 0x20, 0)},
    {"L2_RQSTS.MISS", EVC(0x24, 0x3f, 0)},
    {"INST_RETIRED.ANY", EVC(0xc0, 0x00, 0)},
};
static const evdef_t EV_P_XSNP[] = {
    {"MEM_LOAD_L3_HIT_RETIRED.XSNP_MISS", EVC(0xd2, 0x01, 0)},
    {"MEM_LOAD_L3_HIT_RETIRED.XSNP_NO_FWD", EVC(0xd2, 0x02, 0)},
    {"MEM_LOAD_L3_HIT_RETIRED.XSNP_FWD", EVC(0xd2, 0x04, 0)},
    {"MEM_LOAD_L3_HIT_RETIRED.XSNP_NONE", EVC(0xd2, 0x08, 0)},
};
/* Gracemont (E-core): no L2_LINES_OUT events are documented, only load data-source events */
static const evdef_t EV_E_XS[] = {
    {"MEM_LOAD_UOPS_RETIRED.L3_HIT", EVC(0xd1, 0x04, 0)},
    {"MEM_LOAD_UOPS_RETIRED_MISC.HIT_E_F", EVC(0xd2, 0x40, 0)},
    {"MEM_LOAD_UOPS_RETIRED.HITM", EVC(0xd1, 0x20, 0)},
    {"MEM_LOAD_UOPS_RETIRED.DRAM_HIT", EVC(0xd1, 0x80, 0)},
    {"MEM_LOAD_UOPS_RETIRED.L2_HIT", EVC(0xd1, 0x02, 0)},
};

static int g_pmu_core = -1, g_pmu_atom = -1, g_excl_kernel = 1;
static void pmu_init(void) {
  g_pmu_core = (int)read_long("/sys/bus/event_source/devices/cpu_core/type", -1);
  g_pmu_atom = (int)read_long("/sys/bus/event_source/devices/cpu_atom/type", -1);
  if (g_pmu_core < 0) g_pmu_core = (int)read_long("/sys/bus/event_source/devices/cpu/type", -1);
  g_excl_kernel = geteuid() != 0;
}
static int pmu_type_for(int cpu) {
  if (T.type[cpu] == 'E' && g_pmu_atom >= 0) return g_pmu_atom;
  return g_pmu_core;
}
typedef struct {
  int n;
  int fd[MAXEV];
  const char *name[MAXEV];
} pgrp_t;
typedef struct {
  uint64_t en, run, v[MAXEV];
} psnap_t;
static void pgrp_close(pgrp_t *g) {
  for (int i = 0; i < g->n; i++)
    if (g->fd[i] >= 0) close(g->fd[i]);
  g->n = 0;
}
static int pgrp_open(pgrp_t *g, int type, const evdef_t *ev, int n, pid_t pid, int cpu) {
  memset(g, 0, sizeof *g);
  if (type < 0 || n > MAXEV) {
    errno = ENODEV;
    return -1;
  }
  for (int i = 0; i < n; i++) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    a.type = (uint32_t)type;
    a.config = ev[i].cfg;
    a.disabled = (i == 0);
    a.exclude_hv = 1;
    a.exclude_kernel = (unsigned)g_excl_kernel;
    a.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    int fd = (int)syscall(__NR_perf_event_open, &a, pid, cpu, i == 0 ? -1 : g->fd[0], PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
      int e = errno;
      if (g_verbose) fprintf(stderr, "  perf_event_open(%s, type=%d, cpu=%d) failed: %s\n", ev[i].name, type, cpu, strerror(e));
      pgrp_close(g);
      errno = e;
      return -1;
    }
    g->fd[i] = fd;
    g->name[i] = ev[i].name;
    g->n = i + 1;
  }
  ioctl(g->fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
  ioctl(g->fd[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
  return 0;
}
static int pgrp_read(pgrp_t *g, psnap_t *s) {
  uint64_t buf[3 + MAXEV];
  memset(s, 0, sizeof *s);
  if (g->n <= 0) return -1;
  ssize_t r = read(g->fd[0], buf, sizeof buf);
  if (r < (ssize_t)(3 * sizeof(uint64_t))) return -1;
  s->en = buf[1];
  s->run = buf[2];
  for (int i = 0; i < g->n; i++) s->v[i] = buf[3 + i];
  return 0;
}
static void pdelta(const pgrp_t *g, const psnap_t *a, const psnap_t *b, double *out, double *run_frac) {
  uint64_t den = b->en - a->en, dr = b->run - a->run;
  double sc = dr ? (double)den / (double)dr : 0.0;
  for (int i = 0; i < g->n; i++) out[i] = (double)(b->v[i] - a->v[i]) * sc;
  if (run_frac) *run_frac = den ? (double)dr / (double)den : 0.0;
}

/* ============================== cpuidle residency & control ============================== */
typedef struct {
  int n;
  char name[MAXST][24];
} istates_t;
static istates_t g_ist[MAXCPU];
static int g_idle_orig[MAXCPU][MAXST], g_idle_saved[MAXCPU];
typedef struct {
  double wall;
  uint64_t t[MAXCPU][MAXST];
  uint64_t st_idle[MAXCPU], st_tot[MAXCPU]; /* /proc/stat jiffies (fallback when there is no cpuidle driver) */
} isnap_t;
static isnap_t *g_is0, *g_is1;

static void idle_init(void) {
  char p[256], b[64];
  for (int c = 0; c < T.ncpu; c++) {
    if (!T.online[c]) continue;
    for (int s = 0; s < MAXST; s++) {
      snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/name", c, s);
      if (read_file(p, b, sizeof b) < 0) break;
      snprintf(g_ist[c].name[s], sizeof g_ist[c].name[s], "%.23s", b);
      g_ist[c].n = s + 1;
    }
  }
  g_is0 = calloc(1, sizeof(isnap_t));
  g_is1 = calloc(1, sizeof(isnap_t));
}
static void idle_snap(isnap_t *s) {
  char p[256];
  for (int c = 0; c < T.ncpu; c++) {
    if (!T.online[c]) continue;
    for (int k = 0; k < g_ist[c].n; k++) {
      snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/time", c, k);
      s->t[c][k] = (uint64_t)read_long(p, 0);
    }
  }
  memset(s->st_idle, 0, sizeof s->st_idle);
  memset(s->st_tot, 0, sizeof s->st_tot);
  FILE *f = fopen("/proc/stat", "r");
  if (f) {
    char line[512];
    while (fgets(line, sizeof line, f)) {
      int c;
      unsigned long long v[10] = {0};
      if (strncmp(line, "cpu", 3) || line[3] < '0' || line[3] > '9') continue;
      int n = sscanf(line + 3, "%d %llu %llu %llu %llu %llu %llu %llu %llu", &c, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]);
      if (n < 6 || c < 0 || c >= MAXCPU) continue;
      unsigned long long tot = 0;
      for (int i = 0; i < 8; i++) tot += v[i];
      s->st_idle[c] = v[3] + v[4];
      s->st_tot[c] = tot;
    }
    fclose(f);
  }
  s->wall = now_s();
}
/* busy = fraction of wall time NOT spent in a hardware idle state (POLL counts as busy: core stays in C0) */
static void idle_busy(const isnap_t *a, const isnap_t *b, double *busy) {
  double dw = (b->wall - a->wall) * 1e6;
  for (int c = 0; c < T.ncpu; c++) {
    busy[c] = NAN;
    if (!T.online[c] || dw <= 0) continue;
    if (g_ist[c].n == 0) { /* no cpuidle driver: use OS idle time (HLT) from /proc/stat */
      uint64_t dt = b->st_tot[c] - a->st_tot[c], di = b->st_idle[c] - a->st_idle[c];
      if (b->st_tot[c] && a->st_tot[c] && dt > 0) {
        double x = 1.0 - (double)di / (double)dt;
        busy[c] = x < 0 ? 0 : x > 1 ? 1 : x;
      }
      continue;
    }
    double idle = 0;
    for (int k = 0; k < g_ist[c].n; k++) {
      if (!strcasecmp(g_ist[c].name[k], "POLL")) continue;
      idle += (double)(b->t[c][k] - a->t[c][k]);
    }
    double x = 1.0 - idle / dw;
    busy[c] = x < 0 ? 0 : x > 1 ? 1 : x;
  }
}
static int idle_find(int cpu, const char *name) {
  size_t L = strlen(name);
  for (int k = 0; k < g_ist[cpu].n; k++)
    if (!strcasecmp(g_ist[cpu].name[k], name)) return k;
  for (int k = 0; k < g_ist[cpu].n; k++)
    if (!strncasecmp(g_ist[cpu].name[k], name, L) && g_ist[cpu].name[k][L] == '_') return k;
  return -1;
}
static void idle_restore(int cpu) {
  char p[256], v[8];
  if (!g_idle_saved[cpu]) return;
  for (int k = 0; k < g_ist[cpu].n; k++) {
    snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/disable", cpu, k);
    snprintf(v, sizeof v, "%d", g_idle_orig[cpu][k]);
    write_file(p, v);
  }
  g_idle_saved[cpu] = 0;
}
/* allow only states up to (and including) maxname on this CPU */
static int idle_limit(int cpu, const char *maxname) {
  char p[256];
  int k = idle_find(cpu, maxname);
  if (k < 0) return -1;
  if (!g_idle_saved[cpu]) {
    for (int s = 0; s < g_ist[cpu].n; s++) {
      snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/disable", cpu, s);
      g_idle_orig[cpu][s] = (int)read_long(p, 0);
    }
    g_idle_saved[cpu] = 1;
  }
  int err = 0;
  for (int s = k + 1; s < g_ist[cpu].n; s++) {
    snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/disable", cpu, s);
    if (write_file(p, "1") < 0) err = -1;
  }
  return err;
}
static void idle_restore_all(void) {
  for (int c = 0; c < T.ncpu; c++) idle_restore(c);
}

/* ============================== MSR (prefetcher control 0x1A4) ============================== */
static int msr_rw(int cpu, uint32_t reg, uint64_t *val, int wr) {
  char p[64];
  snprintf(p, sizeof p, "/dev/cpu/%d/msr", cpu);
  int fd = open(p, (wr ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t r = wr ? pwrite(fd, val, 8, reg) : pread(fd, val, 8, reg);
  close(fd);
  return r == 8 ? 0 : -1;
}
static int g_pf_saved[MAXCPU];
static uint64_t g_pf_orig[MAXCPU];
static int pf_set(int cpu, uint64_t v) {
  if (!g_pf_saved[cpu]) {
    if (msr_rw(cpu, 0x1a4, &g_pf_orig[cpu], 0)) return -1;
    g_pf_saved[cpu] = 1;
  }
  return msr_rw(cpu, 0x1a4, &v, 1);
}
static void pf_restore_all(void) {
  for (int c = 0; c < MAXCPU; c++)
    if (g_pf_saved[c]) {
      msr_rw(c, 0x1a4, &g_pf_orig[c], 1);
      g_pf_saved[c] = 0;
    }
}

/* ============================== "active core" generators ============================== */
enum { SP_SLEEP = 0, SP_RUN = 1, SP_EXIT = 2 };
enum { SPK_ALU, SPK_PAUSE, SPK_L2, SPK_LLC, SPK_MEM };
typedef struct {
  int cpu, kind, created;
  pthread_t th;
  _Atomic int state;
  pthread_mutex_t mu;
  pthread_cond_t cv;
  char *buf;
  size_t bufsz;
  char *head[4];
} spinner_t;
static spinner_t g_sp[MAXCPU];
static int g_spin_kind = SPK_ALU, g_act_c1 = 0, g_park_off = 0;
static int g_pool[MAXCPU], g_npool = 0;  /* candidate CPUs of the current order (for --park offline) */
static char g_offlined[MAXCPU];          /* CPUs this program took offline (restored at exit) */
static int cpu_set_online(int cpu, int on) {
  char p[128];
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/online", cpu);
  if (on && !g_offlined[cpu]) return 0;
  if (write_file(p, on ? "1" : "0") < 0) return -1;
  g_offlined[cpu] = !on;
  return 0;
}
static void online_restore_all(void) {
  for (int c = 0; c < MAXCPU; c++)
    if (g_offlined[c]) cpu_set_online(c, 1);
}
static int g_cur_act[MAXCPU], g_ncur = 0;

static void *spinner_main(void *arg) {
  spinner_t *s = (spinner_t *)arg;
  pin_self(s->cpu);
  uint64_t x = (uint64_t)s->cpu * 0x9E3779B97F4A7C15ULL + 1;
  size_t pos = 0;
  if (s->kind == SPK_L2 || s->kind == SPK_LLC || s->kind == SPK_MEM) {
    size_t sz = s->kind == SPK_L2 ? (size_t)l2_of(s->cpu) / 4 : s->kind == SPK_LLC ? 4 * (size_t)l2_of(s->cpu) : 64 * MB;
    s->bufsz = round2m(sz);
    s->buf = alloc_mem(s->bufsz, 1, NULL);
    if (s->kind != SPK_MEM) {
      size_t n = s->bufsz / 64;
      uint32_t *perm = malloc(n * sizeof(uint32_t));
      for (size_t i = 0; i < n; i++) perm[i] = (uint32_t)i;
      shuffle_u32(perm, n);
      for (size_t i = 0; i < n; i++) *(char **)(s->buf + (size_t)perm[i] * 64) = s->buf + (size_t)perm[(i + 1) % n] * 64;
      for (int k = 0; k < 4; k++) s->head[k] = s->buf + (size_t)perm[(n / 4) * (size_t)k] * 64;
      free(perm);
    }
  }
  for (;;) {
    int st = atomic_load_explicit(&s->state, memory_order_acquire);
    if (st == SP_EXIT) break;
    if (st == SP_SLEEP) {
      pthread_mutex_lock(&s->mu);
      while (atomic_load(&s->state) == SP_SLEEP) pthread_cond_wait(&s->cv, &s->mu);
      pthread_mutex_unlock(&s->mu);
      pin_self(s->cpu); /* the CPU may have been offlined/onlined meanwhile (kernel resets affinity) */
      continue;
    }
    switch (s->kind) {
      case SPK_ALU:
        for (int i = 0; i < 20000; i++) {
          x = x * 6364136223846793005ULL + 1442695040888963407ULL;
          __asm__ __volatile__("" : "+r"(x));
        }
        break;
      case SPK_PAUSE:
        for (int i = 0; i < 64; i++) cpu_pause();
        break;
      case SPK_L2:
      case SPK_LLC: x += chase4(s->head, 2048, 0); break;
      default:
        if (pos + 256 * KB > s->bufsz) pos = 0;
        x += stream_read(s->buf + pos, 256 * KB, 64);
        pos += 256 * KB;
        break;
    }
  }
  g_sink += x;
  if (s->buf) free_mem(s->buf, s->bufsz);
  s->buf = NULL;
  return NULL;
}
static void spinner_set(int cpu, int run) {
  spinner_t *s = &g_sp[cpu];
  if (!s->created) {
    if (!run) return;
    s->cpu = cpu;
    s->kind = g_spin_kind;
    atomic_init(&s->state, SP_RUN);
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->cv, NULL);
    if (pthread_create(&s->th, NULL, spinner_main, s)) die("pthread_create");
    s->created = 1;
    return;
  }
  pthread_mutex_lock(&s->mu);
  atomic_store(&s->state, run ? SP_RUN : SP_SLEEP);
  pthread_cond_signal(&s->cv);
  pthread_mutex_unlock(&s->mu);
}
static void spinners_stop_all(void) {
  for (int c = 0; c < MAXCPU; c++) {
    spinner_t *s = &g_sp[c];
    if (!s->created) continue;
    pthread_mutex_lock(&s->mu);
    atomic_store(&s->state, SP_EXIT);
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->mu);
    pthread_join(s->th, NULL);
    s->created = 0;
  }
}
/* make exactly cpus[0..n) "active" (spinning, or held in C1 when --activate-by c1) */
static void activate_set(const int *cpus, int n) {
  char want[MAXCPU];
  memset(want, 0, sizeof want);
  for (int i = 0; i < n; i++)
    if (cpus[i] >= 0 && cpus[i] < MAXCPU) want[cpus[i]] = 1;
  if (g_park_off) { /* bring wanted CPUs online first, then park the rest of the pool offline */
    static int warned0 = 0;
    for (int i = 0; i < n; i++)
      if (cpu_set_online(cpus[i], 1) < 0) warnf("cannot online cpu%d", cpus[i]);
    for (int i = 0; i < g_npool; i++) {
      int c = g_pool[i];
      if (want[c]) continue;
      if (g_sp[c].created) spinner_set(c, 0);
      if (!g_offlined[c] && cpu_set_online(c, 0) < 0 && !(c == 0 && warned0++)) warnf("cannot offline cpu%d (stays idle in HLT)", c);
    }
  }
  if (g_act_c1) {
    for (int i = 0; i < g_ncur; i++)
      if (!want[g_cur_act[i]]) idle_restore(g_cur_act[i]);
    for (int i = 0; i < n; i++)
      if (idle_limit(cpus[i], "C1") < 0) warnf("cannot limit cpu%d to C1 (need root / cpuidle sysfs)", cpus[i]);
  } else {
    for (int c = 0; c < T.ncpu; c++)
      if (g_sp[c].created || want[c]) spinner_set(c, want[c]);
  }
  memcpy(g_cur_act, cpus, (size_t)n * sizeof(int));
  g_ncur = n;
}

/* ============================== cleanup / signals ============================== */
static void cleanup(void) {
  online_restore_all();
  spinners_stop_all();
  idle_restore_all();
  pf_restore_all();
}
static void on_sig(int s) {
  (void)s;
  if (g_stop) _exit(130);
  g_stop = 1;
}

/* ============================== latency calibration ============================== */
typedef struct {
  double l1, l2, l3, dram; /* median TSC ticks per timed dependent load */
  uint32_t thr_l3, thr_dram;
  int ok;
} calib_t;
static double calib_level(size_t bytes, size_t nload) {
  double hf;
  char *b = alloc_mem(bytes, 1, &hf);
  size_t n = round2m(bytes) / 64;
  if (bytes < HUGE2M) n = bytes / 64;
  uint32_t *perm = malloc(n * sizeof(uint32_t));
  for (size_t i = 0; i < n; i++) perm[i] = (uint32_t)i;
  shuffle_u32(perm, n);
  for (size_t i = 0; i < n; i++) *(char **)(b + (size_t)perm[i] * 64) = b + (size_t)perm[(i + 1) % n] * 64;
  char *h = b + (size_t)perm[0] * 64;
  free(perm);
  flush_range(b, n * 64);
  size_t warm = 2 * n;
  if (warm > 4000000) warm = 4000000;
  g_sink += chase(&h, 1, warm, 0);
  uint32_t *hist = calloc(HBINS, sizeof(uint32_t));
  chase_timed_hist(&h, nload, hist);
  double med = hist_quantile(hist, 0.5);
  free(hist);
  free_mem(b, bytes);
  return med;
}
static void calibrate(int cpu, calib_t *c, int print) {
  size_t l2 = (size_t)l2_of(cpu), l3 = (size_t)l3_of();
  size_t s2 = l2 / 4, s3 = 4 * l2, sd = 8 * l3;
  if (s3 > l3 / 2) s3 = l3 / 2;
  if (sd < 512 * MB) sd = 512 * MB;
  double tw = now_s();
  while (now_s() - tw < 0.3) g_sink += rng64(); /* let the core ramp up its clock first */
  c->l1 = calib_level(16 * KB, 20000);
  c->l2 = calib_level(s2, 50000);
  c->l3 = calib_level(s3, 50000);
  c->dram = calib_level(sd, 20000);
  c->thr_l3 = (uint32_t)((c->l2 + c->l3) / 2);
  c->thr_dram = (uint32_t)(c->l3 + 0.4 * (c->dram - c->l3));
  c->ok = c->dram > c->l3 * 1.3 && c->l3 > c->l2;
  if (print) {
    printf("latency calibration on cpu%d (%c-core), median per timed load incl. rdtsc overhead, TSC %.3f GHz\n", cpu, T.type[cpu], g_tsc_ghz);
    printf("  L1   (16 KB)    : %6.0f ticks  %6.1f ns\n", c->l1, c->l1 / g_tsc_ghz);
    printf("  L2   (%5zu KB) : %6.0f ticks  %6.1f ns\n", s2 / KB, c->l2, c->l2 / g_tsc_ghz);
    printf("  L3   (%5zu KB) : %6.0f ticks  %6.1f ns\n", s3 / KB, c->l3, c->l3 / g_tsc_ghz);
    printf("  DRAM (%5zu MB) : %6.0f ticks  %6.1f ns\n", sd / MB, c->dram, c->dram / g_tsc_ghz);
    printf("  thresholds: L3-class >= %u ticks, DRAM-class >= %u ticks %s\n", c->thr_l3, c->thr_dram, c->ok ? "" : "(SUSPICIOUS: levels not separated)");
  }
}

/* ============================== I1: L2 silent-drop fraction ============================== */
typedef struct {
  double fills, sil, nsil, useless, llc_ref, llc_miss, cyc, inst, refc, run_frac, secs, loads;
  int tel;
  double st_tot, st_l3, occ, occ_cyc, cyc_t, offreq, l3hit, l3miss, l2miss, inst_t;
} i1_t;
static pgrp_t g_g1, g_g0;
static int g_g1_open = 0, g_g0_open = 0;
static int i1_open(int cpu) {
  if (g_g1_open) return 0;
  if (T.type[cpu] == 'E') return -1;
  if (pgrp_open(&g_g1, pmu_type_for(cpu), EV_P_L2, NEV(EV_P_L2), 0, -1) < 0) return -1;
  g_g1_open = 1;
  int e = errno;
  g_g0_open = pgrp_open(&g_g0, pmu_type_for(cpu), EV_P_AUX, NEV(EV_P_AUX), 0, -1) == 0;
  if (!g_g0_open) warnf("auxiliary PMU group (cycles/instructions/LLC) unavailable: IPC/GHz columns will be empty");
  errno = e;
  return 0;
}
static int i1_measure(wl_t *w, double warm_ms, double meas_ms, int tel, i1_t *r) {
  memset(r, 0, sizeof *r);
  if (!g_g1_open) return -1;
  pgrp_t t1, t2;
  int tok = 0;
  if (tel && pgrp_open(&t1, g_pmu_core, EV_P_TEL1, NEV(EV_P_TEL1), 0, -1) == 0) {
    if (pgrp_open(&t2, g_pmu_core, EV_P_TEL2, NEV(EV_P_TEL2), 0, -1) == 0) tok = 1;
    else pgrp_close(&t1);
  }
  if (tel && !tok) warnf("telemetry event groups could not be opened (run with -v for details)");
  wl_run_ms(w, warm_ms);
  psnap_t a, b, a0, b0, a1, b1, a2, b2;
  int rc = pgrp_read(&g_g1, &a);
  if (g_g0_open) pgrp_read(&g_g0, &a0);
  if (tok) {
    pgrp_read(&t1, &a1);
    pgrp_read(&t2, &a2);
  }
  double s0 = now_s();
  uint64_t st = wl_run_ms(w, meas_ms);
  double s1 = now_s();
  rc |= pgrp_read(&g_g1, &b);
  if (g_g0_open) pgrp_read(&g_g0, &b0);
  if (tok) {
    pgrp_read(&t1, &b1);
    pgrp_read(&t2, &b2);
  }
  double d[MAXEV];
  if (rc == 0) {
    pdelta(&g_g1, &a, &b, d, &r->run_frac);
    r->fills = d[E_IN];
    r->sil = d[E_SIL];
    r->nsil = d[E_NSIL];
    r->useless = d[E_USELESS];
  }
  if (g_g0_open) {
    pdelta(&g_g0, &a0, &b0, d, NULL);
    r->cyc = d[A_CYC];
    r->inst = d[A_INST];
    r->refc = d[A_REFC];
    r->llc_ref = d[A_LLCREF];
    r->llc_miss = d[A_LLCMISS];
  } else
    r->cyc = r->inst = r->refc = r->llc_ref = r->llc_miss = NAN;
  r->secs = s1 - s0;
  r->loads = (double)st * w->mlp;
  if (tok) {
    pdelta(&t1, &a1, &b1, d, NULL);
    r->st_tot = d[0];
    r->st_l3 = d[1];
    r->occ = d[2];
    r->occ_cyc = d[3];
    r->cyc_t = d[4];
    pdelta(&t2, &a2, &b2, d, NULL);
    r->offreq = d[0];
    r->l3hit = d[1];
    r->l3miss = d[2];
    r->l2miss = d[3];
    r->inst_t = d[4];
    r->tel = 1;
    pgrp_close(&t1);
    pgrp_close(&t2);
  }
  return rc;
}
static const char *verdict_sil(double s) {
  if (isnan(s)) return "?";
  if (s >= 0.7) return "INCL";
  if (s <= 0.3) return "NONINCL";
  return "MIXED";
}

/* ============================== I2: inclusion-victim test (timing) ============================== */
typedef struct {
  char *x, *y, *xh;
  size_t xbytes, xlines, ybytes, ypos, ychunk;
  double hf;
  int ok;
} ivt_ctx_t;
typedef struct {
  double n, dram_frac, l3_frac, mean_ns, med_ns, expect;
} ivt_t;
static void ivt_prepare(ivt_ctx_t *c, int cpu) {
  int sets = l2_sets_of(cpu);
  c->xbytes = (size_t)sets * 64 * (size_t)C.ivt_x;
  c->xlines = c->xbytes / 64;
  c->x = alloc_mem(c->xbytes, 1, &c->hf);
  uint32_t *perm = malloc(c->xlines * sizeof(uint32_t));
  for (size_t i = 0; i < c->xlines; i++) perm[i] = (uint32_t)i;
  shuffle_u32(perm, c->xlines);
  for (size_t i = 0; i < c->xlines; i++) *(char **)(c->x + (size_t)perm[i] * 64) = c->x + (size_t)perm[(i + 1) % c->xlines] * 64;
  c->xh = c->x + (size_t)perm[0] * 64;
  free(perm);
  c->ybytes = round2m(8 * (size_t)l3_of());
  if (c->ybytes < 256 * MB) c->ybytes = 256 * MB;
  c->y = alloc_mem(c->ybytes, 1, NULL);
  c->ychunk = (size_t)sets * 64 * (size_t)C.ivt_y;
  c->ypos = 0;
  flush_range(c->x, c->xbytes);
  flush_range(c->y, c->ybytes);
  if (c->hf >= 0 && c->hf < 0.99)
    warnf("IVT hot set is not fully backed by 2MB pages (%.0f%%): L2 set coverage is uneven, the test is noisier", c->hf * 100);
  c->ok = 1;
}
static void ivt_stream(ivt_ctx_t *c) {
  if (c->ypos + c->ychunk > c->ybytes) c->ypos = 0;
  g_sink += stream_read(c->y + c->ypos, c->ychunk, 64);
  c->ypos += c->ychunk;
}
static void ivt_run(ivt_ctx_t *c, const calib_t *cal, ivt_t *r) {
  static uint32_t hist[HBINS];
  memset(hist, 0, sizeof hist);
  memset(r, 0, sizeof *r);
  size_t passes = ((size_t)l3_of() + c->ychunk - 1) / c->ychunk;
  for (size_t p = 0; p < passes && !g_stop; p++) {
    ivt_stream(c);
    g_sink += chase(&c->xh, 1, c->xlines, 0);
  }
  for (size_t p = 0; p < 3 * passes && !g_stop; p++) {
    ivt_stream(c);
    chase_timed_hist(&c->xh, c->xlines, hist);
  }
  uint64_t n = hist_total(hist);
  r->n = (double)n;
  /* strict inclusion: every LLC churn of size L3 back-invalidates each X line once -> expected DRAM fraction */
  r->expect = (double)c->ychunk / (double)l3_of();
  if (!n) return;
  uint64_t gd = hist_ge(hist, cal->thr_dram), g3 = hist_ge(hist, cal->thr_l3);
  r->dram_frac = (double)gd / (double)n;
  r->l3_frac = (double)(g3 - gd) / (double)n;
  r->mean_ns = hist_mean(hist) / g_tsc_ghz;
  r->med_ns = hist_quantile(hist, 0.5) / g_tsc_ghz;
}

/* ============================== I3: cross-core presence test ============================== */
enum { XS_REF_LLC, XS_REF_FWD, XS_TEST_DRAM, XS_TEST_L3, XS_NV };
static const char *XS_NAME[XS_NV] = {"REF_LLC  (line only in L3)", "REF_FWD  (M line in A's L2)", "TEST_DRAM(A read from DRAM)",
                                     "TEST_L3  (A read via L3 hit)"};
#define XS_STRIDE 256
typedef struct {
  _Alignas(64) _Atomic int cmd;
  _Alignas(64) _Atomic int done;
  _Alignas(64) int helper, round, pmu_ok, nev;
  char *x, *bh, *ah[8];
  size_t xlines;
  char *ev, *evh[8];
  size_t evlines, evbytes;
  uint32_t hist[HBINS];
  double pmu[MAXEV];
  const char *evname[MAXEV];
  pthread_t th;
  int started;
} xs_ctx_t;
typedef struct {
  double med_ns[XS_NV], p90_ns[XS_NV], loads[XS_NV], ev[XS_NV][MAXEV];
  int nev, pmu_ok;
  const char *evname[MAXEV];
} xs_t;

static void *xs_helper(void *arg) {
  xs_ctx_t *c = (xs_ctx_t *)arg;
  pin_self(c->helper);
  pgrp_t g;
  int ok;
  if (T.type[c->helper] == 'E')
    ok = pgrp_open(&g, pmu_type_for(c->helper), EV_E_XS, NEV(EV_E_XS), 0, -1) == 0;
  else
    ok = pgrp_open(&g, pmu_type_for(c->helper), EV_P_XSNP, NEV(EV_P_XSNP), 0, -1) == 0;
  if (ok) {
    c->nev = g.n;
    for (int i = 0; i < g.n; i++) c->evname[i] = g.name[i];
  }
  c->pmu_ok = ok;
  int last = 0;
  atomic_store_explicit(&c->done, -1, memory_order_release); /* ready */
  for (;;) {
    int cmd;
    while ((cmd = atomic_load_explicit(&c->cmd, memory_order_acquire)) == last) cpu_pause();
    if (cmd < 0) break;
    last = cmd;
    psnap_t a, b;
    if (ok) pgrp_read(&g, &a);
    char *p = c->bh;
    chase_timed_hist(&p, c->xlines, c->hist);
    c->bh = p;
    if (ok) {
      pgrp_read(&g, &b);
      double d[MAXEV];
      pdelta(&g, &a, &b, d, NULL);
      for (int i = 0; i < g.n; i++) c->pmu[i] += d[i];
    }
    atomic_store_explicit(&c->done, cmd, memory_order_release);
  }
  if (ok) pgrp_close(&g);
  return NULL;
}
static xs_ctx_t *xs_init(int probe, int helper) {
  xs_ctx_t *c = aligned_alloc(64, (sizeof(xs_ctx_t) + 63) & ~(size_t)63);
  memset(c, 0, sizeof *c);
  c->helper = helper;
  c->xlines = (size_t)C.xs_lines;
  size_t xb = c->xlines * XS_STRIDE;
  c->x = alloc_mem(xb, 1, NULL);
  uint32_t *pa = malloc(c->xlines * sizeof(uint32_t)), *pb = malloc(c->xlines * sizeof(uint32_t));
  for (size_t i = 0; i < c->xlines; i++) pa[i] = pb[i] = (uint32_t)i;
  shuffle_u32(pa, c->xlines);
  shuffle_u32(pb, c->xlines);
  for (size_t i = 0; i < c->xlines; i++) {
    *(char **)(c->x + (size_t)pa[i] * XS_STRIDE) = c->x + (size_t)pa[(i + 1) % c->xlines] * XS_STRIDE;           /* A: offset 0 */
    *(char **)(c->x + (size_t)pb[i] * XS_STRIDE + 8) = c->x + (size_t)pb[(i + 1) % c->xlines] * XS_STRIDE + 8; /* B: offset 8 */
  }
  for (int k = 0; k < 8; k++) c->ah[k] = c->x + (size_t)pa[(c->xlines / 8) * (size_t)k] * XS_STRIDE;
  c->bh = c->x + (size_t)pb[0] * XS_STRIDE + 8;
  free(pa);
  free(pb);
  c->evbytes = round2m(4 * (size_t)l2_of(probe));
  c->ev = alloc_mem(c->evbytes, 1, NULL);
  c->evlines = c->evbytes / 64;
  uint32_t *pe = malloc(c->evlines * sizeof(uint32_t));
  for (size_t i = 0; i < c->evlines; i++) pe[i] = (uint32_t)i;
  shuffle_u32(pe, c->evlines);
  for (size_t i = 0; i < c->evlines; i++) *(char **)(c->ev + (size_t)pe[i] * 64) = c->ev + (size_t)pe[(i + 1) % c->evlines] * 64;
  for (int k = 0; k < 8; k++) c->evh[k] = c->ev + (size_t)pe[(c->evlines / 8) * (size_t)k] * 64;
  free(pe);
  flush_range(c->ev, c->evbytes);
  atomic_init(&c->cmd, 0);
  atomic_init(&c->done, 0);
  if (pthread_create(&c->th, NULL, xs_helper, c)) die("pthread_create(helper)");
  c->started = 1;
  while (atomic_load(&c->done) != -1) cpu_pause();
  return c;
}
static void xs_stop(xs_ctx_t *c) {
  if (!c || !c->started) return;
  atomic_store(&c->cmd, -1);
  pthread_join(c->th, NULL);
  c->started = 0;
}
static void xs_round(xs_ctx_t *c, int v) {
  flush_range(c->x, c->xlines * XS_STRIDE);
  switch (v) {
    case XS_TEST_DRAM: g_sink += chase(c->ah, 8, c->xlines / 8, 0); break;
    case XS_TEST_L3:
      g_sink += chase(c->ah, 8, c->xlines / 8, 0);
      g_sink += chase(c->evh, 8, c->evlines / 8, 0);
      g_sink += chase(c->ah, 8, c->xlines / 8, 0);
      break;
    case XS_REF_FWD:
      for (size_t i = 0; i < c->xlines; i++) *(volatile uint64_t *)(c->x + i * XS_STRIDE + 16) += 1;
      break;
    default: /* XS_REF_LLC */
      g_sink += chase(c->ah, 8, c->xlines / 8, 0);
      g_sink += chase(c->evh, 8, c->evlines / 8, 0);
      break;
  }
  mfence();
  int r = ++c->round;
  atomic_store_explicit(&c->cmd, r, memory_order_release);
  while (atomic_load_explicit(&c->done, memory_order_acquire) != r) cpu_pause();
}
static void xs_measure(xs_ctx_t *c, xs_t *o) {
  memset(o, 0, sizeof *o);
  for (int v = 0; v < XS_NV && !g_stop; v++) {
    memset(c->hist, 0, sizeof c->hist);
    memset(c->pmu, 0, sizeof c->pmu);
    xs_round(c, v); /* warm-up round, discarded */
    memset(c->hist, 0, sizeof c->hist);
    memset(c->pmu, 0, sizeof c->pmu);
    for (int r = 0; r < C.xs_rounds && !g_stop; r++) xs_round(c, v);
    o->med_ns[v] = hist_quantile(c->hist, 0.5) / g_tsc_ghz;
    o->p90_ns[v] = hist_quantile(c->hist, 0.9) / g_tsc_ghz;
    o->loads[v] = (double)hist_total(c->hist);
    for (int i = 0; i < c->nev; i++) o->ev[v][i] = c->pmu[i];
  }
  o->nev = c->nev;
  o->pmu_ok = c->pmu_ok;
  for (int i = 0; i < c->nev; i++) o->evname[i] = c->evname[i];
}
static void xs_print(const xs_t *o, int helper) {
  printf("    xsnp (helper cpu%d, %c-core) median/p90 latency of helper's loads, PMU fraction per load:\n", helper, T.type[helper]);
  printf("      %-28s %7s %7s", "variant", "med_ns", "p90_ns");
  for (int i = 0; i < o->nev; i++) {
    const char *nm = strrchr(o->evname[i], '.');
    printf(" %9.9s", nm ? nm + 1 : o->evname[i]);
  }
  printf("\n");
  for (int v = 0; v < XS_NV; v++) {
    printf("      %-28s %7.1f %7.1f", XS_NAME[v], o->med_ns[v], o->p90_ns[v]);
    for (int i = 0; i < o->nev; i++) printf(" %9.3f", sdiv(o->ev[v][i], o->loads[v]));
    printf("\n");
  }
  double t = o->med_ns[XS_TEST_DRAM], l = o->med_ns[XS_REF_LLC], f = o->med_ns[XS_REF_FWD];
  if (!isnan(t) && !isnan(l) && !isnan(f) && fabs(f - l) > 3)
    printf("      timing: TEST_DRAM is closer to %s\n", fabs(t - l) < fabs(t - f) ? "REF_LLC (served by L3 -> A's clean line IS in L3 -> inclusive-like)"
                                                                                  : "REF_FWD (forwarded by A -> line NOT in L3 -> non-inclusive-like)");
}

/* ============================== experiment context ============================== */
#define M_PMU 1
#define M_IVT 2
#define M_XS 4
typedef struct {
  int probe, helper, methods, wlmask;
  wl_t wl[2];
  calib_t cal;
  ivt_ctx_t ivt;
  xs_ctx_t *xs;
  int order[MAXCPU], norder;
} ctx_t;
typedef struct {
  int n_req, nact, nP, nE;
  double act_l2_mb, l3_l2_ratio; /* US 9,378,148: LLC capacity / capacity of the L2s that belong to active cores */
  int act[MAXCPU];
  int busy_cores, busy_P, busy_E;
  i1_t i1[2];
  int have_i1[2], have_ivt, have_xs;
  ivt_t ivt;
  xs_t xs;
  char verdict[32];
} point_t;

static int pick_probe(void) {
  for (int c = 0; c < T.ncpu; c++)
    if (T.online[c] && T.type[c] == 'P' && T.core_key[c] == c && T.core_key[c] != T.core_key[0]) return c;
  for (int c = 1; c < T.ncpu; c++)
    if (T.online[c]) return c;
  return 0;
}
static int pick_helper(int probe) {
  for (int c = 0; c < T.ncpu; c++)
    if (T.online[c] && T.type[c] == 'P' && T.core_key[c] == c && T.core_key[c] != T.core_key[0] && T.core_key[c] != T.core_key[probe])
      return c;
  for (int c = 0; c < T.ncpu; c++)
    if (T.online[c] && T.core_key[c] != T.core_key[probe]) return c;
  return -1;
}
static int build_order(const char *name, int probe, int helper, int *out) {
  int n = 0, excl[MAXCPU];
  memset(excl, 0, sizeof excl);
  if (probe >= 0) excl[T.core_key[probe]] = 1;
  if (helper >= 0) excl[T.core_key[helper]] = 1;
  if (C.order_list[0]) {
    int tmp[MAXCPU], m = parse_cpulist(C.order_list, tmp, MAXCPU);
    for (int i = 0; i < m; i++) {
      if (tmp[i] < 0 || tmp[i] >= T.ncpu || !T.online[tmp[i]]) continue;
      if (excl[T.core_key[tmp[i]]]) {
        warnf("order-list: cpu%d shares a core with the probe/helper, skipped", tmp[i]);
        continue;
      }
      out[n++] = tmp[i];
    }
    return n;
  }
  int P1[MAXCPU], P2[MAXCPU], E[MAXCPU], nP1 = 0, nP2 = 0, nE = 0;
  for (int c = 0; c < T.ncpu; c++) {
    if (!T.online[c] || excl[T.core_key[c]]) continue;
    if (T.type[c] == 'E') E[nE++] = c;
    else if (T.core_key[c] == c) P1[nP1++] = c;
    else P2[nP2++] = c;
  }
  for (int i = 1; i < nE; i++) { /* sort E-cores by (cluster, cpu) */
    int v = E[i], j = i - 1;
    while (j >= 0 && (T.l2_key[E[j]] > T.l2_key[v] || (T.l2_key[E[j]] == T.l2_key[v] && E[j] > v))) {
      E[j + 1] = E[j];
      j--;
    }
    E[j + 1] = v;
  }
  int Es[MAXCPU], nEs = 0, used[MAXCPU];
  memset(used, 0, sizeof used);
  while (nEs < nE) { /* round-robin over clusters */
    int lastkey = -1;
    for (int i = 0; i < nE; i++) {
      if (used[i] || T.l2_key[E[i]] == lastkey) continue; /* E[] is sorted by cluster: take one per cluster */
      Es[nEs++] = E[i];
      used[i] = 1;
      lastkey = T.l2_key[E[i]];
    }
  }
  if (!strcasecmp(name, "P")) {
    for (int i = 0; i < nP1; i++) out[n++] = P1[i];
  } else if (!strcasecmp(name, "Psmt")) {
    for (int i = 0; i < nP1; i++) {
      out[n++] = P1[i];
      int s = T.sib[P1[i]];
      if (s >= 0 && T.online[s]) out[n++] = s;
    }
  } else if (!strcasecmp(name, "E") || !strcasecmp(name, "Epack")) {
    for (int i = 0; i < nE; i++) out[n++] = E[i];
  } else if (!strcasecmp(name, "Espread")) {
    for (int i = 0; i < nEs; i++) out[n++] = Es[i];
  } else if (!strcasecmp(name, "PE")) {
    for (int i = 0; i < nP1; i++) out[n++] = P1[i];
    for (int i = 0; i < nE; i++) out[n++] = E[i];
  } else if (!strcasecmp(name, "EP")) {
    for (int i = 0; i < nE; i++) out[n++] = E[i];
    for (int i = 0; i < nP1; i++) out[n++] = P1[i];
  } else if (!strcasecmp(name, "all")) {
    for (int i = 0; i < nP1; i++) out[n++] = P1[i];
    for (int i = 0; i < nE; i++) out[n++] = E[i];
    for (int i = 0; i < nP2; i++) out[n++] = P2[i];
  } else
    die("unknown --order '%s' (P, Psmt, E|Epack, Espread, PE, EP, all, or use --order-list)", name);
  return n;
}
static void ctx_init(ctx_t *x, int need_pmu_default) {
  memset(x, 0, sizeof *x);
  x->probe = C.probe;
  x->helper = C.helper;
  if (C.method[0]) {
    if (strstr(C.method, "pmu")) x->methods |= M_PMU;
    if (strstr(C.method, "ivt")) x->methods |= M_IVT;
    if (strstr(C.method, "xsnp")) x->methods |= M_XS;
    if (!x->methods) die("unknown --method '%s' (pmu, ivt, xsnp; comma separated)", C.method);
  } else
    x->methods = M_PMU; /* default indicator; falls back to 'ivt' below if the PMU is unavailable */
  (void)need_pmu_default;
  if (x->methods & M_PMU) {
    if (i1_open(x->probe) < 0) {
      if (T.type[x->probe] == 'E')
        warnf("indicator 'pmu' needs a P-core probe (Gracemont has no L2_LINES_OUT events)");
      else
        warnf("cannot open P-core PMU events (%s). Run as root; check perf_event_paranoid / nmi_watchdog.", strerror(errno));
      x->methods &= ~M_PMU;
      if (!C.method[0] && !x->methods) {
        warnf("falling back to the timing-only indicator 'ivt'");
        x->methods = M_IVT;
      }
    }
  }
  if (!x->methods)
    die("indicator '%s' is not available on cpu%d (needs a P-core probe and perf_event_open access: run as root,\n"
        "       check 'ini_probe info' -> PMU self-test, /proc/sys/kernel/perf_event_paranoid, nmi_watchdog)",
        C.method[0] ? C.method : "pmu", x->probe);
  if (strstr(C.workload, "l3")) x->wlmask |= 1;
  if (strstr(C.workload, "dram")) x->wlmask |= 2;
  if (!x->wlmask) x->wlmask = 1;
  if (x->methods & M_PMU) {
    for (int k = 0; k < 2; k++) {
      if (!(x->wlmask & (1 << k))) continue;
      wl_parse(k == 0 ? "l3" : "dram", &x->wl[k]);
      wl_setup(&x->wl[k], x->probe);
    }
  }
  if (x->methods & (M_IVT | M_XS)) {
    calibrate(x->probe, &x->cal, 1);
    if (!x->cal.ok) warnf("latency classes are not well separated; timing indicators may be unreliable");
  }
  if (x->methods & M_IVT) ivt_prepare(&x->ivt, x->probe);
  if (x->methods & M_XS) {
    if (x->helper < 0) die("xsnp needs a helper CPU on another core (--helper)");
    if (T.l2_key[x->helper] == T.l2_key[x->probe] || T.core_key[x->helper] == T.core_key[x->probe])
      die("--helper cpu%d shares an L2 with the probe cpu%d; pick a CPU on another core/cluster", x->helper, x->probe);
    x->xs = xs_init(x->probe, x->helper);
  }
  x->norder = build_order(C.order, x->probe, (x->methods & M_XS) ? x->helper : -1, x->order);
  memcpy(g_pool, x->order, (size_t)x->norder * sizeof(int));
  g_npool = x->norder;
}
static void busy_summary(const double *busy, int *nc, int *nP, int *nE) {
  double cb[MAXCPU];
  for (int i = 0; i < MAXCPU; i++) cb[i] = -1;
  for (int c = 0; c < T.ncpu; c++) {
    if (!T.online[c] || isnan(busy[c])) continue;
    int k = T.core_key[c];
    if (busy[c] > cb[k]) cb[k] = busy[c];
  }
  *nc = *nP = *nE = 0;
  for (int k = 0; k < T.ncpu; k++) {
    if (cb[k] <= 0.5) continue;
    (*nc)++;
    if (T.type[k] == 'E') (*nE)++;
    else (*nP)++;
  }
}
static void measure_point(ctx_t *x, point_t *p) {
  double busy[MAXCPU];
  idle_snap(g_is0);
  for (int k = 0; k < 2; k++)
    if ((x->methods & M_PMU) && (x->wlmask & (1 << k))) p->have_i1[k] = i1_measure(&x->wl[k], C.warm_ms, C.meas_ms, C.telemetry, &p->i1[k]) == 0;
  if (x->methods & M_IVT) {
    ivt_run(&x->ivt, &x->cal, &p->ivt);
    p->have_ivt = 1;
  }
  if (x->methods & M_XS) {
    xs_measure(x->xs, &p->xs);
    p->have_xs = 1;
  }
  idle_snap(g_is1);
  idle_busy(g_is0, g_is1, busy);
  busy_summary(busy, &p->busy_cores, &p->busy_P, &p->busy_E);
  const char *v = "?";
  if (p->have_i1[0]) v = verdict_sil(silfrac(p->i1[0].sil, p->i1[0].nsil));
  else if (p->have_i1[1]) v = verdict_sil(silfrac(p->i1[1].sil, p->i1[1].nsil));
  else if (p->have_ivt) v = p->ivt.dram_frac >= fmax(0.3 * p->ivt.expect, 0.005) ? "INCL(strict)" : "NONINCL/nonstrict";
  else if (p->have_xs) {
    double t = p->xs.med_ns[XS_TEST_DRAM], l = p->xs.med_ns[XS_REF_LLC], f = p->xs.med_ns[XS_REF_FWD];
    v = fabs(t - l) < fabs(t - f) ? "INCL(xsnp)" : "NONINCL(xsnp)";
  }
  snprintf(p->verdict, sizeof p->verdict, "%s", v);
}
static void print_point(const ctx_t *x, const point_t *p, int rep) {
  char act[512];
  cpus_str(p->act, p->nact, act, sizeof act);
  printf("n=%-2d rep%d act=%-24.24s busyCores(P/E)=%d(%d/%d) L2act=%.0fMB L3/L2=%.1f", p->n_req, rep, act, p->busy_cores, p->busy_P, p->busy_E,
         p->act_l2_mb, p->l3_l2_ratio);
  for (int k = 0; k < 2; k++) {
    if (!p->have_i1[k]) continue;
    const i1_t *r = &p->i1[k];
    printf(" | %s silfrac=%.3f (sil/fill=%.3f nsil/fill=%.3f) evict/us=%.1f %.2fGHz", k ? "DRAM" : "L3", silfrac(r->sil, r->nsil), sdiv(r->sil, r->fills),
           sdiv(r->nsil, r->fills), (r->sil + r->nsil) / (r->secs * 1e6), sdiv(r->cyc, r->refc) * g_tsc_ghz);
    if (r->run_frac < 0.99) printf(" (pmu-run %.0f%%)", r->run_frac * 100);
  }
  if (p->have_ivt)
    printf(" | IVT dram=%.3f%% (strict-incl ~%.2f%%) l3=%.2f%% %.1fns", p->ivt.dram_frac * 100, p->ivt.expect * 100, p->ivt.l3_frac * 100, p->ivt.mean_ns);
  if (p->have_xs)
    printf(" | XS test=%.1f llc=%.1f fwd=%.1fns", p->xs.med_ns[XS_TEST_DRAM], p->xs.med_ns[XS_REF_LLC], p->xs.med_ns[XS_REF_FWD]);
  printf(" => %s\n", p->verdict);
  if (p->have_xs && g_verbose) xs_print(&p->xs, x->helper);
  fflush(stdout);
}
static FILE *g_csv = NULL;
static int g_csv_hdr = 0;
static void csv_open(void) {
  if (!C.out[0]) return;
  g_csv = fopen(C.out, "w");
  if (!g_csv) die("cannot open %s: %s", C.out, strerror(errno));
}
static void csv_point(const char *exp, const point_t *p, int rep) {
  if (!g_csv) return;
  if (!g_csv_hdr) {
    fprintf(g_csv,
            "exp,rep,n_req,active,nP_spin,nE_spin,busy_cores,busy_P,busy_E,act_l2_mb,l3_l2_ratio,"
            "l3_fills,l3_sil_frac,l3_nsil_pf,l3_useless_pf,l3_llc_miss_ratio,l3_ipc,l3_ghz,l3_run_frac,"
            "dram_fills,dram_sil_frac,dram_nsil_pf,dram_useless_pf,dram_llc_miss_ratio,dram_ipc,dram_ghz,"
            "ivt_dram_frac,ivt_l3_frac,ivt_mean_ns,xs_refllc_ns,xs_reffwd_ns,xs_testdram_ns,xs_testl3_ns,"
            "xs_e0_testdram,xs_e1_testdram,xs_e2_testdram,xs_e3_testdram,verdict\n");
    g_csv_hdr = 1;
  }
  char act[1024];
  cpus_str(p->act, p->nact, act, sizeof act);
  fprintf(g_csv, "%s,%d,%d,%s,%d,%d,%d,%d,%d,%.1f,%.3f", exp, rep, p->n_req, act, p->nP, p->nE, p->busy_cores, p->busy_P, p->busy_E, p->act_l2_mb,
          p->l3_l2_ratio);
  for (int k = 0; k < 2; k++) {
    const i1_t *r = &p->i1[k];
    if (p->have_i1[k]) {
      fprintf(g_csv, ",%.0f,%.5f,%.5f,%.5f,%.5f,%.4f,%.4f", r->fills, silfrac(r->sil, r->nsil), sdiv(r->nsil, r->fills), sdiv(r->useless, r->fills),
              sdiv(r->llc_miss, r->llc_ref), sdiv(r->inst, r->cyc), sdiv(r->cyc, r->refc) * g_tsc_ghz);
      if (k == 0) fprintf(g_csv, ",%.4f", r->run_frac);
    } else
      fprintf(g_csv, k == 0 ? ",,,,,,,," : ",,,,,,,");
  }
  if (p->have_ivt) fprintf(g_csv, ",%.6f,%.6f,%.2f", p->ivt.dram_frac, p->ivt.l3_frac, p->ivt.mean_ns);
  else fprintf(g_csv, ",,,");
  if (p->have_xs) {
    fprintf(g_csv, ",%.2f,%.2f,%.2f,%.2f", p->xs.med_ns[XS_REF_LLC], p->xs.med_ns[XS_REF_FWD], p->xs.med_ns[XS_TEST_DRAM], p->xs.med_ns[XS_TEST_L3]);
    for (int i = 0; i < 4; i++) {
      if (i < p->xs.nev) fprintf(g_csv, ",%.4f", sdiv(p->xs.ev[XS_TEST_DRAM][i], p->xs.loads[XS_TEST_DRAM]));
      else fprintf(g_csv, ",");
    }
  } else
    fprintf(g_csv, ",,,,,,,,");
  fprintf(g_csv, ",%s\n", p->verdict);
  fflush(g_csv);
}
static void fill_point_act(ctx_t *x, point_t *p, const int *cpus, int n, int n_req) {
  char seen[MAXCPU];
  memset(seen, 0, sizeof seen);
  p->n_req = n_req;
  p->nact = n;
  p->nP = p->nE = 0;
  double l2 = 0;
  seen[T.l2_key[x->probe]] = 1;
  l2 += (double)l2_of(x->probe);
  if ((x->methods & M_XS) && x->helper >= 0 && !seen[T.l2_key[x->helper]]) {
    seen[T.l2_key[x->helper]] = 1;
    l2 += (double)l2_of(x->helper);
  }
  for (int i = 0; i < n; i++) {
    p->act[i] = cpus[i];
    if (T.type[cpus[i]] == 'E') p->nE++;
    else p->nP++;
    if (!seen[T.l2_key[cpus[i]]]) {
      seen[T.l2_key[cpus[i]]] = 1;
      l2 += (double)l2_of(cpus[i]);
    }
  }
  p->act_l2_mb = l2 / (double)MB;
  p->l3_l2_ratio = (double)l3_of() / l2;
}

/* ============================== commands ============================== */
static void print_cpuid4(int cpu) {
  if (pin_self(cpu)) return;
  printf("  CPUID.4 on cpu%d (%c-core):\n", cpu, T.type[cpu]);
  for (int i = 0; i < 8; i++) {
    unsigned a, b, c, d;
    __cpuid_count(4, i, a, b, c, d);
    int type = a & 0x1f;
    if (!type) break;
    unsigned level = (a >> 5) & 7, ways = ((b >> 22) & 0x3ff) + 1, parts = ((b >> 12) & 0x3ff) + 1, line = (b & 0xfff) + 1, sets = c + 1;
    unsigned long size = (unsigned long)ways * parts * line * sets;
    printf("    L%u %-5s %7lu KB %2u-way %6u sets  inclusive(EDX1)=%u  wbinvd(EDX0)=%u  complex_idx(EDX2)=%u  threads=%u\n", level,
           type == 1 ? "Data" : type == 2 ? "Instr" : "Unif", size / 1024, ways, sets, (d >> 1) & 1, d & 1, (d >> 2) & 1, ((a >> 14) & 0xfff) + 1);
  }
}
static void cmd_info(void) {
  char b[4096], p[256];
  FILE *f = fopen("/proc/cpuinfo", "r");
  char model[256] = "?", ucode[64] = "?";
  if (f) {
    char line[512];
    while (fgets(line, sizeof line, f)) {
      if (!strncmp(line, "model name", 10) && model[0] == '?') sscanf(strchr(line, ':') + 2, "%255[^\n]", model);
      if (!strncmp(line, "microcode", 9) && ucode[0] == '?') sscanf(strchr(line, ':') + 2, "%63s", ucode);
    }
    fclose(f);
  }
  unsigned a, bx, c, d;
  __cpuid(1, a, bx, c, d);
  unsigned fam = (a >> 8) & 0xf, mod = (a >> 4) & 0xf, step = a & 0xf;
  if (fam == 6 || fam == 15) mod += ((a >> 16) & 0xf) << 4;
  if (fam == 15) fam += (a >> 20) & 0xff;
  printf("== ini_probe %s system information\n", VERSION);
  printf("CPU      : %s  (family %u model 0x%X stepping %u)  microcode %s\n", model, fam, mod, step, ucode);
  if (!(fam == 6 && (mod == 0xB7 || mod == 0xBA || mod == 0xBF)))
    printf("           NOTE: not a Raptor Lake model (0xB7/0xBA/0xBF); event encodings/thresholds may not apply.\n");
  if (read_file("/proc/sys/kernel/osrelease", b, sizeof b) >= 0) printf("kernel   : %s\n", b);
  if (read_file("/proc/cmdline", b, sizeof b) >= 0) printf("cmdline  : %s\n", b);
  printf("TSC      : %.3f GHz   clflushopt=%d cldemote=%d hybrid=%d\n", g_tsc_ghz, g_has_clflushopt, g_has_cldemote, T.hybrid);
  printf("L3       : %ld KB, %d-way, %d sets (sysfs)\n", T.l3_size / 1024, T.l3_ways, T.l3_sets);
  printf("topology : cpu type core(L2grp) sib  L2\n");
  for (int cc = 0; cc < T.ncpu; cc++) {
    if (!T.online[cc]) continue;
    printf("           %3d  %c   %3d(%3d)  %3d  %ldK/%dw/%ds\n", cc, T.type[cc], T.core_key[cc], T.l2_key[cc], T.sib[cc], T.l2_size[cc] / 1024, T.l2_ways[cc], T.l2_sets[cc]);
  }
  cpu_set_t old;
  pthread_getaffinity_np(pthread_self(), sizeof old, &old);
  int pp = -1, ee = -1;
  for (int cc = 0; cc < T.ncpu; cc++) {
    if (!T.online[cc]) continue;
    if (T.type[cc] == 'P' && pp < 0) pp = cc;
    if (T.type[cc] == 'E' && ee < 0) ee = cc;
  }
  if (pp >= 0) print_cpuid4(pp);
  if (ee >= 0) print_cpuid4(ee);
  int pmucpu[2] = {pp, ee};
  for (int k = 0; k < 2; k++) {
    if (pmucpu[k] < 0 || pin_self(pmucpu[k])) continue;
    unsigned ea, eb, ec, ed;
    __cpuid_count(0xa, 0, ea, eb, ec, ed);
    printf("  CPUID.0AH on cpu%d (%c-core): PMU v%u, %u general-purpose counters/thread, %u fixed counters\n", pmucpu[k], T.type[pmucpu[k]], ea & 0xff,
           (ea >> 8) & 0xff, ed & 0x1f);
  }
  pthread_setaffinity_np(pthread_self(), sizeof old, &old);
  printf("perf     : cpu_core type=%d cpu_atom type=%d  perf_event_paranoid=%ld  nmi_watchdog=%ld  euid=%d\n", g_pmu_core, g_pmu_atom,
         read_long("/proc/sys/kernel/perf_event_paranoid", -99), read_long("/proc/sys/kernel/nmi_watchdog", -1), (int)geteuid());
  if (read_long("/proc/sys/kernel/nmi_watchdog", 0) == 1)
    printf("           NOTE: the NMI watchdog occupies a counter; for clean counting: echo 0 | sudo tee /proc/sys/kernel/nmi_watchdog\n");
  if (geteuid() != 0) printf("           NOTE: not root -- per-CPU counting, cpuidle control and MSR access will fail; use sudo\n");
  if (read_file("/sys/devices/system/cpu/cpuidle/current_driver", b, sizeof b) >= 0) printf("cpuidle  : driver=%s", b);
  if (read_file("/sys/devices/system/cpu/cpuidle/current_governor_ro", b, sizeof b) >= 0 ||
      read_file("/sys/devices/system/cpu/cpuidle/current_governor", b, sizeof b) >= 0)
    printf(" governor=%s", b);
  printf("\n");
  if (g_ist[C.probe].n == 0)
    printf("           NOTE: NO cpuidle driver -> idle CPUs only execute HLT (C1/C1E) and never reach C6.\n"
           "                 If the INI logic counts C1 cores as 'active', it will look non-inclusive even when idle.\n"
           "                 Check: dmesg | grep -i idle ; grep -c mwait /proc/cpuinfo ; BIOS C-state settings.\n"
           "                 Workaround for experiments: --park offline (offline CPUs enter the deepest MWAIT state).\n");
  int show[2] = {C.probe, ee};
  for (int s = 0; s < 2; s++) {
    int cc = show[s];
    if (cc < 0) continue;
    printf("           cpu%d states:", cc);
    for (int k = 0; k < g_ist[cc].n; k++) {
      snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/latency", cc, k);
      long lat = read_long(p, -1);
      snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/disable", cc, k);
      long dis = read_long(p, -1);
      printf(" %s(lat%ldus%s)", g_ist[cc].name[k], lat, dis == 1 ? ",DISABLED" : "");
    }
    printf("\n");
  }
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_driver", C.probe);
  if (read_file(p, b, sizeof b) >= 0) printf("cpufreq  : driver=%s", b);
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", C.probe);
  if (read_file(p, b, sizeof b) >= 0) printf(" governor=%s", b);
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/energy_performance_preference", C.probe);
  if (read_file(p, b, sizeof b) >= 0) printf(" epp=%s", b);
  printf(" no_turbo=%ld", read_long("/sys/devices/system/cpu/intel_pstate/no_turbo", -1));
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", C.probe);
  printf(" max=%ldMHz", read_long(p, -1000) / 1000);
  snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", C.probe);
  printf(" (hw %ldMHz)\n", read_long(p, -1000) / 1000);
  if (read_file("/sys/kernel/mm/transparent_hugepage/enabled", b, sizeof b) >= 0) printf("THP      : %s", b);
  printf("   nr_hugepages=%ld\n", read_long("/proc/sys/vm/nr_hugepages", -1));
  uint64_t v;
  if (msr_rw(C.probe, 0x1a4, &v, 0) == 0)
    printf("MSR 0x1A4: cpu%d = 0x%llx (bit0 L2 streamer, bit1 L2 adjacent, bit2 DCU next-line, bit3 DCU IP; 1 = disabled)\n", C.probe, (unsigned long long)v);
  else
    printf("MSR      : /dev/cpu/%d/msr not readable (sudo modprobe msr; run as root) -- only needed for --pf-msr\n", C.probe);
  printf("defaults : probe=cpu%d  helper=cpu%d\n", C.probe, C.helper);
  const char *ords[] = {"P", "Psmt", "Epack", "Espread", "PE", "all"};
  for (int i = 0; i < 6; i++) {
    int o[MAXCPU];
    int n = build_order(ords[i], C.probe, -1, o);
    char s[1024];
    cpus_str(o, n, s, sizeof s);
    printf("order %-8s: %s\n", ords[i], s);
  }
  /* PMU self test */
  printf("PMU self-test on probe cpu%d (each event alone, 20 ms of an L3-reuse chase):\n", C.probe);
  if (g_pmu_core < 0) {
    printf("  no core PMU exposed by the kernel (/sys/bus/event_source/devices/cpu_core missing; VM?): skipped\n");
    return;
  }
  if (T.type[C.probe] == 'E') {
    printf("  probe is an E-core: skipped\n");
    return;
  }
  wl_t w;
  wl_parse("l3", &w);
  wl_setup(&w, C.probe);
  const evdef_t *sets[] = {EV_P_L2, EV_P_AUX, EV_P_TEL1, EV_P_TEL2, EV_P_XSNP};
  int ns[] = {NEV(EV_P_L2), NEV(EV_P_AUX), NEV(EV_P_TEL1), NEV(EV_P_TEL2), NEV(EV_P_XSNP)};
  for (int s = 0; s < 5; s++)
    for (int i = 0; i < ns[s]; i++) {
      pgrp_t g;
      if (pgrp_open(&g, pmu_type_for(C.probe), &sets[s][i], 1, 0, -1) < 0) {
        printf("  %-50s open failed: %s\n", sets[s][i].name, strerror(errno));
        continue;
      }
      psnap_t s0, s1;
      pgrp_read(&g, &s0);
      wl_run_ms(&w, 20);
      pgrp_read(&g, &s1);
      double dd[MAXEV];
      pdelta(&g, &s0, &s1, dd, NULL);
      printf("  %-50s cfg=0x%-8llx %14.0f%s\n", sets[s][i].name, (unsigned long long)sets[s][i].cfg, dd[0], dd[0] == 0 ? "   <-- zero: unsupported?" : "");
      pgrp_close(&g);
    }
}
static void cmd_calib(void) {
  calib_t c;
  calibrate(C.probe, &c, 1);
}
static int resolve_active(ctx_t *x, int *cpus, int *n_req) {
  if (C.active[0]) {
    int n = parse_cpulist(C.active, cpus, MAXCPU);
    *n_req = n;
    return n;
  }
  int n = C.nactive < 0 ? 0 : C.nactive;
  if (n > x->norder) n = x->norder;
  memcpy(cpus, x->order, (size_t)n * sizeof(int));
  *n_req = n;
  return n;
}
static void cmd_probe(void) {
  ctx_t x;
  ctx_init(&x, 1);
  int cpus[MAXCPU], n_req, n = resolve_active(&x, cpus, &n_req);
  char s[1024];
  cpus_str(cpus, n, s, sizeof s);
  printf("probe cpu%d (%c), methods:%s%s%s, active set: %s\n", x.probe, T.type[x.probe], (x.methods & M_PMU) ? " pmu" : "",
         (x.methods & M_IVT) ? " ivt" : "", (x.methods & M_XS) ? " xsnp" : "", s);
  for (int k = 0; k < 2; k++)
    if ((x.methods & M_PMU) && (x.wlmask & (1 << k))) printf("workload %s  (2MB-page backing %.0f%%)\n", x.wl[k].label, x.wl[k].b->huge_frac * 100);
  activate_set(cpus, n);
  sleep_ms(C.settle_ms);
  csv_open();
  for (int r = 0; r < C.reps && !g_stop; r++) {
    point_t p;
    memset(&p, 0, sizeof p);
    fill_point_act(&x, &p, cpus, n, n_req);
    measure_point(&x, &p);
    print_point(&x, &p, r);
    if (p.have_xs && !g_verbose && r == C.reps - 1) xs_print(&p.xs, x.helper);
    csv_point("probe", &p, r);
  }
  int none[1];
  activate_set(none, 0);
  xs_stop(x.xs);
}
static int parse_nlist(const char *s, int maxn, int *out) {
  int n = 0;
  char tmp[512];
  snprintf(tmp, sizeof tmp, "%s", s);
  char *save = NULL;
  for (char *t = strtok_r(tmp, ",", &save); t && n < 256; t = strtok_r(NULL, ",", &save)) {
    if (!strcasecmp(t, "all") || !strcasecmp(t, "max")) out[n++] = maxn;
    else if (strchr(t, '-')) {
      int a = atoi(t), b = atoi(strchr(t, '-') + 1);
      for (int i = a; i <= b && n < 256; i++) out[n++] = i;
    } else
      out[n++] = atoi(t);
    if (out[n - 1] > maxn) out[n - 1] = maxn;
  }
  return n;
}
static void cmd_sweep(void) {
  ctx_t x;
  ctx_init(&x, 1);
  int ns[512], nn = 0;
  if (C.nlist[0]) nn = parse_nlist(C.nlist, x.norder, ns);
  else
    for (int i = 0; i <= x.norder; i++) ns[nn++] = i;
  if (C.updown)
    for (int i = nn - 2; i >= 0; i--) ns[nn++] = ns[i];
  char s[1024];
  cpus_str(x.order, x.norder, s, sizeof s);
  printf("sweep: probe cpu%d (%c), order %s = [%s], activate-by %s, spinner %s, settle %.0f ms, %d reps\n", x.probe, T.type[x.probe],
         C.order_list[0] ? "custom" : C.order, s, C.activate_by, C.spin, C.settle_ms, C.reps);
  csv_open();
  double med[512];
  for (int i = 0; i < nn && !g_stop; i++) {
    int n = ns[i];
    activate_set(x.order, n);
    sleep_ms(C.settle_ms);
    double v[64];
    int nv = 0;
    for (int r = 0; r < C.reps && !g_stop; r++) {
      point_t p;
      memset(&p, 0, sizeof p);
      fill_point_act(&x, &p, x.order, n, n);
      measure_point(&x, &p);
      print_point(&x, &p, r);
      csv_point("sweep", &p, r);
      double m = NAN;
      if (p.have_i1[0]) m = silfrac(p.i1[0].sil, p.i1[0].nsil);
      else if (p.have_i1[1]) m = silfrac(p.i1[1].sil, p.i1[1].nsil);
      else if (p.have_ivt) m = p.ivt.dram_frac;
      else if (p.have_xs) m = p.xs.med_ns[XS_TEST_DRAM];
      if (nv < 64) v[nv++] = m;
    }
    for (int a = 1; a < nv; a++) {
      double t = v[a];
      int b = a - 1;
      while (b >= 0 && v[b] > t) {
        v[b + 1] = v[b];
        b--;
      }
      v[b + 1] = t;
    }
    med[i] = nv ? v[nv / 2] : NAN;
  }
  int none[1];
  activate_set(none, 0);
  const char *what = (x.methods & M_PMU) ? "silent share of L2 evictions (1=inclusive, 0=non-inclusive)"
                     : (x.methods & M_IVT) ? "IVT DRAM-class fraction (>0 = strict inclusion)"
                                           : "xsnp TEST_DRAM latency (ns)";
  printf("\nsummary: median %s per step\n", what);
  for (int i = 0; i < nn; i++) {
    printf("  n=%-3d %8.4f  %s", ns[i], med[i], (x.methods & M_PMU) ? verdict_sil(med[i]) : "");
    if (i > 0 && (x.methods & M_PMU) && !isnan(med[i]) && !isnan(med[i - 1]) && strcmp(verdict_sil(med[i]), verdict_sil(med[i - 1])))
      printf("   <== transition between n=%d and n=%d", ns[i - 1], ns[i]);
    printf("\n");
  }
  xs_stop(x.xs);
}
typedef struct {
  double t_ms;
  int n;
  double fills, sil, nsil, useless, cyc, refc, inst;
} trec_t;
static void cmd_timeline(void) {
  ctx_t x;
  snprintf(C.method, sizeof C.method, "pmu");
  ctx_init(&x, 1);
  if (!(x.methods & M_PMU)) die("timeline needs indicator 'pmu' (P-core probe + PMU access)");
  wl_t *w = (x.wlmask & 1) ? &x.wl[0] : &x.wl[1];
  double ev_t[128];
  int ev_n[128], nev = 0;
  char sched[1024];
  if (C.schedule[0]) snprintf(sched, sizeof sched, "%s", C.schedule);
  else snprintf(sched, sizeof sched, "0:0,1000:all,2000:0,3000:%d,4000:0", x.norder / 2 > 0 ? x.norder / 2 : 1);
  char *save = NULL;
  for (char *t = strtok_r(sched, ",", &save); t && nev < 128; t = strtok_r(NULL, ",", &save)) {
    char *c = strchr(t, ':');
    if (!c) die("bad --schedule token '%s' (expected t_ms:n)", t);
    ev_t[nev] = atof(t);
    ev_n[nev] = (!strcasecmp(c + 1, "all") || !strcasecmp(c + 1, "max")) ? x.norder : atoi(c + 1);
    if (ev_n[nev] > x.norder) ev_n[nev] = x.norder;
    nev++;
  }
  double dur = C.duration_ms > 0 ? C.duration_ms : ev_t[nev - 1] + 1000;
  activate_set(x.order, x.norder); /* create all spinner threads up front, then park them */
  sleep_ms(50);
  activate_set(x.order, 0);
  sleep_ms(C.settle_ms);
  wl_run_ms(w, 50);
  double t0 = now_s();
  uint64_t steps = wl_run_ms(w, 20);
  double sps = (double)steps / (now_s() - t0);
  uint64_t chunk = (uint64_t)(sps * C.window_us * 1e-6);
  if (chunk < 32) chunk = 32;
  size_t maxw = (size_t)(dur * 1000.0 / C.window_us * 2 + 1000);
  trec_t *rec = calloc(maxw, sizeof(trec_t));
  printf("timeline: probe cpu%d, workload %s, window %.0f us (%llu steps), duration %.0f ms, schedule %s\n", x.probe, w->label, C.window_us,
         (unsigned long long)chunk, dur, C.schedule[0] ? C.schedule : "(default)");
  psnap_t a, b, a0, b0;
  pgrp_read(&g_g1, &a);
  if (g_g0_open) pgrp_read(&g_g0, &a0);
  double start = now_s();
  int ei = 0, cur = 0;
  size_t nw = 0;
  while (!g_stop && nw < maxw) {
    double tms = (now_s() - start) * 1e3;
    if (tms >= dur) break;
    while (ei < nev && ev_t[ei] <= tms) {
      activate_set(x.order, ev_n[ei]);
      cur = ev_n[ei];
      ei++;
    }
    g_sink += wl_run(w, chunk);
    pgrp_read(&g_g1, &b);
    if (g_g0_open) pgrp_read(&g_g0, &b0);
    double d[MAXEV];
    trec_t *r = &rec[nw++];
    pdelta(&g_g1, &a, &b, d, NULL);
    a = b;
    r->t_ms = (now_s() - start) * 1e3;
    r->n = cur;
    r->fills = d[E_IN];
    r->sil = d[E_SIL];
    r->nsil = d[E_NSIL];
    r->useless = d[E_USELESS];
    if (g_g0_open) {
      pdelta(&g_g0, &a0, &b0, d, NULL);
      a0 = b0;
      r->cyc = d[A_CYC];
      r->refc = d[A_REFC];
      r->inst = d[A_INST];
    } else
      r->cyc = r->refc = r->inst = NAN;
  }
  activate_set(x.order, 0);
  csv_open();
  if (g_csv) {
    fprintf(g_csv, "t_ms,n_active,fills,sil_frac,nsil_pf,useless_pf,ghz,ipc\n");
    for (size_t i = 0; i < nw; i++)
      fprintf(g_csv, "%.3f,%d,%.0f,%.5f,%.5f,%.5f,%.3f,%.4f\n", rec[i].t_ms, rec[i].n, rec[i].fills, silfrac(rec[i].sil, rec[i].nsil),
              sdiv(rec[i].nsil, rec[i].fills), sdiv(rec[i].useless, rec[i].fills), sdiv(rec[i].cyc, rec[i].refc) * g_tsc_ghz,
              sdiv(rec[i].inst, rec[i].cyc));
    fflush(g_csv);
  }
  printf("windows recorded: %zu\n", nw);
  double segmed[128];
  for (int e = 0; e < nev; e++) {
    double ts = ev_t[e], te = e + 1 < nev ? ev_t[e + 1] : dur, tl = ts + 0.3 * (te - ts);
    double *v = malloc(nw * sizeof(double));
    size_t m = 0;
    for (size_t i = 0; i < nw; i++)
      if (rec[i].t_ms >= tl && rec[i].t_ms < te && rec[i].sil + rec[i].nsil > 0) v[m++] = silfrac(rec[i].sil, rec[i].nsil);
    for (size_t i = 1; i < m; i++) {
      double t = v[i];
      size_t j = i;
      while (j > 0 && v[j - 1] > t) {
        v[j] = v[j - 1];
        j--;
      }
      v[j] = t;
    }
    segmed[e] = m ? v[m / 2] : NAN;
    free(v);
    printf("  segment %7.0f..%7.0f ms  n_active=%-3d  median silent-drop fraction %.3f  (%s)\n", ts, te, ev_n[e], segmed[e], verdict_sil(segmed[e]));
    if (e > 0 && !isnan(segmed[e]) && !isnan(segmed[e - 1]) && fabs(segmed[e] - segmed[e - 1]) >= 0.3) {
      double mid = (segmed[e] + segmed[e - 1]) / 2;
      int up = segmed[e] > mid;
      double lat = NAN;
      for (size_t i = 0; i + 3 < nw; i++) {
        if (rec[i].t_ms < ts) continue;
        int ok = 1;
        for (int k = 0; k < 3; k++) {
          double s = silfrac(rec[i + k].sil, rec[i + k].nsil);
          if (isnan(s) || (up ? s <= mid : s >= mid)) ok = 0;
        }
        if (ok) {
          lat = rec[i].t_ms - ts;
          break;
        }
      }
      printf("      -> switch detected; latency after the change: %.3f ms (window %.0f us)\n", lat, C.window_us);
    }
  }
  free(rec);
}
static void cmd_grid(void) {
  ctx_t x;
  snprintf(C.method, sizeof C.method, "pmu");
  C.telemetry = 1;
  ctx_init(&x, 1);
  if (!(x.methods & M_PMU)) die("grid needs indicator 'pmu' (P-core probe + PMU access)");
  int ns[512], nn = 0;
  if (C.nlist[0]) nn = parse_nlist(C.nlist, x.norder, ns);
  else
    for (int i = 0; i <= x.norder; i++) ns[nn++] = i;
  char wls[2048];
  snprintf(wls, sizeof wls, "%s", C.wlist[0] ? C.wlist : "l3:mlp=1,l3:mlp=4,l3:mlp=16,l3:mlp=8:alu=64,dram:mlp=1,dram:mlp=4,dram:mlp=16,dram:mlp=8:seq");
  wl_t W[32];
  int nw = 0;
  char *save = NULL;
  for (char *t = strtok_r(wls, ",", &save); t && nw < 32; t = strtok_r(NULL, ",", &save)) {
    if (wl_parse(t, &W[nw]) < 0) die("bad workload spec '%s'", t);
    wl_setup(&W[nw], x.probe);
    nw++;
  }
  printf("grid: probe cpu%d, %d active-core steps x %d workloads x %d reps (telemetry on)\n", x.probe, nn, nw, C.reps);
  csv_open();
  if (g_csv)
    fprintf(g_csv, "n_req,rep,wl,kind,ws_kb,mlp,alu,seq,busy_cores,busy_P,busy_E,fills,sil_frac,nsil_pf,useless_pf,fills_pki,llc_miss_ratio,ipc,ghz,"
                   "stall_frac,l3stall_frac,occ,occ_busy,offreq_pki,l3hit_pki,l3miss_pki,l2miss_pki,run_frac,verdict,label\n");
  for (int i = 0; i < nn && !g_stop; i++) {
    activate_set(x.order, ns[i]);
    sleep_ms(C.settle_ms);
    for (int k = 0; k < nw && !g_stop; k++)
      for (int r = 0; r < C.reps && !g_stop; r++) {
        i1_t q;
        double busy[MAXCPU];
        int bc, bp, be;
        idle_snap(g_is0);
        i1_measure(&W[k], C.warm_ms > 50 ? C.warm_ms : 50, C.meas_ms, 1, &q);
        idle_snap(g_is1);
        idle_busy(g_is0, g_is1, busy);
        busy_summary(busy, &bc, &bp, &be);
        double sil = silfrac(q.sil, q.nsil);
        printf("n=%-2d %-40s sil=%.3f nsil=%.3f ipc=%.2f stall=%.2f occ=%.1f l3miss/ki=%.1f => %s\n", ns[i], W[k].label, sil, sdiv(q.nsil, q.fills),
               sdiv(q.inst, q.cyc), sdiv(q.st_tot, q.cyc_t), sdiv(q.occ, q.cyc_t), sdiv(q.l3miss, q.inst_t) * 1000, verdict_sil(sil));
        fflush(stdout);
        if (g_csv)
          fprintf(g_csv, "%d,%d,%s,%d,%zu,%d,%d,%d,%d,%d,%d,%.0f,%.5f,%.5f,%.5f,%.4f,%.5f,%.4f,%.4f,%.5f,%.5f,%.4f,%.5f,%.4f,%.4f,%.4f,%.4f,%.3f,%s,%d\n",
                  ns[i], r, W[k].label, W[k].kind, W[k].ws / KB, W[k].mlp, W[k].alu, W[k].seq, bc, bp, be, q.fills, sil, sdiv(q.nsil, q.fills),
                  sdiv(q.useless, q.fills), sdiv(q.fills, q.inst) * 1000, sdiv(q.llc_miss, q.llc_ref), sdiv(q.inst, q.cyc),
                  sdiv(q.cyc, q.refc) * g_tsc_ghz, sdiv(q.st_tot, q.cyc_t), sdiv(q.st_l3, q.cyc_t), sdiv(q.occ, q.cyc_t), sdiv(q.occ_cyc, q.cyc_t),
                  sdiv(q.offreq, q.inst_t) * 1000, sdiv(q.l3hit, q.inst_t) * 1000, sdiv(q.l3miss, q.inst_t) * 1000, sdiv(q.l2miss, q.inst_t) * 1000,
                  q.run_frac, verdict_sil(sil), isnan(sil) ? -1 : sil >= C.thr);
      }
    if (g_csv) fflush(g_csv);
  }
  int none[1];
  activate_set(none, 0);
}

/* ---------- fit: logistic regression (US 12,693,977 B2 FIG. 3: z = theta0 + sum theta_i x_i, predict 1 iff z >= 0) ---------- */
typedef struct {
  int ncol, nrow;
  char *names[256];
  double *v;
} csv_t;
static int csv_load(const char *path, csv_t *t) {
  memset(t, 0, sizeof *t);
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  char *line = NULL;
  size_t cap = 0;
  ssize_t len = getline(&line, &cap, f);
  if (len <= 0) {
    fclose(f);
    return -1;
  }
  line[strcspn(line, "\r\n")] = 0;
  char *save = NULL;
  for (char *tok = strtok_r(line, ",", &save); tok && t->ncol < 256; tok = strtok_r(NULL, ",", &save)) t->names[t->ncol++] = strdup(tok);
  size_t capr = 1024;
  t->v = malloc(capr * (size_t)t->ncol * sizeof(double));
  while ((len = getline(&line, &cap, f)) > 0) {
    line[strcspn(line, "\r\n")] = 0;
    if (!line[0]) continue;
    if ((size_t)t->nrow == capr) {
      capr *= 2;
      t->v = realloc(t->v, capr * (size_t)t->ncol * sizeof(double));
    }
    double *row = t->v + (size_t)t->nrow * (size_t)t->ncol;
    char *p = line;
    for (int j = 0; j < t->ncol; j++) {
      char *e = strchr(p, ',');
      if (e) *e = 0;
      char *end;
      double val = strtod(p, &end);
      row[j] = (end != p && *end == 0) ? val : NAN;
      p = e ? e + 1 : p + strlen(p);
    }
    t->nrow++;
  }
  free(line);
  fclose(f);
  return 0;
}
static int csv_col(const csv_t *t, const char *name) {
  for (int j = 0; j < t->ncol; j++)
    if (!strcmp(t->names[j], name)) return j;
  return -1;
}
static int solve_lin(double *A, double *b, int n) {
  for (int i = 0; i < n; i++) {
    int pv = i;
    for (int r = i + 1; r < n; r++)
      if (fabs(A[r * n + i]) > fabs(A[pv * n + i])) pv = r;
    if (fabs(A[pv * n + i]) < 1e-14) return -1;
    if (pv != i) {
      for (int c = 0; c < n; c++) {
        double t = A[i * n + c];
        A[i * n + c] = A[pv * n + c];
        A[pv * n + c] = t;
      }
      double t = b[i];
      b[i] = b[pv];
      b[pv] = t;
    }
    for (int r = i + 1; r < n; r++) {
      double f = A[r * n + i] / A[i * n + i];
      for (int c = i; c < n; c++) A[r * n + c] -= f * A[i * n + c];
      b[r] -= f * b[i];
    }
  }
  for (int i = n - 1; i >= 0; i--) {
    double s = b[i];
    for (int c = i + 1; c < n; c++) s -= A[i * n + c] * b[c];
    b[i] = s / A[i * n + i];
  }
  return 0;
}
static void logreg(const double *X, const int *y, int n, int d, double lambda, double *w) {
  int D = d + 1;
  memset(w, 0, (size_t)D * sizeof(double));
  double *H = malloc((size_t)D * D * sizeof(double)), *g = malloc((size_t)D * sizeof(double)), xi[64];
  for (int it = 0; it < 200; it++) {
    memset(H, 0, (size_t)D * D * sizeof(double));
    memset(g, 0, (size_t)D * sizeof(double));
    for (int i = 0; i < n; i++) {
      xi[0] = 1;
      for (int j = 0; j < d; j++) xi[j + 1] = X[i * d + j];
      double z = 0;
      for (int j = 0; j < D; j++) z += w[j] * xi[j];
      double p = 1.0 / (1.0 + exp(-z)), s = p * (1 - p), r = p - y[i];
      for (int a = 0; a < D; a++) {
        g[a] += r * xi[a];
        for (int b = 0; b < D; b++) H[a * D + b] += s * xi[a] * xi[b];
      }
    }
    for (int a = 1; a < D; a++) {
      g[a] += lambda * w[a];
      H[a * D + a] += lambda;
    }
    H[0] += 1e-9;
    if (solve_lin(H, g, D)) break;
    double mx = 0;
    for (int a = 0; a < D; a++) {
      w[a] -= g[a];
      if (fabs(g[a]) > mx) mx = fabs(g[a]);
    }
    if (mx < 1e-10) break;
  }
  free(H);
  free(g);
}
static void cmd_fit(const char *path) {
  csv_t t;
  if (csv_load(path, &t) < 0) die("cannot read %s", path);
  char feats[512];
  snprintf(feats, sizeof feats, "%s", C.features[0] ? C.features : (csv_col(&t, "n_req") >= 0 ? "n_req" : "busy_cores"));
  int fc[32], d = 0;
  const char *fn[32];
  char *save = NULL;
  for (char *tok = strtok_r(feats, ",", &save); tok && d < 32; tok = strtok_r(NULL, ",", &save)) {
    int c = csv_col(&t, tok);
    if (c < 0) die("feature column '%s' not found in %s", tok, path);
    fc[d] = c;
    fn[d] = t.names[c];
    d++;
  }
  int lc = csv_col(&t, C.label);
  if (lc < 0) die("label column '%s' not found (use --label, e.g. sil_frac or l3_sil_frac)", C.label);
  double *X = malloc((size_t)t.nrow * (size_t)d * sizeof(double));
  int *y = malloc((size_t)t.nrow * sizeof(int)), n = 0, npos = 0;
  for (int i = 0; i < t.nrow; i++) {
    const double *row = t.v + (size_t)i * (size_t)t.ncol;
    if (isnan(row[lc])) continue;
    int bad = 0;
    for (int j = 0; j < d; j++)
      if (isnan(row[fc[j]])) bad = 1;
    if (bad) continue;
    for (int j = 0; j < d; j++) X[n * d + j] = row[fc[j]];
    y[n] = row[lc] >= C.thr;
    npos += y[n];
    n++;
  }
  printf("fit: %d usable rows, label = (%s >= %.3f): %d inclusive / %d non-inclusive\n", n, C.label, C.thr, npos, n - npos);
  if (n < 4 || npos == 0 || npos == n) {
    printf("  need both classes to fit a boundary.\n");
    return;
  }
  printf("single-feature threshold rules (decision stumps):\n");
  double *xs = malloc((size_t)n * sizeof(double));
  for (int j = 0; j < d; j++) {
    for (int i = 0; i < n; i++) xs[i] = X[i * d + j];
    double best = -1, bthr = NAN;
    int bdir = 0;
    for (int i = 0; i < n; i++) {
      double thr = xs[i];
      for (int dir = 0; dir < 2; dir++) {
        int ok = 0;
        for (int k = 0; k < n; k++) {
          int pred = dir == 0 ? (X[k * d + j] <= thr) : (X[k * d + j] > thr);
          ok += pred == y[k];
        }
        if (ok > best) {
          best = ok;
          bthr = thr;
          bdir = dir;
        }
      }
    }
    double next = INFINITY;
    for (int i = 0; i < n; i++)
      if (X[i * d + j] > bthr && X[i * d + j] < next) next = X[i * d + j];
    double mid = isinf(next) ? bthr : (bthr + next) / 2;
    printf("  %-20s : INCLUSIVE iff %s %s %.4g   accuracy %.1f%%\n", fn[j], fn[j], bdir == 0 ? "<=" : ">", mid, 100.0 * best / n);
  }
  free(xs);
  double mu[32], sd[32];
  for (int j = 0; j < d; j++) {
    double s = 0, s2 = 0;
    for (int i = 0; i < n; i++) {
      s += X[i * d + j];
      s2 += X[i * d + j] * X[i * d + j];
    }
    mu[j] = s / n;
    sd[j] = sqrt(fmax(s2 / n - mu[j] * mu[j], 0));
    if (sd[j] < 1e-12) sd[j] = 1;
    for (int i = 0; i < n; i++) X[i * d + j] = (X[i * d + j] - mu[j]) / sd[j];
  }
  double w[33];
  logreg(X, y, n, d, C.lambda, w);
  int tp = 0, tn = 0, fp = 0, fnn = 0;
  for (int i = 0; i < n; i++) {
    double z = w[0];
    for (int j = 0; j < d; j++) z += w[j + 1] * X[i * d + j];
    int pr = z >= 0;
    if (pr && y[i]) tp++;
    else if (!pr && !y[i]) tn++;
    else if (pr) fp++;
    else fnn++;
  }
  double b0 = w[0];
  for (int j = 0; j < d; j++) b0 -= w[j + 1] * mu[j] / sd[j];
  printf("logistic regression (L2 lambda=%.3g on standardized features):\n  z = %+.5g", C.lambda, b0);
  for (int j = 0; j < d; j++) printf(" %+.5g*%s", w[j + 1] / sd[j], fn[j]);
  printf("\n  predict INCLUSIVE iff z >= 0     (standardized weights:");
  for (int j = 0; j < d; j++) printf(" %s=%+.3f", fn[j], w[j + 1]);
  printf(")\n  training accuracy %.1f%%  [TP %d TN %d FP %d FN %d]\n", 100.0 * (tp + tn) / n, tp, tn, fp, fnn);
  if (d == 1 && fabs(w[1]) > 1e-12) printf("  1-D boundary: %s = %.4g\n", fn[0], mu[0] - w[0] * sd[0] / w[1]);
}
static void cmd_monitor(void) {
  int cpus[MAXCPU], n = 0;
  if (C.cpus[0]) n = parse_cpulist(C.cpus, cpus, MAXCPU);
  else
    for (int c = 0; c < T.ncpu; c++)
      if (T.online[c] && T.type[c] == 'P' && T.core_key[c] == c) cpus[n++] = c;
  pgrp_t g[MAXCPU];
  int ok[MAXCPU], nok = 0;
  psnap_t a[MAXCPU], b[MAXCPU];
  for (int i = 0; i < n; i++) {
    ok[i] = 0;
    if (T.type[cpus[i]] == 'E') {
      warnf("cpu%d is an E-core: no L2_LINES_OUT events, skipped", cpus[i]);
      continue;
    }
    ok[i] = pgrp_open(&g[i], pmu_type_for(cpus[i]), EV_P_L2, NEV(EV_P_L2), -1, cpus[i]) == 0;
    if (!ok[i]) warnf("cannot open per-CPU events on cpu%d: %s (needs root or perf_event_paranoid<=0)", cpus[i], strerror(errno));
    else {
      pgrp_read(&g[i], &a[i]);
      nok++;
    }
  }
  if (!nok) die("no CPU could be monitored");
  csv_open();
  if (g_csv) fprintf(g_csv, "t_s,cpu,fills,sil_frac,nsil_pf,useless_pf\n");
  printf("monitor: per-core L2 silent-drop fraction (1 = clean victims dropped = inclusive-like; 0 = written back = non-inclusive-like)\n");
  printf("         only meaningful while the core has L2 misses; [fills per ms] shown in brackets. Ctrl-C to stop.\n");
  double t0 = now_s();
  while (!g_stop) {
    sleep_ms(C.interval_ms);
    double t = now_s() - t0;
    printf("%7.2fs", t);
    for (int i = 0; i < n; i++) {
      if (!ok[i]) continue;
      pgrp_read(&g[i], &b[i]);
      double d[MAXEV];
      pdelta(&g[i], &a[i], &b[i], d, NULL);
      a[i] = b[i];
      double s = silfrac(d[1], d[2]);
      if (d[1] + d[2] < 1000) printf("  c%-2d   -  [%5.0f]", cpus[i], d[0] / C.interval_ms);
      else printf("  c%-2d %.2f [%5.0f]", cpus[i], s, d[0] / C.interval_ms);
      if (g_csv) fprintf(g_csv, "%.3f,%d,%.0f,%.5f,%.5f,%.5f\n", t, cpus[i], d[0], s, sdiv(d[2], d[0]), sdiv(d[3], d[0]));
    }
    printf("\n");
    fflush(stdout);
    if (g_csv) fflush(g_csv);
    if (C.dur_s > 0 && t >= C.dur_s) break;
  }
  for (int i = 0; i < n; i++)
    if (ok[i]) pgrp_close(&g[i]);
}
static void cmd_setscan(void) {
  ctx_t x;
  snprintf(C.method, sizeof C.method, "pmu");
  snprintf(C.workload, sizeof C.workload, "l3");
  ctx_init(&x, 1);
  if (!(x.methods & M_PMU)) die("setscan needs indicator 'pmu' (P-core probe + PMU access)");
  int ways = T.l3_ways > 0 ? T.l3_ways : 12;
  long S = (long)C.slice_kb * 1024 / 64 / ways;
  long S2 = 1;
  while (S2 * 2 <= S) S2 *= 2;
  if (S2 != S) warnf("sets per slice %ld is not a power of two; using %ld", S, S2);
  S = S2;
  int G = C.set_group;
  if (G < 1 || S % G) die("--set-group must divide the number of sets per slice (%ld)", S);
  long ngroups = S / G, lines_pp = (long)(HUGE2M / 64);
  if (S > lines_pp) die("sets per slice (%ld) exceed one 2MB page", S);
  size_t bytes = (size_t)C.pages * HUGE2M;
  double hf;
  char *buf = alloc_mem(bytes, 2, &hf);
  printf("setscan: probe cpu%d, %d x 2MB pages (2MB backing %.0f%%), LLC %d-way, %ld sets/slice (index = PA bits 6..%d), group = %d set(s)\n", x.probe,
         C.pages, hf * 100, ways, S, 5 + (int)log2((double)S), G);
  if (hf < 0.99)
    warnf("buffer is not fully backed by 2MB pages -> set indices above bit 11 are unknown. Reserve pages: echo 64 | sudo tee /proc/sys/vm/nr_hugepages");
  long per = (long)C.pages * (lines_pp / S) * G;
  printf("         %ld lines per group (%ld per L2 set if the L2 has %d sets)\n", per, per / G, l2_sets_of(x.probe));
  uint32_t *off = malloc((size_t)ngroups * (size_t)per * sizeof(uint32_t));
  long *cnt = calloc((size_t)ngroups, sizeof(long));
  for (long pg = 0; pg < C.pages; pg++)
    for (long li = 0; li < lines_pp; li++) {
      long grp = (li & (S - 1)) / G;
      off[grp * per + cnt[grp]++] = (uint32_t)(pg * lines_pp + li);
    }
  char **heads = malloc((size_t)ngroups * sizeof(char *));
  for (long gi = 0; gi < ngroups; gi++) {
    uint32_t *o = off + gi * per;
    shuffle_u32(o, (size_t)per);
    for (long k = 0; k < per; k++) *(char **)(buf + (size_t)o[k] * 64) = buf + (size_t)o[(k + 1) % per] * 64;
    heads[gi] = buf + (size_t)o[0] * 64;
  }
  flush_range(buf, bytes);
  int cpus[MAXCPU], n_req, n = resolve_active(&x, cpus, &n_req);
  activate_set(cpus, n);
  sleep_ms(C.settle_ms);
  double *fill = calloc((size_t)ngroups, sizeof(double)), *sil = calloc((size_t)ngroups, sizeof(double)), *nsil = calloc((size_t)ngroups, sizeof(double));
  for (int r = 0; r < C.reps && !g_stop; r++)
    for (long gi = 0; gi < ngroups && !g_stop; gi++) {
      psnap_t a, b;
      g_sink += chase(&heads[gi], 1, 200, 0);
      pgrp_read(&g_g1, &a);
      g_sink += chase(&heads[gi], 1, (uint64_t)C.ss_steps, 0);
      pgrp_read(&g_g1, &b);
      double d[MAXEV];
      pdelta(&g_g1, &a, &b, d, NULL);
      fill[gi] += d[E_IN];
      sil[gi] += d[E_SIL];
      nsil[gi] += d[E_NSIL];
    }
  int none[1];
  activate_set(none, 0);
  double *v = malloc((size_t)ngroups * sizeof(double));
  long m = 0;
  for (long gi = 0; gi < ngroups; gi++)
    if (sil[gi] + nsil[gi] > 0) v[m++] = silfrac(sil[gi], nsil[gi]);
  for (long i = 1; i < m; i++) {
    double t = v[i];
    long j = i;
    while (j > 0 && v[j - 1] > t) {
      v[j] = v[j - 1];
      j--;
    }
    v[j] = t;
  }
  double med = m ? v[m / 2] : NAN;
  for (long i = 0; i < m; i++) v[i] = fabs(v[i] - med);
  for (long i = 1; i < m; i++) {
    double t = v[i];
    long j = i;
    while (j > 0 && v[j - 1] > t) {
      v[j] = v[j - 1];
      j--;
    }
    v[j] = t;
  }
  double mad = m ? v[m / 2] : NAN, lim = fmax(0.2, 6 * mad);
  printf("result: median silent-drop fraction %.3f (%s), MAD %.4f; groups deviating by more than %.3f:\n", med, verdict_sil(med), mad, lim);
  long nout = 0;
  for (long gi = 0; gi < ngroups; gi++) {
    double s = silfrac(sil[gi], nsil[gi]);
    if (!isnan(s) && fabs(s - med) > lim) {
      if (nout < 64) printf("  sets %5ld..%5ld : %.3f  (fills %.0f)\n", gi * G, gi * G + G - 1, s, fill[gi]);
      nout++;
    }
  }
  printf("  %ld outlier group(s) of %ld%s\n", nout, ngroups, nout > 64 ? " (first 64 shown)" : "");
  csv_open();
  if (g_csv) {
    fprintf(g_csv, "group,set_lo,set_hi,fills,sil_frac,nsil_pf\n");
    for (long gi = 0; gi < ngroups; gi++)
      fprintf(g_csv, "%ld,%ld,%ld,%.0f,%.5f,%.5f\n", gi, gi * G, gi * G + G - 1, fill[gi], silfrac(sil[gi], nsil[gi]), sdiv(nsil[gi], fill[gi]));
    fflush(g_csv);
  }
}

/* ============================== CLI ============================== */
static void usage(void) {
  printf(
      "ini_probe %s -- Raptor Lake dynamic inclusive/non-inclusive (INI) L3 policy explorer\n"
      "usage: sudo ./ini_probe <command> [options]\n\n"
      "commands\n"
      "  info       system, topology, CPUID.4, cpuidle, PMU self-test (start here)\n"
      "  calib      L1/L2/L3/DRAM latency calibration on the probe CPU\n"
      "  probe      measure the indicators once (with an optional set of active cores)\n"
      "  sweep      vary the number of active cores (main test of US12693977 / US9378148)\n"
      "  timeline   time series of the indicator while active cores are switched (switch latency)\n"
      "  grid       (active cores) x (probe workload) with telemetry features -> CSV for 'fit'\n"
      "  fit FILE   decision stumps + logistic regression of the inclusive/non-inclusive boundary\n"
      "  monitor    passive per-core silent-drop fraction while YOUR workload runs\n"
      "  setscan    indicator per LLC set index (set-dueling / leader-set test, FLEXclusion)\n\n"
      "common options\n"
      "  -p, --probe CPU         probe CPU (default: first thread of the 2nd P-core)\n"
      "      --helper CPU        helper CPU for xsnp (default: next P-core)\n"
      "  -m, --method LIST       pmu,ivt,xsnp (default pmu; falls back to ivt without PMU)\n"
      "  -w, --workload LIST     l3,dram : read-only probe workload for 'pmu' (default l3)\n"
      "      --ws SIZE --dram-ws SIZE --mlp N --alu N --seq --stride BYTES   workload shape\n"
      "  -a, --active LIST       explicit active CPUs, e.g. 4,6,16-19\n"
      "  -n, --nactive N         first N CPUs of --order are active\n"
      "      --order NAME        P | Psmt | Epack(E) | Espread | PE (default) | EP | all\n"
      "      --order-list LIST   custom activation order\n"
      "      --nlist LIST        n values for sweep/grid, e.g. 0-8,12,16,all\n"
      "      --updown            sweep up and back down (hysteresis)\n"
      "      --spin KIND         alu (default) | pause | l2 | llc | mem   (what active cores run)\n"
      "      --activate-by MODE  spin (default) | c1 (cores idle but limited to C1, no spinner)\n"
      "      --idle-max NAME --idle-cpus LIST   limit cpuidle on CPUs (e.g. C1, C1E, C6); restored at exit\n"
      "      --park MODE         idle (default) | offline : inactive CPUs of the order are taken offline\n"
      "                          (they then sit in the deepest MWAIT C-state); restored at exit\n"
      "      --settle MS         wait after changing the active set (default 300)\n"
      "      --warm MS --meas MS warm-up / measurement time per point (default 20 / 30)\n"
      "  -r, --reps N            repetitions per point (default 3)\n"
      "  -o, --out FILE          CSV output\n"
      "      --pf-msr VALUE      write MSR 0x1A4 (prefetchers) on the probe core; restored at exit\n"
      "      --telemetry         also collect stall/queue-occupancy events (probe/sweep)\n"
      "  timeline: --window US (200) --schedule \"0:0,1000:all,2000:0\" --duration MS\n"
      "  grid    : --wlist \"l3:mlp=1,l3:mlp=16,dram:mlp=4:alu=32,dram:seq\"\n"
      "  fit     : --features n_req,occ,stall_frac --label sil_frac --thr 0.5 --lambda 0.01\n"
      "  monitor : --cpus LIST -i MS -d SEC\n"
      "  setscan : --pages N (8) --set-group N (2) --slice-kb KB (3072) --ss-steps N (2000)\n"
      "  xsnp/ivt: --xs-lines N (2048) --xs-rounds N (40) --ivt-x N (4) --ivt-y N (8)\n"
      "  -v, --verbose   --no-thp\n",
      VERSION);
}
int main(int argc, char **argv) {
  if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
    usage();
    return 0;
  }
  const char *cmd = argv[1];
  const char *fitfile = NULL;
  cfg_defaults();
  enum {
    O_HELPER = 1000, O_WS, O_DWS, O_MLP, O_ALU, O_SEQ, O_STRIDE, O_ORDER, O_ORDERL, O_NLIST, O_UPDOWN, O_SPIN, O_ACTBY, O_IDLEMAX, O_IDLECPUS,
    O_SETTLE, O_WARM, O_MEAS, O_PFMSR, O_TEL, O_WINDOW, O_SCHED, O_DUR, O_WLIST, O_FEAT, O_LABEL, O_THR, O_LAMBDA, O_CPUS, O_PAGES, O_SETG,
    O_SLICE, O_SSSTEPS, O_XSL, O_XSR, O_IVTX, O_IVTY, O_NOTHP, O_PARK
  };
  static struct option lo[] = {
      {"probe", 1, 0, 'p'}, {"helper", 1, 0, O_HELPER}, {"method", 1, 0, 'm'}, {"workload", 1, 0, 'w'}, {"ws", 1, 0, O_WS},
      {"dram-ws", 1, 0, O_DWS}, {"mlp", 1, 0, O_MLP}, {"alu", 1, 0, O_ALU}, {"seq", 0, 0, O_SEQ}, {"stride", 1, 0, O_STRIDE},
      {"active", 1, 0, 'a'}, {"nactive", 1, 0, 'n'}, {"order", 1, 0, O_ORDER}, {"order-list", 1, 0, O_ORDERL}, {"nlist", 1, 0, O_NLIST},
      {"updown", 0, 0, O_UPDOWN}, {"spin", 1, 0, O_SPIN}, {"activate-by", 1, 0, O_ACTBY}, {"idle-max", 1, 0, O_IDLEMAX},
      {"idle-cpus", 1, 0, O_IDLECPUS}, {"settle", 1, 0, O_SETTLE}, {"warm", 1, 0, O_WARM}, {"meas", 1, 0, O_MEAS}, {"reps", 1, 0, 'r'},
      {"out", 1, 0, 'o'}, {"pf-msr", 1, 0, O_PFMSR}, {"telemetry", 0, 0, O_TEL}, {"window", 1, 0, O_WINDOW}, {"schedule", 1, 0, O_SCHED},
      {"duration", 1, 0, O_DUR}, {"wlist", 1, 0, O_WLIST}, {"features", 1, 0, O_FEAT}, {"label", 1, 0, O_LABEL}, {"thr", 1, 0, O_THR},
      {"lambda", 1, 0, O_LAMBDA}, {"cpus", 1, 0, O_CPUS}, {"interval", 1, 0, 'i'}, {"dur", 1, 0, 'd'}, {"pages", 1, 0, O_PAGES},
      {"set-group", 1, 0, O_SETG}, {"slice-kb", 1, 0, O_SLICE}, {"ss-steps", 1, 0, O_SSSTEPS}, {"xs-lines", 1, 0, O_XSL},
      {"xs-rounds", 1, 0, O_XSR}, {"ivt-x", 1, 0, O_IVTX}, {"ivt-y", 1, 0, O_IVTY}, {"no-thp", 0, 0, O_NOTHP}, {"park", 1, 0, O_PARK}, {"verbose", 0, 0, 'v'},
      {"help", 0, 0, 'h'}, {0, 0, 0, 0}};
  int o;
  optind = 2;
  while ((o = getopt_long(argc, argv, "p:m:w:a:n:r:o:i:d:vh", lo, NULL)) != -1) {
    switch (o) {
      case 'p': C.probe = atoi(optarg); break;
      case O_HELPER: C.helper = atoi(optarg); break;
      case 'm': snprintf(C.method, sizeof C.method, "%s", optarg); break;
      case 'w': snprintf(C.workload, sizeof C.workload, "%s", optarg); break;
      case O_WS: C.ws = (size_t)parse_size(optarg); break;
      case O_DWS: C.dram_ws = (size_t)parse_size(optarg); break;
      case O_MLP: C.mlp = atoi(optarg); break;
      case O_ALU: C.alu = atoi(optarg); break;
      case O_SEQ: C.seq = 1; break;
      case O_STRIDE: C.stride = (size_t)parse_size(optarg); break;
      case 'a': snprintf(C.active, sizeof C.active, "%s", optarg); break;
      case 'n': C.nactive = atoi(optarg); break;
      case O_ORDER: snprintf(C.order, sizeof C.order, "%s", optarg); break;
      case O_ORDERL: snprintf(C.order_list, sizeof C.order_list, "%s", optarg); break;
      case O_NLIST: snprintf(C.nlist, sizeof C.nlist, "%s", optarg); break;
      case O_UPDOWN: C.updown = 1; break;
      case O_SPIN: snprintf(C.spin, sizeof C.spin, "%s", optarg); break;
      case O_ACTBY: snprintf(C.activate_by, sizeof C.activate_by, "%s", optarg); break;
      case O_IDLEMAX: snprintf(C.idle_max, sizeof C.idle_max, "%s", optarg); break;
      case O_IDLECPUS: snprintf(C.idle_cpus, sizeof C.idle_cpus, "%s", optarg); break;
      case O_SETTLE: C.settle_ms = atof(optarg); break;
      case O_WARM: C.warm_ms = atof(optarg); break;
      case O_MEAS: C.meas_ms = atof(optarg); break;
      case 'r': C.reps = atoi(optarg); break;
      case 'o': snprintf(C.out, sizeof C.out, "%s", optarg); break;
      case O_PFMSR: C.pf_msr = strtoll(optarg, NULL, 0); break;
      case O_TEL: C.telemetry = 1; break;
      case O_WINDOW: C.window_us = atof(optarg); break;
      case O_SCHED: snprintf(C.schedule, sizeof C.schedule, "%s", optarg); break;
      case O_DUR: C.duration_ms = atof(optarg); break;
      case O_WLIST: snprintf(C.wlist, sizeof C.wlist, "%s", optarg); break;
      case O_FEAT: snprintf(C.features, sizeof C.features, "%s", optarg); break;
      case O_LABEL: snprintf(C.label, sizeof C.label, "%s", optarg); break;
      case O_THR: C.thr = atof(optarg); break;
      case O_LAMBDA: C.lambda = atof(optarg); break;
      case O_CPUS: snprintf(C.cpus, sizeof C.cpus, "%s", optarg); break;
      case 'i': C.interval_ms = atof(optarg); break;
      case 'd': C.dur_s = atof(optarg); break;
      case O_PAGES: C.pages = atoi(optarg); break;
      case O_SETG: C.set_group = atoi(optarg); break;
      case O_SLICE: C.slice_kb = atoi(optarg); break;
      case O_SSSTEPS: C.ss_steps = atoi(optarg); break;
      case O_XSL: C.xs_lines = atoi(optarg); break;
      case O_XSR: C.xs_rounds = atoi(optarg); break;
      case O_IVTX: C.ivt_x = atoi(optarg); break;
      case O_IVTY: C.ivt_y = atoi(optarg); break;
      case O_NOTHP: C.no_thp = 1; break;
      case O_PARK:
        if (!strcasecmp(optarg, "offline")) g_park_off = 1;
        else if (strcasecmp(optarg, "idle")) die("--park must be idle (default) or offline");
        break;
      case 'v': g_verbose = 1; break;
      case 'h': usage(); return 0;
      default: usage(); return 1;
    }
  }
  if (!strcmp(cmd, "fit")) {
    if (optind < argc) fitfile = argv[optind];
    if (!fitfile) die("usage: ini_probe fit FILE.csv [--features a,b] [--label sil_frac] [--thr 0.5]");
    cmd_fit(fitfile);
    return 0;
  }
  if (C.reps < 1) C.reps = 1;
  if (C.xs_lines < 64) C.xs_lines = 64;
  if (C.xs_rounds < 1) C.xs_rounds = 1;
  if (C.ivt_x < 1) C.ivt_x = 1;
  if (C.ivt_y < 1) C.ivt_y = 1;
  if (C.pages < 1) C.pages = 1;
  if (C.ss_steps < 100) C.ss_steps = 100;
  if (C.window_us < 20) C.window_us = 20;
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_sig;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL); /* SSH disconnect: still restore cpuidle / online / MSR state */
  atexit(cleanup);
  g_rng ^= (uint64_t)time(NULL) * 0x9E3779B97F4A7C15ULL;
  topo_init();
  detect_features();
  pmu_init();
  idle_init();
  tsc_calibrate();
  if (C.probe < 0) C.probe = pick_probe();
  if (C.probe >= T.ncpu || !T.online[C.probe]) die("probe cpu%d is not online", C.probe);
  if (C.helper < 0) C.helper = pick_helper(C.probe);
  if (C.helper >= 0 && (C.helper >= T.ncpu || !T.online[C.helper])) die("helper cpu%d is not online", C.helper);
  if (!strcasecmp(C.spin, "alu")) g_spin_kind = SPK_ALU;
  else if (!strcasecmp(C.spin, "pause")) g_spin_kind = SPK_PAUSE;
  else if (!strcasecmp(C.spin, "l2")) g_spin_kind = SPK_L2;
  else if (!strcasecmp(C.spin, "llc")) g_spin_kind = SPK_LLC;
  else if (!strcasecmp(C.spin, "mem")) g_spin_kind = SPK_MEM;
  else die("unknown --spin '%s'", C.spin);
  if (!strcasecmp(C.activate_by, "c1")) g_act_c1 = 1;
  else if (strcasecmp(C.activate_by, "spin")) die("unknown --activate-by '%s'", C.activate_by);
  if (g_act_c1 && geteuid() != 0) die("--activate-by c1 needs root (writes cpuidle sysfs)");
  if (g_park_off && geteuid() != 0) die("--park offline needs root (writes /sys/devices/system/cpu/cpuN/online)");
  if (g_park_off && g_act_c1) die("--park offline and --activate-by c1 cannot be combined");
  if (C.idle_max[0]) {
    int cl[MAXCPU], n = 0;
    if (C.idle_cpus[0]) n = parse_cpulist(C.idle_cpus, cl, MAXCPU);
    else
      for (int c = 0; c < T.ncpu; c++)
        if (T.online[c]) cl[n++] = c;
    for (int i = 0; i < n; i++)
      if (idle_limit(cl[i], C.idle_max) < 0) warnf("cannot limit cpu%d to %s (root? state name? see 'info')", cl[i], C.idle_max);
  }
  if (pin_self(C.probe)) die("cannot pin to cpu%d", C.probe);
  if (C.pf_msr >= 0) {
    int cl[2] = {C.probe, T.sib[C.probe]};
    for (int i = 0; i < 2; i++)
      if (cl[i] >= 0 && pf_set(cl[i], (uint64_t)C.pf_msr)) warnf("cannot write MSR 0x1A4 on cpu%d (sudo modprobe msr; root)", cl[i]);
  }
  if (g_verbose) printf("TSC %.3f GHz, probe cpu%d (%c), helper cpu%d\n", g_tsc_ghz, C.probe, T.type[C.probe], C.helper);
  if (!strcmp(cmd, "info")) cmd_info();
  else if (!strcmp(cmd, "calib")) cmd_calib();
  else if (!strcmp(cmd, "probe")) cmd_probe();
  else if (!strcmp(cmd, "sweep")) cmd_sweep();
  else if (!strcmp(cmd, "timeline")) cmd_timeline();
  else if (!strcmp(cmd, "grid")) cmd_grid();
  else if (!strcmp(cmd, "monitor")) cmd_monitor();
  else if (!strcmp(cmd, "setscan")) cmd_setscan();
  else {
    usage();
    die("unknown command '%s'", cmd);
  }
  if (g_csv) {
    fclose(g_csv);
    printf("CSV written to %s\n", C.out);
  }
  return 0;
}
