/*
 * workload_ini_probe.c
 * ----------------------------------------------------------------------------
 * ini_probe에서 측정 코어가 돌리는 워크로드(무작위 포인터 추적) 코드.
 *
 * 구성
 *   [A] 원본 그대로 옮긴 부분: ini_probe_v1.4.c의 해당 행 (각 블록 앞에 행 번호 표시).
 *   [B] 이 파일만으로 빌드·실행해 볼 수 있게 덧붙인 부분: 원본의 전역 설정·토폴로지 대신 쓰는
 *       최소한의 대체 코드와 main(). 원본에는 없음.
 *
 * 빌드와 실행 (root 불필요)
 *   gcc -O2 -pthread -o workload workload_ini_probe.c -lm
 *   ./workload l3:mlp=8:alu=64 200          # 워크로드 문자열, 실행 시간(ms)
 *   ./workload dram:mlp=1:alu=384 200
 *
 * 버전 차이
 *   v1.1에는 나눗셈(div) 기능이 없음(v1.2에서 추가). div=0이면 v1.1~v1.4 동작이 같음.
 *   규칙 1 실험은 모두 div=0.
 *
 * 핵심 아이디어
 *   1) 버퍼 하나를 64바이트 라인으로 나누고, 라인 번호를 무작위로 섞은 순서(perm)대로
 *      "다음 라인의 주소"를 각 라인 첫 8바이트에 적어 하나의 고리를 만듦 (wbuf_get).
 *   2) 고리를 만든 뒤 clflush로 캐시에서 모두 비움 → 측정 중에는 읽기만 하므로 수정된
 *      라인이 생기지 않음 (sil_frac이 모드만 반영하게 하는 조건).
 *   3) 측정은 고리의 서로 떨어진 위치 K곳(mlp = K)에서 동시에 주소를 따라감. 다음 주소는
 *      지금 라인을 읽어야 알 수 있어서, 한 체인 안에서는 읽기가 하나씩만 진행됨.
 *   4) 한 번 읽을 때마다 alu번의 의존 계산(곱셈·덧셈)과 div번의 나눗셈을 넣어, 읽기 간격을
 *      늘려 메모리 부하를 낮춤.
 *   5) 버퍼는 2 MB 경계에 맞춰 잡고 huge page를 요청함(THP) → TLB miss 영향을 줄임.
 *   6) 작업 크기 기본값: l3 = 4 × L2(=8 MB, L3의 절반 이하), dram = 8 × L3(최소 256 MB → 288 MB).
 *
 * 워크로드 문자열 (결과 파일의 l3:ws=8192K:mlp=8:alu=64:div=0:rand:stride=64)
 *   l3 / dram   작업 크기 기본값 종류          ws=     작업 크기 (K, M, G 단위 가능)
 *   mlp=        동시 체인 수 (1,2,3,4,6,8,12,16 중 가까운 아래 값)
 *   alu=        읽기마다 의존 계산 횟수         div=    읽기마다 나눗셈 횟수
 *   rand / seq  무작위 고리 / 순차 고리          stride= 라인 간격 (기본 64바이트)
 * ----------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <time.h>

/* ===================== [B] 원본의 전역 정의를 대신하는 최소 코드 ===================== */
#define KB (1UL << 10)
#define MB (1UL << 20)
#define HUGE2M (2UL << 20)
static volatile uint64_t g_sink;
static int g_has_clflushopt = 0;
static void die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "error: ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}
static volatile int g_stop = 0;
static inline void mfence(void) { __asm__ __volatile__("mfence" ::: "memory"); }
/* 원본의 cfg_t C 중 워크로드가 쓰는 필드만 (기본값도 원본과 같음) */
static struct { size_t ws, dram_ws, stride; int mlp, alu, seq, dv, no_thp; } C = {0, 0, 64, 8, 0, 0, 0, 0};
/* 원본은 sysfs에서 코어별 L2, 공용 L3 크기를 읽음. 여기서는 i9-13900K P코어 값으로 고정 */
static long l2_of(int cpu) { (void)cpu; return (long)(2 * MB); }
static long l3_of(void) { return (long)(36 * MB); }

/* ===================== [A] ini_probe_v1.4.c 106~110행: 시간 ===================== */
static double now_s(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* ===================== [A] 136~152행: 난수와 섞기 (고리 순서를 무작위로) ===================== */
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

/* ===================== [A] 175~185행: 크기 문자열 해석 (8192K, 288M …) ===================== */
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

/* ===================== [A] 409~463행: 메모리 할당(huge page)과 캐시 비우기 ===================== */
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

/* ===================== [A] 464~514행: 포인터 추적 커널 (mlp 체인, alu·div 의존 연산) ===================== */
/* K independent pointer chains (memory-level parallelism = K), optional dependent ALU work per step,
   optional dependent 64-bit divisions per step (g_div: non-memory stalls; thread-local) */
static __thread int g_div = 0;
static __thread uint64_t g_divisor = 3;
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
      for (int a = 0; a < g_div; a++) {                                               \
        uint64_t q_ = x | 0x8000000000000000ULL, r_ = 0;                              \
        __asm__ __volatile__("divq %2" : "+a"(q_), "+d"(r_) : "r"(g_divisor));        \
        x = q_ + r_ + 0x9E3779B97F4A7C15ULL;                                          \
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

/* ===================== [A] 565~683행: 워크로드 버퍼(고리) 만들기, 해석, 실행 ===================== */
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
  int kind, mlp, alu, seq, dv;
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
  snprintf(w->label, sizeof w->label, "%s:ws=%zuK:mlp=%d:alu=%d:div=%d:%s:stride=%zu", w->kind == WL_L3 ? "l3" : "dram", w->ws / KB, w->mlp,
           w->alu, w->dv, w->seq ? "seq" : "rand", w->stride);
}
static int wl_parse(const char *spec, wl_t *w) {
  memset(w, 0, sizeof *w);
  w->mlp = C.mlp;
  w->alu = C.alu;
  w->dv = C.dv;
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
    else if (!strcasecmp(k, "div")) w->dv = atoi(v);
    else if (!strcasecmp(k, "stride")) w->stride = (size_t)parse_size(v);
    else if (!strcasecmp(k, "seq")) w->seq = atoi(v);
    else return -1;
  }
  return 0;
}
static uint64_t wl_run(wl_t *w, uint64_t steps) {
  g_div = w->dv;
  uint64_t r = chase(w->h, w->mlp, steps, w->alu);
  g_div = 0;
  return r;
}
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

/* ===================== [B] 시험용 main (원본에는 없음) ===================== */
int main(int argc, char **argv) {
  unsigned a, b, c, d;
  if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) g_has_clflushopt = (b >> 23) & 1;
  (void)free_mem; /* 원본에서 쓰는 함수, 여기서는 안 씀 */
  const char *spec = argc > 1 ? argv[1] : "l3:mlp=8:alu=64";
  double ms = argc > 2 ? atof(argv[2]) : 200;
  wl_t w;
  if (wl_parse(spec, &w) < 0) die("bad workload spec '%s'", spec);
  wl_setup(&w, 0);
  printf("workload %s  (2MB-page backing %.0f%%)\n", w.label, w.b->huge_frac * 100);
  wl_run_ms(&w, 50); /* 예열 */
  double t0 = now_s();
  uint64_t steps = wl_run_ms(&w, ms);
  double dt = now_s() - t0;
  printf("%llu steps in %.1f ms -> %.1f M loads/s (%.1f ns per step)\n", (unsigned long long)steps, dt * 1e3,
         (double)steps * w.mlp / dt * 1e-6, dt / (double)steps * 1e9);
  return (int)(g_sink & 0);
}
