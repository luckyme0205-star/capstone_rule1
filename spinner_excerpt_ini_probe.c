/*
 * spinner_excerpt_ini_probe.c
 * ----------------------------------------------------------------------------
 * ini_probe에서 다른 코어를 "켜고(spinner 돌리기) 끄는(spinner 재우기)" 부분 발췌.
 * 원본: ini_probe_v1.4.c (각 블록 앞에 원본 행 번호). v1.1~v1.4 모두 같은 코드임.
 * 이 파일만으로는 빌드되지 않음(T, C, die, warnf 등 나머지는 원본에 있음).
 *
 * 흐름 요약
 *   1) activate_set(목록, n)        목록의 앞 n개 코어는 켜고, 나머지는 재우라고 지시
 *   2) spinner_set(코어, 1 또는 0)  그 코어의 spinner 상태를 SP_RUN / SP_SLEEP으로 바꿈
 *                                   (처음 켜는 코어면 스레드를 새로 만듦)
 *   3) spinner_main()               spinner 스레드 본체. 자기 코어에 고정(pin_self)된 채
 *                                   - SP_RUN이면 루프를 계속 돌아 코어를 C0에 묶어 둠
 *                                   - SP_SLEEP이면 조건 변수에서 잠듦 → OS가 코어를 HLT(C1)로 재움
 *   4) spinners_stop_all()          프로그램이 끝날 때 모든 spinner를 SP_EXIT로 끝냄
 *
 * 핵심 변수
 *   g_sp[cpu]     코어마다 spinner 하나 (spinner_t)
 *   state         SP_RUN(1) / SP_SLEEP(0) / SP_EXIT(2). 원자 변수라 잠금 없이 읽음
 *   mu, cv        재울 때 쓰는 뮤텍스와 조건 변수. 깨울 때 pthread_cond_signal
 *   kind          루프 종류. --spin 옵션 (alu 기본, pause, l2, llc, mem)
 *   g_spin_kind   새 spinner가 쓸 루프 종류
 * ----------------------------------------------------------------------------
 */

/* ===== 212~217행: 현재 스레드를 한 코어에 고정 ===== */
static int pin_self(int cpu) {
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s);
  return pthread_setaffinity_np(pthread_self(), sizeof s, &s);
}

/* ===== 129행: pause 명령 ===== */
static inline void cpu_pause(void) { __asm__ __volatile__("pause" ::: "memory"); }

/* ===== 976~989행: 상태값, 루프 종류, spinner 구조체 ===== */
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

/* ===== 1006~1058행: spinner 스레드 본체 ===== */
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

/* ===== 1059~1076행: spinner 하나를 켜거나 재움 ===== */
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

/* ===== 1077~1088행: 끝낼 때 모든 spinner 종료 ===== */
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

/* ===== 1089~1117행: 목록의 앞 n개만 켜고 나머지는 재움 ===== */
/* (g_park_off: --park offline, g_act_c1: --activate-by c1. 규칙 1 실험에서는 둘 다 쓰지 않아 맨 아래 else만 실행됨) */
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

/* ===== 2811~2816행: --spin 옵션 → 루프 종류 ===== */
  if (!strcasecmp(C.spin, "alu")) g_spin_kind = SPK_ALU;
  else if (!strcasecmp(C.spin, "pause")) g_spin_kind = SPK_PAUSE;
  else if (!strcasecmp(C.spin, "l2")) g_spin_kind = SPK_L2;
  else if (!strcasecmp(C.spin, "llc")) g_spin_kind = SPK_LLC;
  else if (!strcasecmp(C.spin, "mem")) g_spin_kind = SPK_MEM;
  else die("unknown --spin '%s'", C.spin);

/* ===== 2048행: sweep에서 쓰는 곳 (단계마다 n개 켜고 settle만큼 기다림) ===== */
    activate_set(x.order, n);
    sleep_ms(C.settle_ms);

/* ===== cmd_timeline 안: 일정 시각이 되면 코어 수를 바꿈 ===== */
  activate_set(x.order, x.norder); /* create all spinner threads up front, then park them */
  sleep_ms(50);
  activate_set(x.order, 0);
  sleep_ms(C.settle_ms);
  /* … */
  while (!g_stop && nw < maxw) {
    double tms = (now_s() - start) * 1e3;
    if (tms >= dur) break;
    while (ei < nev && ev_t[ei] <= tms) {
      activate_set(x.order, ev_n[ei]);
      cur = ev_n[ei];
      ei++;
    }
    g_sink += wl_run(w, chunk);
