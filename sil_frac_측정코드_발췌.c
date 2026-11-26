/*
 * sil_frac 측정 코드 발췌 — ini_probe v1.4 (규칙 1에 쓴 v1.1~v1.4에서 이 부분은 동일)
 * =======================================================================================
 * 원본 소스에서 L2_LINES_OUT.SILENT / NON_SILENT를 세고 sil_frac을 계산하는 부분만
 * 순서대로 그대로 옮겨 놓은 파일임. 각 조각 위에 원본 행 번호와 해설을 붙였음.
 * 이 파일만으로는 컴파일되지 않음 (전체는 ini_probe_v1.4.c).
 *
 * 측정의 흐름
 *   [1] 측정 스레드를 측정 코어(probe)에 고정함                       pin_self(), main
 *   [2] P코어 PMU의 type 번호를 sysfs에서 읽음 (하이브리드 CPU라 P/E PMU가 따로 있음)  pmu_init()
 *   [3] 이벤트 4개를 한 묶음(group)으로 엶                           EV_P_L2, pgrp_open(), i1_open()
 *         L2_LINES_IN.ALL          event 0x25 umask 0x1f   L2에 들어온 라인
 *         L2_LINES_OUT.SILENT      event 0x26 umask 0x01   조용히 버린 라인
 *         L2_LINES_OUT.NON_SILENT  event 0x26 umask 0x02   L3로 넘기며 내보낸 라인
 *         L2_LINES_OUT.USELESS_HWPF event 0x26 umask 0x04  쓰이지 않은 프리페치 라인
 *       pid=0, cpu=-1 → "이 스레드가 어느 CPU에서 돌든" 셈. [1]로 측정 코어에 고정했으므로
 *       결과적으로 측정 코어의 L2만 셈. 묶음이라 4개가 같은 순간에 함께 켜지고 읽힘.
 *   [4] 측정 전 값 읽기 → 워크로드 실행 → 측정 후 값 읽기 → 차이        pgrp_read(), pdelta()
 *       (멀티플렉싱으로 카운터가 일부 시간만 돌았으면 enabled/running 비율로 보정)
 *   [5] sil_frac = SILENT / (SILENT + NON_SILENT), 판정 0.7 / 0.3        silfrac(), verdict_sil()
 *
 *   sweep·probe·grid는 [4]를 i1_measure()로 한 번에 30 ms 동안 하고,
 *   timeline은 창(50~200 µs)마다 [4]를 반복함 (맨 아래 조각).
 */

/* [1] 측정 스레드를 한 CPU에 고정하는 함수 */
/* ---- ini_probe_v1.4.c 212~217행 ---- */
static int pin_self(int cpu) {
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s);
  return pthread_setaffinity_np(pthread_self(), sizeof s, &s);
}

/* [1] main(): 명령 실행 전에 측정 스레드를 측정 코어(-p)에 고정 */
/* ---- ini_probe_v1.4.c 2831~2831행 ---- */
  if (pin_self(C.probe)) die("cannot pin to cpu%d", C.probe);

/* [5] sil_frac 계산식. 내보낸 라인이 하나도 없으면 NAN */
/* ---- ini_probe_v1.4.c 134~134행 ---- */
static double silfrac(double sil, double nsil) { return (sil + nsil) > 0 ? sil / (sil + nsil) : NAN; }

/* [3] 이벤트 정의. EVC(event, umask, cmask)로 perf raw config 값을 만듦.
 *     EV_P_L2의 4개가 이 측정의 전부이고, E_SIL·E_NSIL이 SILENT·NON_SILENT의 위치(인덱스) */
/* ---- ini_probe_v1.4.c 685~700행 ---- */
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

/* [3] 보조 묶음: 사이클·명령 수 등 (sil_frac 계산에는 안 쓰고 IPC·클럭 계산용) */
/* ---- ini_probe_v1.4.c 702~709행 ---- */
static const evdef_t EV_P_AUX[] = {
    {"CPU_CLK_UNHALTED.THREAD", EVC(0x3c, 0x00, 0)},
    {"INST_RETIRED.ANY", EVC(0xc0, 0x00, 0)},
    {"CPU_CLK_UNHALTED.REF_TSC", 0x0300}, /* fixed-counter pseudo encoding */
    {"LONGEST_LAT_CACHE.REFERENCE", EVC(0x2e, 0x4f, 0)},
    {"LONGEST_LAT_CACHE.MISS", EVC(0x2e, 0x41, 0)},
};
enum { A_CYC, A_INST, A_REFC, A_LLCREF, A_LLCMISS };

/* [2] P코어/E코어 PMU type 번호 읽기. root가 아니면 커널 모드는 빼고 셈 */
/* ---- ini_probe_v1.4.c 753~763행 ---- */
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

/* [3][4] 묶음 열기·읽기·차이 계산
 *  pgrp_open : 첫 이벤트를 리더로, 나머지를 그 묶음에 붙여 perf_event_open. 리셋 후 켬
 *  pgrp_read : 리더 fd 하나를 read 하면 묶음 전체 값 + enabled/running 시간이 함께 옴
 *  pdelta    : 두 스냅샷의 차이 × (enabled/running) → 보정된 증가량 */
/* ---- ini_probe_v1.4.c 764~826행 ---- */
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


/* [3][4] 측정 한 번 (sweep·probe·grid가 사용)
 *  i1_open    : 측정 코어가 P코어일 때 EV_P_L2 묶음(g_g1)을 한 번만 엶
 *  i1_measure : warm_ms 예열 → 읽기(a) → meas_ms 동안 워크로드 → 읽기(b) → 차이
 *               r->sil = SILENT 증가량, r->nsil = NON_SILENT 증가량.
 *               tel=1이면 grid용 텔레메트리 묶음(TEL1~4)도 함께 읽음 (sil_frac과 무관) */
/* ---- ini_probe_v1.4.c 1185~1293행 ---- */
typedef struct {
  double fills, sil, nsil, useless, llc_ref, llc_miss, cyc, inst, refc, run_frac, secs, loads;
  int tel;
  double st_tot, st_l3, occ, occ_cyc, cyc_t, offreq, l3hit, l3miss, l2miss, inst_t;
  double st_l1d, st_l2, memany, cyc_t3;
  double dem_occ, dem_cyc, l1pend_cyc, l2res, cyc_t4;
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
  pgrp_t t1, t2, t3, t4;
  int tok = 0, t3ok = 0, t4ok = 0;
  if (tel && pgrp_open(&t1, g_pmu_core, EV_P_TEL1, NEV(EV_P_TEL1), 0, -1) == 0) {
    if (pgrp_open(&t2, g_pmu_core, EV_P_TEL2, NEV(EV_P_TEL2), 0, -1) == 0) tok = 1;
    else pgrp_close(&t1);
  }
  if (tok) t3ok = pgrp_open(&t3, g_pmu_core, EV_P_TEL3, NEV(EV_P_TEL3), 0, -1) == 0;
  if (tok) t4ok = pgrp_open(&t4, g_pmu_core, EV_P_TEL4, NEV(EV_P_TEL4), 0, -1) == 0;
  if (tel && !tok) warnf("telemetry event groups could not be opened (run with -v for details)");
  wl_run_ms(w, warm_ms);
  psnap_t a, b, a0, b0, a1, b1, a2, b2, a3, b3, a4, b4;
  int rc = pgrp_read(&g_g1, &a);
  if (g_g0_open) pgrp_read(&g_g0, &a0);
  if (tok) {
    pgrp_read(&t1, &a1);
    pgrp_read(&t2, &a2);
  }
  if (t3ok) pgrp_read(&t3, &a3);
  if (t4ok) pgrp_read(&t4, &a4);
  double s0 = now_s();
  uint64_t st = wl_run_ms(w, meas_ms);
  double s1 = now_s();
  rc |= pgrp_read(&g_g1, &b);
  if (g_g0_open) pgrp_read(&g_g0, &b0);
  if (tok) {
    pgrp_read(&t1, &b1);
    pgrp_read(&t2, &b2);
  }
  if (t3ok) pgrp_read(&t3, &b3);
  if (t4ok) pgrp_read(&t4, &b4);
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
  r->st_l1d = r->st_l2 = r->memany = r->cyc_t3 = NAN;
  if (t3ok) {
    pdelta(&t3, &a3, &b3, d, NULL);
    r->st_l1d = d[0];
    r->st_l2 = d[1];
    r->memany = d[2];
    r->cyc_t3 = d[3];
    pgrp_close(&t3);
  }
  r->dem_occ = r->dem_cyc = r->l1pend_cyc = r->l2res = r->cyc_t4 = NAN;
  if (t4ok) {
    pdelta(&t4, &a4, &b4, d, NULL);
    r->dem_occ = d[0];
    r->dem_cyc = d[1];
    r->l1pend_cyc = d[2];
    r->l2res = d[3];
    r->cyc_t4 = d[4];
    pgrp_close(&t4);
  }
  return rc;

/* [5] 판정: 0.7 이상 INCL, 0.3 이하 NONINCL(NI), 그 사이 MIXED */
/* ---- ini_probe_v1.4.c 1295~1300행 ---- */
static const char *verdict_sil(double s) {
  if (isnan(s)) return "?";
  if (s >= 0.7) return "INCL";
  if (s <= 0.3) return "NONINCL";
  return "MIXED";
}

/* [4] timeline 창 기록: 워크로드 조각(chunk) 하나를 돌릴 때마다 g_g1을 읽어
 *     창 하나의 SILENT·NON_SILENT 증가량을 trec_t에 저장 (cmd_timeline 안) */
/* ---- ini_probe_v1.4.c 2091~2095행 ---- */
typedef struct {
  double t_ms;
  int n;
  double fills, sil, nsil, useless, cyc, refc, inst;
} trec_t;

/* ---- ini_probe_v1.4.c 2132~2165행 ---- */
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

/* [5] timeline CSV: 창마다 sil_frac = silfrac(SILENT, NON_SILENT)을 계산해 씀 */
/* ---- ini_probe_v1.4.c 2170~2174행 ---- */
    fprintf(g_csv, "t_ms,n_active,fills,sil_frac,nsil_pf,useless_pf,ghz,ipc\n");
    for (size_t i = 0; i < nw; i++)
      fprintf(g_csv, "%.3f,%d,%.0f,%.5f,%.5f,%.5f,%.3f,%.4f\n", rec[i].t_ms, rec[i].n, rec[i].fills, silfrac(rec[i].sil, rec[i].nsil),
              sdiv(rec[i].nsil, rec[i].fills), sdiv(rec[i].useless, rec[i].fills), sdiv(rec[i].cyc, rec[i].refc) * g_tsc_ghz,
              sdiv(rec[i].inst, rec[i].cyc));

/* [5] sweep·probe 출력: 측정 줄의 "silfrac=" 값 (print_point 안) */

/* ---- ini_probe_v1.4.c 1731~1742행 ---- */
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
  /* … (IVT, xsnp 출력 생략) … */
}
