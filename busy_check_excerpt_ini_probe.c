/*
 * busy_check_excerpt_ini_probe.c
 * ----------------------------------------------------------------------------
 * ini_probe에서 "다른 코어가 실제로 일하고 있었는지(C0)"를 확인하는 데 쓴 코드 발췌.
 * 원본: ini_probe_v1.4.c (아래 각 함수 앞의 행 번호). v1.1~v1.4 모두 같은 코드임.
 * 이 파일만으로는 빌드되지 않음(전역 T, MAXCPU, read_file 등은 원본에 있음).
 *
 * 무엇을 하나
 *   - 하드웨어 C-state(C0/C1)를 직접 읽는 코드는 없음.
 *   - 대신 측정 한 번의 시작과 끝에 OS가 기록한 "코어별 쉰 시간"을 읽어,
 *       busy = 1 - (쉰 시간 / 전체 시간)
 *     을 코어마다 계산함. busy가 0.5보다 크면 그 코어를 "활성"으로 셈.
 *   - 쉰 시간을 읽는 곳은 두 가지:
 *       (1) cpuidle 드라이버가 있으면 /sys/devices/system/cpu/cpuN/cpuidle/stateK/time
 *           (상태별 체류 시간, µs). POLL 상태는 C0이므로 쉰 시간에서 뺌.
 *       (2) 없으면 /proc/stat의 idle + iowait (jiffies).  <- 실험 서버는 cpuidle 드라이버가
 *           없어서 항상 (2)를 씀. 이때 "쉰 시간"은 OS가 HLT로 재운 시간 = C1 체류.
 *   - 결과는 측정 줄의 busyCores(P/E)=…, grid CSV의 busy_cores / busy_P / busy_E 열이 됨.
 *
 * 한계
 *   - /proc/stat은 보통 10 ms(USER_HZ=100) 단위라 30 ms 측정에서는 거칠게만 보임.
 *   - 실제로 C0에 있었는지가 아니라 "OS가 그 코어를 놀리지 않았는지"를 보는 것임.
 *   - timeline 명령(C, F, G, J2, O3)은 이 확인을 하지 않음. 일정대로 spinner를 깨우고
 *     재웠다는 프로그램 쪽 기록(n_active)만 남김.
 *   - 같은 물리 코어의 스레드는 가장 바쁜 값 하나로 묶음(HT는 꺼져 있어 영향 없음).
 * ----------------------------------------------------------------------------
 */

/* ===== ini_probe_v1.4.c 828~840행: 자료 구조 ===== */
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


/* ===== 842~854행: 시작할 때 코어별 cpuidle 상태 이름을 읽음 (서버에서는 상태가 0개) ===== */
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

/* ===== 855~884행: 지금 시점의 쉰 시간 스냅샷 (cpuidle 시간 + /proc/stat) ===== */
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

/* ===== 885~906행: 두 스냅샷 사이의 코어별 busy 비율 ===== */
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

/* ===== 1689~1704행: busy > 0.5인 물리 코어를 P/E로 나눠 셈 ===== */
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

/* ===== 1705~1720행: probe·sweep 측정 한 번 앞뒤로 스냅샷 (measure_point 앞부분) ===== */
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
  /* … 이후 생략 … */

/* ===== 2254~2260행: grid 측정 한 번 앞뒤로 스냅샷 (cmd_grid 안) ===== */
        double busy[MAXCPU];
        int bc, bp, be;
        idle_snap(g_is0);
        i1_measure(&W[k], C.warm_ms > 50 ? C.warm_ms : 50, C.meas_ms, 1, &q);
        idle_snap(g_is1);
        idle_busy(g_is0, g_is1, busy);
        busy_summary(busy, &bc, &bp, &be);

/* ===== 1734행: 결과가 측정 줄에 찍히는 곳 ===== */
  printf("n=%-2d rep%d act=%-24.24s busyCores(P/E)=%d(%d/%d) L2act=%.0fMB L3/L2=%.1f", p->n_req, rep, act, p->busy_cores, p->busy_P, p->busy_E,
         p->act_l2_mb, p->l3_l2_ratio);
