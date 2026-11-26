/*
 * measure_excerpt_ini_probe.c
 * ----------------------------------------------------------------------------
 * ini_probe에서 sil_frac을 재는 두 방식의 코드 발췌. 원본: ini_probe_v1.4.c (행 번호는 각 블록 앞).
 * sweep·timeline 함수는 v1.1~v1.4가 같고, i1_measure·cmd_grid는 텔레메트리 부분만 버전마다 다름.
 * 이 파일만으로는 빌드되지 않음.
 *
 * [방식 1] sweep·grid : 조건을 고정 → settle 기다림 → (warm 예열 → meas 측정) × reps
 *          측정 한 번 = 워크로드를 meas_ms 동안 돌리고, 시작·끝 카운터 차이로 sil_frac 1개
 * [방식 2] timeline   : 워크로드를 창(window_us) 크기 조각으로 쉬지 않고 돌림.
 *          조각마다 카운터 차이로 sil_frac 1개 기록, schedule 시각에 다른 코어 수를 바꿈
 * ----------------------------------------------------------------------------
 */

/* ===== 134행: sil_frac 계산 ===== */
static double silfrac(double sil, double nsil) { return (sil + nsil) > 0 ? sil / (sil + nsil) : NAN; }

/* ===== 243~273행 중: 기본값 (settle 300 ms, warm 20 ms, meas 30 ms, reps 3, window 200 us) ===== */
  C.settle_ms = 300;
  C.meas_ms = 30;
  C.warm_ms = 20;
  C.reps = 3;
  C.pf_msr = -1;
  C.window_us = 200;

/* ===== 674~685행: 워크로드를 정해진 ms 동안 돌림 (512 스텝씩) ===== */
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

/* ===== [방식 1] 1205~1294행: i1_measure — 측정 한 번 (텔레메트리 부분 일부 생략 없이 원문) ===== */
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
}

/* ===== [방식 1] 1705~1720행: measure_point — probe·sweep의 측정 한 번 ===== */
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
  /* … 판정 문자열 만들기 생략 … */

/* ===== [방식 1] 2031~2090행: cmd_sweep ===== */
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

/* ===== [방식 1] 2218~2270행: cmd_grid 앞부분 (측정 루프까지) ===== */
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
  char wls[8192];
  snprintf(wls, sizeof wls, "%s", C.wlist[0] ? C.wlist : "l3:mlp=1,l3:mlp=4,l3:mlp=16,l3:mlp=8:alu=64,dram:mlp=1,dram:mlp=4,dram:mlp=16,dram:mlp=8:seq");
  enum { MAXGW = 160 };
  static wl_t W[MAXGW];
  int nw = 0, ntok = 0;
  char *save = NULL;
  for (char *t = strtok_r(wls, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
    ntok++;
    if (nw >= MAXGW) continue;
    if (wl_parse(t, &W[nw]) < 0) die("bad workload spec '%s'", t);
    wl_setup(&W[nw], x.probe);
    nw++;
  }
  if (ntok > nw) warnf("--wlist has %d workloads; only the first %d are used", ntok, nw);
  printf("grid: probe cpu%d, %d active-core steps x %d workloads x %d reps (telemetry on)\n", x.probe, nn, nw, C.reps);
  csv_open();
  if (g_csv)
    fprintf(g_csv, "n_req,rep,wl,kind,ws_kb,mlp,alu,seq,busy_cores,busy_P,busy_E,fills,sil_frac,nsil_pf,useless_pf,fills_pki,llc_miss_ratio,ipc,ghz,"
                   "stall_frac,l3stall_frac,occ,occ_busy,offreq_pki,l3hit_pki,l3miss_pki,l2miss_pki,run_frac,verdict,label,"
                   "div,l1dstall_frac,l2stall_frac,memany_frac,fills_pc,l3miss_pc,pfx,dem_occ,dem_busy,l1pend_busy,l2res_frac\n");
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
        printf("n=%-2d %-46s sil=%.3f ipc=%.2f stall=%.2f memany=%.3f occbusy=%.3f occ=%.1f fill/cyc=%.4f l3miss/ki=%.1f pfx=%.2f dem=%.3f l1pend=%.3f => %s\n", ns[i],
  /* … CSV 기록 생략 … */

/* ===== [방식 2] 2091~2216행: cmd_timeline 전체 ===== */
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
