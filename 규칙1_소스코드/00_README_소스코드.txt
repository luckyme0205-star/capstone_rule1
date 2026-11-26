규칙 1에 사용한 소스코드 (ini_probe v1.1 ~ v1.4) — 안내와 해설
========================================================================

1. 들어 있는 파일
------------------------------------------------------------------------
ini_probe_v1.1.c   초기 실험(s2, s3, s6), A, C, D, E 결과를 만든 버전
ini_probe_v1.2.c   F, G 결과를 만든 버전
ini_probe_v1.3.c   J2 결과를 만든 버전
ini_probe_v1.4.c   N, O3 결과를 만든 버전
Makefile           make 하면 네 버전이 각각 ini_probe_v1.1 ~ ini_probe_v1.4로 빌드됨

v1.0은 넣지 않았음. 규칙 1 결과 파일 어디에도 v1.0의 출력 형식이 나오지 않기 때문임.


2. 어느 결과가 어느 버전에서 나왔는지 (판단 근거)
------------------------------------------------------------------------
결과 파일에는 버전 번호가 찍혀 있지 않아서, 버전마다 다른 출력 형식으로 판단했음.

  출력 형식                                                     버전   해당 결과
  측정 줄에 "silfrac=… (sil/fill=… nsil/fill=…) evict/us="     v1.1+  초기 s2·s3, A, D
    (v1.0은 "sil=… nsil=… usl=… fill/us="로 찍음)
  grid 줄 "sil= nsil= ipc= stall= occ= l3miss/ki="             v1.1   초기 s6, B, E
  grid 줄 "sil= ipc= stall= l1dst= l2st= occ= …"               v1.2   H (F, G와 같은 파일)
  grid 줄 "… memany= occbusy= occ= fill/cyc= …"                v1.3   J3 (J2와 같은 파일)
  grid 줄 "… pfx= dem= l1pend="                                v1.4   N, O1·O2 (O3와 같은 파일)

규칙 1과 직접 관련된 코드(spinner, 다른 코어 켜기/끄기, sweep, timeline, 코어 순서 만들기)는
v1.1부터 v1.4까지 한 글자도 바뀌지 않았음(함수 단위로 비교해 확인). 버전 간 차이는 grid의
텔레메트리 지표 추가뿐임(7절).


3. 빌드와 실행
------------------------------------------------------------------------
  make                          # 네 버전 빌드
  sudo modprobe msr             # 프리페처 MSR을 쓸 때만 필요 (규칙 1 실험에는 불필요)
  sudo ./ini_probe_v1.4 help    # 명령과 옵션 목록
  sudo ./ini_probe_v1.4 info    # CPU, 캐시, PMU 확인

root가 필요함(perf_event_open으로 PMU 카운터를 읽기 때문).


4. 프로그램 구조 한눈에
------------------------------------------------------------------------
명령(첫 인자)마다 cmd_* 함수 하나가 실행됨. 규칙 1에 쓴 명령은 네 가지.

  probe     정해진 코어를 켠 상태에서 측정 코어의 모드를 몇 번 잼          (초기 s2, D)
  sweep     켜는 다른 코어 수를 0, 1, 2 … 로 바꾸며 단계마다 잼            (초기 s3, A)
  timeline  일정(schedule)대로 다른 코어를 켜고 끄며 짧은 창마다 기록      (C, F, G, J2, O3)
  grid      다른 코어 수 × 워크로드 목록 × 반복으로 잼, 지표도 함께 기록   (초기 s6, E, N)

모든 명령은 같은 순서로 동작함.
  (1) ctx_init: 측정 코어(probe)를 정하고, PMU 카운터 묶음을 열고, 워크로드 버퍼를 만들고,
      켤 다른 코어의 순서(order)를 만듦.
  (2) activate_set: 순서의 앞 n개 코어에 spinner를 돌리고 나머지는 재움.
  (3) 측정 코어에서 워크로드를 돌리며 카운터 차이를 읽어 sil_frac을 계산함.
  (4) 화면 출력(결과 txt가 됨)과 CSV 저장.


5. 핵심 아이디어
------------------------------------------------------------------------
[아이디어 1] 모드를 L2의 버리는 방식으로 읽음
  - INCL이면 L3에 사본이 있으니 깨끗한 라인을 L2에서 조용히 버림(SILENT).
    NI면 L3로 다시 써야 함(NON_SILENT).
  - P코어 PMU의 L2_LINES_OUT.SILENT / NON_SILENT를 세서
        sil_frac = SILENT / (SILENT + NON_SILENT)
    로 모드를 판정함. 0.7 이상 INCL, 0.3 이하 NI, 그 사이 MIXED.
  - 코드: silfrac() 함수, verdict_sil() 함수, 이벤트 표 EV_P_L2.

[아이디어 2] 측정 워크로드는 읽기만 하는 무작위 포인터 추적
  - 버퍼를 64바이트 라인으로 나누고, 무작위 순열(perm) 순서로 각 라인에 "다음 라인 주소"를
    적어 하나의 고리로 만듦. 만든 뒤 clflush로 캐시에서 비워 모든 라인을 깨끗한 상태로 둠.
  - 측정 중에는 주소를 따라 읽기만 하므로 수정된 라인이 생기지 않음. 그래서 버리는 방식이
    모드에만 달려 sil_frac이 모드를 그대로 보여 줌.
  - mlp = 동시에 따라가는 고리 위치 수, alu = 한 번 읽을 때마다 하는 의존 계산(곱셈·덧셈) 수,
    div = 나눗셈 수. 이 셋으로 메모리 부하를 조절함.
  - 버퍼는 2 MB huge page로 잡아 TLB 영향을 줄임.
  - 코드: wbuf_get() (고리 만들기), DEF_CHASE / chase() (따라가기), wl_parse() (워크로드 문자열 해석).

[아이디어 3] 다른 코어를 "켜고 끈다" = spinner 스레드를 깨우고 재움
  - 다른 코어마다 그 코어에 고정(affinity)된 spinner 스레드를 하나 둠.
  - 켜기: 상태를 SP_RUN으로 바꾸면 스레드가 루프를 계속 돌아 그 코어가 C0에 머묾.
  - 끄기: 상태를 SP_SLEEP으로 바꾸면 스레드가 조건 변수에서 잠들어, 코어가 HLT(C1)로 쉼.
  - 루프 종류(--spin): alu(기본, 계산만), pause, l2, llc, mem(메모리 읽기).
  - CPU offline 기능(--park)도 있지만 규칙 1 실험에서는 쓰지 않음.
  - 코드: spinner_t, spinner_main(), spinner_set(), activate_set().

[아이디어 4] 어떤 코어를 몇 개 켤지는 "순서 목록의 앞 n개"
  - build_order()가 측정 코어(와 helper)와 같은 코어를 빼고 순서 목록을 만듦.
      P       P코어 (cpu0, 2, 3, … 7)
      Epack   E코어를 클러스터별로 채움 (8, 9, 10, 11, 12, …)
      Espread E코어를 클러스터마다 하나씩 돌아가며 (8, 12, 16, 20, 9, …)
      PE      P코어 다음 E코어
  - activate_set(order, n)은 목록의 앞 n개만 켜고 나머지는 재움.
  - 이렇게 하면 "켠 코어 수"와 "켠 코어의 종류·배치"를 따로 바꿀 수 있음(실험 A).

[아이디어 5] sweep: 단계마다 기다렸다가 여러 번 재고 중앙값
  - 다른 코어 수 n마다: activate_set → settle(기본 300 ms) 기다림 → reps(기본 3)번 측정.
  - 한 번 측정 = warm(기본 20 ms) 돌린 뒤 meas(기본 30 ms) 동안 카운터 차이를 읽음.
  - --updown이면 0→최대→0으로 다시 내려옴. 마지막에 단계별 중앙값 summary를 찍음.
  - 코드: cmd_sweep(), i1_measure().

[아이디어 6] timeline: 워크로드를 창 길이만큼 잘라 돌리며 매 조각 뒤 카운터를 읽음
  - 시작 전에 20 ms 동안 워크로드 속도를 재서, 창 하나(--window, 예: 50 µs)에 해당하는
    조각 크기(chunk, 출력의 "steps")를 정함.
  - 루프: 현재 시각이 일정(--schedule "시각:코어 수,…")의 다음 시각을 넘으면 activate_set으로
    다른 코어 수를 바꿈 → 조각 하나 실행 → 카운터 차이를 읽어 창 기록(trec_t) 하나 저장.
  - 끝나면 CSV(t_ms, n_active, sil_frac …)를 쓰고 구간별 요약을 찍음.
      구간 중앙값: 구간 뒤쪽 70% 창들의 sil_frac 중앙값(앞 30%는 전환 중이라 뺌).
      전환 지연: 앞 구간과 중앙값이 0.3 이상 다르면, 구간 시작 뒤 sil_frac이 두 중앙값의
                 가운데를 3창 연속 넘은 첫 창의 시각 − 구간 시작 시각.
  - 그래서 1 ms보다 짧게 켠 구간은 중앙값이 거의 바뀌지 않음. 짧은 펄스의 전환은 CSV에서 봄.
  - schedule의 시각은 소수(200.1 등)도 됨 → 0.1 ms 펄스를 만들 수 있음(실험 G, O3).
  - 코드: cmd_timeline().

[아이디어 7] grid: 조건 조합을 한 번에 훑고 지표를 함께 기록
  - --nlist(다른 코어 수 목록) × --wlist(워크로드 목록) × --reps.
  - 기본 워크로드 목록은 l3 mlp1/4/16, l3 mlp8 alu64, dram mlp1/4/16, dram mlp8 seq의 8개
    (초기 s6이 이 기본값으로 돌았음).
  - 텔레메트리 묶음(stall, 큐 점유, 프리페치 요청 등)을 같이 읽어 CSV에 41개 열로 남김.
    규칙 1에는 n_req, sil_frac, verdict, pfx만 씀. 나머지는 규칙 2·3용.
  - 코드: cmd_grid().


6. 핵심 변수
------------------------------------------------------------------------
[설정: cfg_t C]  명령행 옵션이 들어가는 전역 구조체 (v1.4 220~240행)
  C.probe        측정 코어 번호 (-p). 결과에서는 대부분 cpu1, N은 cpu3·7, O3는 cpu5
  C.helper       xsnp용 보조 코어 (--helper). 초기 s2에서 cpu2
  C.workload     "l3" 또는 "dram" (-w)
  C.mlp, C.alu   기본 워크로드의 동시 체인 수(기본 8), 로드 사이 계산 수(기본 0)
  C.order        켤 코어 순서 이름 (--order: P, Epack, Espread, PE …, 기본 PE)
  C.nlist        켤 코어 수 목록 (--nlist, 예: "0,8,23")
  C.updown       sweep을 올라갔다 내려오기 (--updown)
  C.active       probe에서 켤 코어 목록 (--active, 실험 D는 0 = cpu0)
  C.spin         spinner 루프 종류 (--spin, 기본 alu)
  C.settle_ms    코어 수를 바꾼 뒤 기다리는 시간 (--settle, 기본 300 ms)
  C.warm_ms, C.meas_ms   측정 한 번의 예열·측정 시간 (기본 20 ms, 30 ms)
  C.reps         반복 수 (-r, 기본 3)
  C.window_us    timeline 창 길이 (--window, 기본 200 µs)
  C.schedule     timeline 일정 "시각(ms):코어 수,…" (--schedule)
  C.duration_ms  timeline 전체 시간 (--duration)
  C.wlist        grid 워크로드 목록 (--wlist)
  C.out          CSV 파일 이름 (-o)

[토폴로지: topo_t T]  sysfs에서 읽은 CPU 정보
  T.type[c]      'P' 또는 'E'
  T.core_key[c]  같은 물리 코어끼리 같은 값 (측정 코어와 같은 코어를 순서에서 뺄 때 씀)
  T.l2_key[c]    같은 L2를 쓰는 코어끼리 같은 값 (E코어 클러스터 구분)

[실행 문맥: ctx_t x]
  x.probe, x.helper     측정 코어, 보조 코어
  x.order[], x.norder   build_order()가 만든 켤 코어 순서와 개수
  x.wl[0], x.wl[1]      l3, dram 워크로드

[spinner: spinner_t g_sp[cpu]]
  cpu, kind     고정된 코어, 루프 종류
  state         SP_RUN(돌기) / SP_SLEEP(재움) / SP_EXIT(종료)
  mu, cv        재울 때 쓰는 뮤텍스와 조건 변수
  g_spin_kind   새 spinner의 루프 종류 (C.spin에서 정함)

[PMU 카운터]
  EV_P_L2       항상 같이 세는 4개: L2_LINES_IN.ALL(E_IN), L2_LINES_OUT.SILENT(E_SIL),
                L2_LINES_OUT.NON_SILENT(E_NSIL), L2_LINES_OUT.USELESS_HWPF(E_USELESS)
  EV_P_AUX      사이클, 명령 수, LLC 참조·miss
  EV_P_TEL1~4   grid 텔레메트리 (TEL3는 v1.2, TEL4는 v1.4에서 추가)
  g_g1, g_g0    열려 있는 EV_P_L2 묶음, EV_P_AUX 묶음

[측정 결과]
  i1_t          측정 한 번의 카운터 차이: fills, sil, nsil, useless, cyc, inst, … (+ 텔레메트리)
  point_t       sweep·probe 한 줄: n_req, act[], act_l2_mb(L2act), l3_l2_ratio(L3/L2), i1 …
  trec_t        timeline 창 하나: t_ms, n(켠 코어 수), fills, sil, nsil, useless, cyc, refc, inst

[timeline 내부]
  chunk         창 하나에 해당하는 워크로드 반복 수 (출력의 "steps")
  ev_t[], ev_n[]  schedule을 풀어 놓은 시각과 코어 수
  segmed[e]     구간 e의 sil_frac 중앙값
  tl            구간 시작 + 구간 길이 × 0.3 (중앙값 계산 시작점)
  lat           전환 지연 (출력의 latency)


7. 버전별 차이 (규칙 1과의 관계)
------------------------------------------------------------------------
  v1.1  sil_frac을 SILENT / (SILENT + NON_SILENT)로 정의 (v1.0은 SILENT / L2_LINES_IN).
        측정 줄에 silfrac, sil/fill, nsil/fill, evict/us를 찍음.
  v1.2  grid 텔레메트리에 TEL3(L1D·L2 miss로 멈춘 사이클 등) 추가. 줄에 l1dst, l2st.
  v1.3  grid 줄에 memany, occbusy, fill/cyc 추가 (규칙 3 탐색용).
  v1.4  TEL4(프리페치를 뺀 demand 요청만의 큐 점유) 추가. 줄에 pfx, dem, l1pend 추가.

  규칙 1에 쓰는 부분(spinner, activate_set, build_order, cmd_sweep, cmd_timeline,
  silfrac, verdict_sil)은 네 버전이 동일함.


8. 코드 위치 (함수 이름으로 검색하면 됨)
------------------------------------------------------------------------
  항목                         v1.1 행   v1.4 행
  silfrac()                     134       134
  cfg_t / cfg_defaults()        220~273   220~273
  DEF_CHASE / chase()           465~505   468~513
  wbuf_get() (고리 만들기)      576       584
  EV_P_L2 (L2 이벤트)           679       694
  spinner_t / spinner_main()    949~1029  978~1058
  spinner_set()                 1030      1059
  activate_set()                1061      1090
  i1_measure()                  1174      1205
  verdict_sil()                 1239      1295
  build_order()                 1510      1566
  ctx_init()                    1579      1635
  cmd_probe()                   1933      1989
  cmd_sweep()                   1975      2031
  cmd_timeline()                2040      2096
    구간 중앙값 (segmed)        2138      2194
    전환 지연 출력              2157      2213
  cmd_grid()                    2162      2218


9. 실험별 명령 (결과 파일의 머리줄로 재구성)
------------------------------------------------------------------------
초기 실험의 세 명령은 결과 파일에 그대로 찍혀 있음. 나머지는 머리줄(측정 코어, 워크로드,
창, 일정)에서 재구성한 것이라 원래 명령과 옵션 순서나 생략된 기본값이 다를 수 있음.

  초기 s2   sudo ./ini_probe probe -m pmu,ivt,xsnp -w l3 -r 3 -o s2_all3.csv        (원문)
  초기 s3   sudo ./ini_probe sweep --order PE --updown -r 3 -o s3_PE.csv           (원문)
  초기 s6   sudo ./ini_probe grid --nlist 0,8,23 -r 2 -o s6_grid.csv               (원문)
  A         sudo ./ini_probe sweep -p 1 --order P --updown -r 3 --alu 64 -o s10_P.csv
            (--order Epack, --order Espread로 같은 명령. --alu 64는 추정)
  C         sudo ./ini_probe timeline -p 1 --alu 64 --window 100 --duration 2500 \
                 --schedule "0:0,500:1,1000:0,1500:1,2000:0" -o s12_timeline.csv
  D         sudo ./ini_probe probe -p 1 -m pmu --active 0 --spin pause --alu 64 -r 3
            (--spin l2, llc, mem으로 반복)
  E         sudo ./ini_probe grid -p 1 --nlist 0,1,8 -r 2 \
                 --wlist "l3:mlp=8:alu=24,l3:mlp=8:alu=128,l3:mlp=8:alu=256,l3:mlp=8:alu=512,l3:mlp=8:alu=1024"
  F         sudo ./ini_probe timeline -p 1 --alu 64 --window 50 --duration 4100 \
                 --schedule "0:0,100:1,200:0,300:1, … ,3900:1,4000:0" -o s14_toggle.csv
  G         sudo ./ini_probe timeline -p 1 --alu 64 --window 50 --duration 1000 \
                 --schedule "0:0,200:1,200.1:0,400:1,400.3:0,600:1,601:0,800:1,803:0" -o s15_pulse.csv
  J2        sudo ./ini_probe timeline -p 1 --mlp 1 --alu 16 --window 200 --duration 1500 \
                 --schedule "0:0,500:1,1000:0" -o j2_m1_a16.csv      (워크로드 7종 반복)
  N         sudo ./ini_probe grid -p 3 --nlist 0,1 -r 3 --wlist "<워크로드 8종>" -o n1_cpu3.csv
            (-p 7로 반복)
  O3        sudo ./ini_probe timeline -p 5 --mlp 1 --alu 32 --window 100 --duration 1400 \
                 --schedule "0:0,200:1,200.3:0,400:1,400.4:0,600:1,600.5:0,800:1,800.6:0,1000:1,1000.7:0,1200:1,1200.8:0" \
                 -o o3_r1.csv                                        (3회 반복)
