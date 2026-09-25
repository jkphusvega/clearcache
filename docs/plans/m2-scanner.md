# M2 계획: 확보량 계산 core + 스캐너 + 드라이브 선택 + 진행률 + 결과 표

> **현재 상태 (2026-09-26): eng 리뷰 완료. 다음은 구현 승인.** 구현은 아직 시작하지 않았다.
> - 다음 세션: 이 계획으로 M2 구현 승인을 받은 뒤 아래 "Implementation Tasks" T1~T9를 진행한다(레인 A Rust core, 레인 B `src/lib` + Vitest).
> - 남은 할 일:
>   - 디자인 리뷰(/plan-design-review)는 M3 계획 때 한다(네 종류 카드 화면).
>   - 라이선스(현재 MIT 임시)는 M3 규칙 작성 전에 확정한다.
>   - 설계 문서의 Reviewer Concerns 중 M3 항목(R2-3, R2-4, R2-8, R2-14, R2-15)은 M3 계획에서 다룬다.
> - 리뷰 결정 D9~D17은 모두 아래 "Decision ledger"에 있다.

기준 문서: [SPEC.md](../../SPEC.md) v1.3, 승인된 설계 문서 [docs/designs/clearcache-reclaim-core.md](../designs/clearcache-reclaim-core.md)(접근 B)

## 완료 기준

- **사용자 폴더**(`%USERPROFILE%`, 기본 대상)를 스캔하면 1GB 이상 폴더가 트리 형태로 크기 순으로 나온다.
  - 걸린 시간을 기록한다.
  - 비공식 목표: 소유자 PC에서 두 번째 스캔(캐시가 데워진 상태)이 30초 이내다. 첫 스캔 시간과 파일 수도 함께 기록한다.
- **드라이브 전체**(고정·이동식)를 골라 스캔할 수 있다. 걸린 시간은 실측만 기록한다.
- 화면은 스캔 대상 **id만** Rust로 보낸다. 경로 문자열을 받는 커맨드는 없다.
- 폴더마다 `logical_bytes`가 나오고, 허용 목록 폴더는 `exclusive_bytes`·`shared_bytes`도 나온다.
- **테스트용 CLI** `cargo run --example scan -- --target <id> --json`이 Tauri와 같은 core 코드로 같은 결과를 낸다(`src-tauri/examples/scan.rs`, 설치 파일에 포함되지 않음, D10).
- 클라우드 전용 파일과 동기화 루트 안의 파일은 **한 번도 열리지 않는다**(단위 테스트로 보장).

## 범위

**이번에 하는 것**
- Rust `core` 모듈: targets, scan(walk, attrs, policy, progress), accounting(`exclusive_bytes`)
- 테스트용 CLI(`examples/scan.rs`, D10)
- 스캔 대상 목록(사용자 폴더 + 로컬 드라이브)
- 시스템 항목 매핑 중 **측정과 표시 부분**. 분류·안내 문구는 M3에서 한다.
- 동기화 루트를 감지해 해당 노드에 표시한다. 격리 차단은 M3·M4(SPEC S7)에서 한다.
- 진행률과 취소, 1GB 이상 트리 결과 표

**다음 단계로 미루는 것**
- M3: 등급·action 판정, 규칙 묶음, 규칙에 걸린 폴더에서 탐색 멈추기, 앱 연결, 선택 정책, 보호 검사(S2·S3·S9 등)
  - M2에는 선택 기능이 없다. `DirPolicy` 자리만 만든다.
- M3: 사용자가 체크하거나 펼칠 때 `exclusive_bytes`를 계산하는 것. M2는 허용 목록 폴더만 스캔 때 바로 계산한다.
- M4: 격리, 복원, 완전 삭제, 영수증, 안전 규칙 S1~S12 테스트
- 나중: 드라이브 밖의 임의 폴더를 고르는 창

## 구조

```
src-tauri/
  src/
    core/                 ← UI와 무관한 순수 로직 (CLI·Tauri 공용)
      mod.rs
      targets.rs          스캔 대상 목록, id → 경로
      scan/
        mod.rs            스캔 진입점, ScanResult 조립
        walk.rs           read_dir + rayon 병렬 순회
        attrs.rs          파일 속성 판별 (클라우드, 리파스)  ← 순수 함수
        policy.rs         DirPolicy: 시스템 항목 매핑, 격리함 제외
        syncroots.rs      동기화 루트 감지 (레지스트리·환경 변수)
        progress.rs       카운터 + 취소 플래그
      accounting.rs       exclusive_bytes (파일 ID·링크 수)
  examples/scan.rs         테스트용 CLI: cargo run --example scan -- --target <id> --json (D10)
    commands.rs           Tauri 커맨드 (core 호출만)
    lib.rs                상태·커맨드 등록
```

## 스캔 대상 (드라이브 선택)

- 커맨드 `list_scan_targets() -> Vec<ScanTarget>`
  - `ScanTarget { id, kind: "user_home" | "drive", label, root_display, fs, total_bytes, free_bytes, removable }`
  - id 예시: `user_home`, `drive:C`, `drive:D`
- 드라이브 목록 규칙:
  - `GetLogicalDrives`로 드라이브를 찾고 `GetDriveTypeW`로 종류를 가른다. **고정(FIXED)과 이동식(REMOVABLE)만** 넣는다.
  - `GetVolumeInformationW`에 실패하는 드라이브는 뺀다.
  - `QueryDosDeviceW` 결과가 `\??\`로 시작하는 `subst` 가상 드라이브는 뺀다.
  - 용량 바는 `GetDiskFreeSpaceExW`로 채운다.
- 커맨드 `start_scan(target_id, on_progress: Channel) -> ScanSummary`
  - Rust가 **대상 목록을 다시 조회해서** id를 경로로 바꾼다. 목록에 없는 id는 거부한다.
  - 한 번에 스캔 하나만 돈다.
- 커맨드 `cancel_scan()`, `get_scan_result() -> ScanResult`
- 기본 선택은 `user_home`이다.

## 스캐너 설계

- **순회: `std::fs::read_dir` + `rayon` 병렬 재귀.** Windows에서 `DirEntry::metadata()`는 목록 정보를 쓰므로 **파일을 열지 않는다.** 루트의 `pagefile.sys`, `hiberfil.sys` 같은 파일도 목록 정보로 크기를 얻는다.
- **깊이 대응**(D12): rayon 전용 스레드 풀의 스택을 8 MiB로 잡는다. 깊이 512를 넘는 폴더는 들어가지 않고 `skipped`(이유: "너무 깊음")에 기록한다.
- **파일 속성 처리** (`attrs.rs`, 순수 함수)
  - 이름 대리 리파스 포인트(정션, 심볼릭 링크, 마운트 지점)는 들어가지 않고 크기도 세지 않는다. 노드에 `is_link`로 표시한다.
  - 클라우드 전용(`RECALL_ON_DATA_ACCESS 0x400000`, `RECALL_ON_OPEN 0x40000`, `OFFLINE 0x1000`)은 크기 0으로 세고 `cloud_only_files`에 개수를 더한다. **어떤 경로에서도 열지 않는다.**
  - OneDrive 폴더 자체는 클라우드 리파스 태그를 가진 일반 폴더라서 들어간다.
- **동기화 루트** (`syncroots.rs`)
  - 스캔 시작 때 한 번 수집한다. 소스는 다음과 같다.
    - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\*` 값 중 사용자 폴더 경로
    - `HKCU\Software\Microsoft\OneDrive\Accounts\*\UserFolder`
    - 환경 변수 `%OneDrive%`, `%OneDriveConsumer%`, `%OneDriveCommercial%`
  - 루트 안의 노드는 `in_sync_root: true`로 표시하고, accounting 허용 목록에서 제외한다.
  - **감지 실패 처리**(D14): 소스별 결과(찾은 루트 수, 오류)를 `ScanSummary.sync_root_detection`과 scan.log에 기록한다. 하나라도 실패하면 화면 하단에 "동기화 폴더 감지 일부 실패" 경고를 띄운다. 모든 소스가 실패하면 사용자 폴더 안의 accounting을 건너뛰고 확보량 칸을 "미검증"으로 둔다. 레지스트리·환경 변수 읽기는 트레이트로 주입한다.
- **시스템 항목 매핑** (`policy.rs`, 드라이브 전체 스캔에서만)

| 항목 | M2 동작 |
| --- | --- |
| `Program Files`, `Program Files (x86)` | 전체 순회(`tag=system_apps`). `WindowsApps`는 접근 거부로 건너뜀 |
| `Windows` | **들어가되 알려진 하위 폴더만 측정**: `WinSxS`, `SoftwareDistribution\Download`, `Installer`, `Temp`, `Minidump`, `LiveKernelReports`. 나머지 하위는 `Unmeasured`("기타 Windows"). `Minidump`·`LiveKernelReports`는 관리자 없이 보통 읽기 불가라 "건너뜀"이 예상된다(D16) |
| `C:\Windows.old` | 순회하고 접근 가능한 만큼만 측정 |
| 루트 파일 `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `C:\Windows\MEMORY.DMP` | 목록 정보 크기로 노드 생성 |
| `ProgramData`, `System Volume Information`, `$Recycle.Bin`, `Recovery`, `$WinREAgent`, `PerfLogs` | `Unmeasured`(M2) |

  - 위 항목과 그 하위는 모두 `tag=system` 계열이고 **보호 대상**이다. 선택을 막는 것은 M3에서 한다.
- **`DirPolicy`**: `Descend` / `Unmeasured { tag }` / `Skip` / `MeasureChildrenOnly { allow: [...] }`. M3에서 규칙 매칭이 여기에 끼어든다.
- **확보량 계산** (`accounting.rs`)
  - **정의**: 범위는 해당 폴더와 그 하위 전체다. 파일의 디스크상 크기는 "범위 안에서 본 링크 수 == `nNumberOfLinks`"일 때만 한 번 센다. 그렇지 않으면 `shared_bytes`에 더한다.
  - **허용 목록**(M2): `Windows\WinSxS`, uv 캐시(`%LOCALAPPDATA%\uv\cache`), pnpm 저장소(`%LOCALAPPDATA%\pnpm\store` 등 알려진 위치), 그리고 그 하위의 1GB 이상 노드
  - **파일 여는 방식**:
    - `CreateFileW(access=FILE_READ_ATTRIBUTES, share=READ|WRITE|DELETE, flags=OPEN_REPARSE_POINT|BACKUP_SEMANTICS)` 후 `GetFileInformationByHandle`로 볼륨 번호, 파일 인덱스, 링크 수를 얻는다.
    - 디스크상 크기와 크기는 **같은 핸들**에서 `GetFileInformationByHandleEx`(FileStandardInfo: EndOfFile·AllocationSize, FileCompressionInfo)로 읽는다. 파일당 열기는 한 번뿐이다. 허용 목록 파일의 logical도 이 값을 쓴다(하드링크 파일의 디렉터리 항목 크기가 옛날 값일 수 있기 때문, D11).
    - 속성상 클라우드 전용이거나 동기화 루트 안이면 **여는 함수를 호출하기 전에** 건너뛴다.
  - **열기 실패**(공유 위반, 접근 거부): 그 파일은 logical 크기로 세고 `unverified_files`에 더한다.
  - **WinSxS 표시**: "Windows와 공유되지 않는 파일 N GB (전부 확보 가능한 것은 아님)"라는 중립 라벨을 쓴다.
- **폴더 요약** `DirAgg { logical_bytes, files, latest_mtime, ext_bytes, children }`
  - `children`에는 기준 크기(1 GiB) 이상만 남긴다. 시스템 항목 노드는 기준과 관계없이 남긴다.
  - 확장자 맵은 상위 32개만 남긴다.
- **건너뛰기**: 접근 거부나 읽기 오류는 `skipped`에 경로와 이유를 담는다. 다른 사용자 프로필, `WindowsApps`가 여기에 해당한다. 격리함(`C:\ClearCache_Quarantine`)은 탐색하지 않는다.
- **두 단계 표시**(D13): 순회가 끝나면 결과를 바로 반환·표시한다. 확보량 칸은 "계산 중"으로 두고, accounting 결과는 `Channel`로 노드별(`AccountingUpdate { node_id, exclusive_bytes, shared_bytes, unverified_files }`)로 채운다. 30초 목표는 **순회 단계**로 재고, `accounting_ms`는 따로 기록한다. accounting만 취소되면 순회 결과는 남고 확보량 칸은 "취소됨"이 된다.
  - M3·M4 규칙: 확보량이 "계산 중"이거나 계산이 취소된 폴더는 선택·격리할 수 없고, 예상 확보량 합계에도 넣지 않는다(D13).
- **진행률**: `AtomicU64` 카운터와 `Mutex<String>`을 두고, 200ms마다 `Channel`로 `ScanProgress { files, bytes, current, elapsed_ms, phase: "walk" | "accounting" }`를 보낸다.
- **취소**: `AtomicBool`을 폴더마다, 그리고 accounting 파일 1000개마다 확인한다.
- **결과**
  - `FlatNode { id, parent_id, path, name, logical_bytes: Option<u64>, files: Option<u64>, exclusive_bytes: Option<u64>, shared_bytes: Option<u64>, unverified_files: u32, partial: bool, skipped_descendants: u32, top_exts, last_modified, tag, is_link, in_sync_root, read_only_volume }`
  - `partial`·`skipped_descendants`: 하위에서 읽지 못한 폴더가 있으면 위로 전파한다. 화면 크기 칸에 "일부만 측정 (N개 폴더 읽기 불가)"을 표시한다(D16).
  - `ScanSummary { root_display, total_logical_bytes, files, elapsed_ms, accounting_ms, skipped_count, cloud_only_files, drive_used_bytes?, unaccounted_bytes?, sync_root_detection }`
  - `unaccounted_bytes = max(0, drive_used_bytes − total_logical_bytes)`이고 화면에는 "약 N GB (근사치)"로 표시한다. 툴팁은 포함 항목(측정 안 한 시스템 폴더, 접근 거부, 루트 시스템 파일)과 하드링크 중복 집계로 실제보다 작게 보일 수 있다는 점을 설명한다(D15).
- **로그**: 스캔마다 `%LOCALAPPDATA%\ClearCache\logs\scan.log`에 한 줄을 남긴다.

## 화면 (`src/`)

- **상단**: 대상 드롭다운 + 스캔/취소 버튼 + 진행률 줄. accounting 단계일 때는 "확보량 계산 중"으로 표시한다.
- **표**: 트리 형태이고, 같은 층에서는 크기 내림차순이다.
  - 열: 체크박스(비활성), 이름, 경로, 크기, 확장자 상위 5개, 수정일, 등급/근거/출처(M3 전까지 "—")
  - 크기 칸:
    - exclusive가 있으면 "실제 확보 N GB (공유 M GB)"
    - 없으면 logical을 "최대치(미검증)"로 표시
    - 시스템 항목은 "차지하는 크기"로 표시
  - 시스템 항목: 잠금 아이콘을 붙인다. "기타 Windows"는 크기 "—"에 툴팁 "측정하지 않음. '스캔되지 않은 용량'에 포함"을 단다.
  - 링크 노드는 링크 아이콘을 붙이고, 동기화 루트 안의 노드는 구름 아이콘을 붙인다.
  - C: 이외 드라이브는 "보기 전용" 배지를 단다.
- **하단 요약**: 대상, 합계, 걸린 시간, 건너뜀 수, 제외한 클라우드 파일 수. 드라이브 스캔이면 "스캔되지 않은 용량"도 표시한다.

## 파일

- `src-tauri/Cargo.toml`: `rayon`, `windows`(`Win32_Storage_FileSystem`, `Win32_System_Registry`, `Win32_Foundation`), `serde_json`, `tempfile`(dev). 두 번째 `[[bin]]`은 두지 않는다(D10)
- `src-tauri/src/core/**`, `src-tauri/examples/scan.rs`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`
- `src/App.tsx`, `src/components/{TargetPicker,ProgressBar,FolderTree,Summary}.tsx`, `src/types.ts`
- `src/lib/{format,sizeLabel,sortTree}.ts`와 각각의 `*.test.ts`(D17). `package.json`: devDependency `vitest`, 스크립트 `"test": "vitest run"`
- `LICENSE`(MIT, 임시)

## 라이선스

- MIT로 임시 결정했다. BleachBit(GPL) 규칙은 참고만 하고 복사하지 않는다. 규칙은 직접 작성하고, 출처는 문서 링크로만 남긴다.
- M3에서 규칙을 쓰기 전에 최종 확정한다.

## 테스트

SPEC 규칙에 따라 픽스처는 `C:\ClearCache_TestZone\scan-tests\<무작위>`에만 만들고, 테스트가 끝나면 지운다.

- 크기 합산, 파일 수, 최근 수정일
- 기준 크기로 걸러내기(테스트 기준 1 KiB), 부모·자식 관계, 같은 층 크기 내림차순
- 정션(`cmd /c mklink /J`)을 따라가지 않고 크기에도 넣지 않는지
- 확장자 상위 5개 합산
- 취소하면 `cancelled`가 되는지(순회 중, accounting 중 모두)
- 두 단계: 순회 결과가 accounting보다 먼저 반환되는지, accounting 갱신이 노드 id로 맞게 채워지는지, accounting만 취소했을 때 순회 결과가 남는지(D13)
- 깊이 600 픽스처: 크래시 없이 끝나고, 512를 넘는 부분이 `skipped`("너무 깊음")로 기록되는지(D12)
- `attrs.rs` 클라우드 속성 판별: 세 속성 각각과 조합이 "열지 않음"으로 판정되는지
- **accounting이 클라우드 파일을 열지 않음**: 여는 함수를 트레이트로 주입하고, 클라우드 속성 파일과 동기화 루트 안의 파일에 대해 호출이 0회인지 확인한다.
- **동기화 루트 제외**: 가짜 동기화 루트를 주입하면 그 안의 노드가 `in_sync_root`가 되고 accounting 대상에서 빠지는지
- **동기화 루트 감지 실패**(D14): 소스 하나가 실패하면 경고 플래그가 서는지, 전부 실패하면 사용자 폴더 accounting이 호출 0회이고 "미검증"인지(주입 테스트)
- `partial` 전파: 읽기 거부 폴더를 흉내 낸 주입 테스트에서 조상 노드마다 `partial`과 `skipped_descendants`가 맞게 올라가는지(D16)
- `unaccounted_bytes`: 합계가 사용량보다 크면 0이 되는지(D15)
- **하드링크**: `std::fs::hard_link`로 만든 파일이 두 가지 경우에 맞게 계산되는지
  - 범위 안에 링크가 모두 있음 → exclusive에 한 번만 센다
  - 범위 밖에 링크가 있음 → shared로 센다
- `policy.rs`: 시스템 항목 매핑(가짜 드라이브 루트 픽스처), 대소문자, `%SystemRoot%`가 C:가 아닐 때
- `targets.rs`: 목록에 없는 id를 거부하는지, 드라이브 종류로 거르는지(순수 함수)
- CLI: 픽스처를 스캔한 JSON이 Tauri 커맨드 결과와 같은 구조인지
- (리뷰에서 추가, 승인된 동작의 증명) accounting 열기 실패 주입: 공유 위반·접근 거부 시 그 파일은 logical 크기로 세고 `unverified_files`가 늘어나는지
- (리뷰에서 추가) 진행률: 주입한 sink로 주기 이벤트와 종료 시 최종 이벤트가 나오는지
- (리뷰에서 추가) 스캔 중 두 번째 `start_scan`이 거부되는지
- **화면 로직 (Vitest, D17)**: `sizeLabel`은 실제 확보·최대치(미검증)·차지하는 크기·계산 중·취소됨·일부만 측정의 여섯 경우를 판정한다. `format`은 바이트를 표기한다(0, 1023, 1 KiB, GiB 경계). `sortTree`는 같은 층 크기 내림차순, 크기 없는 시스템 행, 동률일 때 이름순을 처리한다.
- **크기 출처 검증**(D11): 소유자 PC의 `C:\Windows\WinSxS` 파일 100개 샘플에서 핸들 기반 크기와 `GetCompressedFileSizeW` 값을 비교하는 무시(ignored) 테스트. 읽기만 하고, `cargo test -- --ignored`로 수동 실행한다. 차이가 있으면 결과를 보고하고 방식을 확정한다.

## 검증

1. `cargo test`, `cargo clippy`, `npm test`(Vitest), `npm run build`
2. CLI로 사용자 폴더를 스캔한다(첫 스캔과 두 번째 스캔 시간 기록).
3. `npm run tauri dev`로 사용자 폴더와 C: 전체를 스캔하고 화면을 확인한다.
4. The Assignment(설계 문서) 값과 비교한다: uv·pnpm·HF·Ollama·WinSxS의 탐색기 크기와 디스크 할당 크기, DISM 분석값을 `logical`·`exclusive`와 비교해 보고한다.
5. 스크린샷은 사용자에게 확인을 부탁한다. 끝나면 커밋하고 push할지 묻는다.

## 결정 이력

- 2026-09-25: C:만 격리하고 다른 드라이브는 보기 전용으로 한다(유지).
- 2026-09-25: 시스템 폴더는 들어가지 않고 "측정 안 함"으로 표시하기로 했으나, 2026-09-26 설계 문서 접근 B(D7)로 **대체**했다. 이제는 알려진 하위 폴더를 측정하고 Program Files는 전체를 측정한다.
- 2026-09-26: 접근 B(core + CLI + exclusive_bytes), 클라우드 파일 미개봉과 동기화 루트 제외, MIT 임시 라이선스를 정했다(D7).

## Decision ledger

### Scope record (Scope Challenge B)
feature answers: 제안한 기능 삭제·연기 없음 (D7에서 승인한 기능 목록 유지); structure: A) Original arrangement (D9); accepted scope: 이 계획의 "구조"·"범위" 절 그대로; pending remedies: F1, F2, F3

### R1: F1 — CLI 바이너리 패키징
Finding: F1, P1, confidence 8/10, docs/plans/m2-scanner.md "파일" 절 `[[bin]] clearcache-cli`, reviewer: Claude (plan-eng-review Scope Challenge)
Plan baseline: src-tauri 크레이트 안에 두 번째 `[[bin]]`으로 clearcache-cli를 둔다 (D7 승인 범위, 형태는 미정)
Runtime evidence: 아직 코드 없음. 외부 보고: 여러 bin이면 `tauri dev`가 default-run 없이 실패(tauri discussions #7592, idle-app PR #15), WiX 빌드 실패 보고(tauri #4807). unknown: 현재 Tauri 2 버전에서 WiX 문제 재현 여부
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1 CLI 형태 | src-tauri `[[bin]]` (미해결 위험) | `src-tauri/examples/scan.rs` (`cargo run --example scan -- --target ... --json`), 설치 파일·tauri dev에 영향 없음 | Cargo 워크스페이스: `crates/clearcache-core`(lib) + `crates/clearcache-cli` + src-tauri가 core에 의존 | src-tauri `[[bin]]` 유지 + `default-run = "clearcache"` + 번들 제외 설정 확인 |
| CLI·Tauri가 같은 core 코드 사용 (D7 승인) | 승인됨 | 유지 | 유지 | 유지 |
Question D10:
D10 — 테스트용 CLI를 어떤 형태로 둘까요?
Project/branch/task: ClearCache main, M2 계획 F1(CLI 바이너리 패키징).
ELI10: CLI는 스캐너 숫자를 WizTree와 비교하려고 만드는 개발용 도구입니다. 지금 계획처럼 앱과 같은 크레이트에 두 번째 실행 파일로 넣으면, `npm run tauri dev`가 어느 실행 파일을 띄울지 몰라 실패하고, 설치 파일(MSI) 빌드가 깨졌다는 보고도 있습니다. examples로 두면 이 문제가 아예 생기지 않습니다.
Stakes if we pick wrong: C를 고르고 설정을 놓치면 tauri dev가 안 뜨거나 M6에서 설치 파일 빌드가 깨지고, B는 지금 구조 변경 비용이 큽니다.
Recommendation: A because 개발용 도구라 설치 파일에 들어갈 이유가 없고, examples는 tauri dev·MSI 빌드에 전혀 영향을 주지 않으면서 같은 core 코드를 씁니다.
Completeness: A=9/10, B=10/10, C=7/10
Net: 가장 작은 변경으로 위험을 없앨지(A), 경계를 가장 깔끔하게 할지(B), 지금 계획을 설정으로 버틸지(C)의 선택입니다.
Header: CLI 형태
Options:
A) examples로 두기 (recommended)
`src-tauri/examples/scan.rs`. `cargo run --example scan`으로 실행. tauri dev·MSI 빌드에 영향 없음. core는 라이브러리 크레이트에서 pub으로 노출. human ~30분 / CC ~5분.
B) 워크스페이스 분리
`crates/clearcache-core` + `crates/clearcache-cli` + src-tauri 의존. 경계가 가장 깔끔하지만 Cargo 구조 변경과 경로 설정이 늘어남. human ~3시간 / CC ~20분.
C) [[bin]] 유지 + default-run
src-tauri에 두 번째 bin, `default-run` 설정, MSI에 CLI가 들어가지 않는지 M2에서 확인. human ~1시간 / CC ~10분.
State: approved
Actual answer: A) examples로 두기 (recommended) — D10 사용자 답변
Accepted scope: CLI를 `src-tauri/examples/scan.rs`로 둔다. `cargo run --example scan -- --target <id> --json`. src-tauri에 두 번째 `[[bin]]`을 두지 않는다. core는 라이브러리 크레이트(`clearcache_lib`)에서 pub으로 노출한다. 계획의 완료 기준·범위·구조·파일 절을 이에 맞춰 고쳤다.
History: —

### R2: F2 — accounting의 파일 크기 출처 (설계 리뷰 R2-5 포함)
Finding: F2, P2, confidence 6/10, docs/plans/m2-scanner.md "확보량 계산" 절 "디스크상 크기는 `GetCompressedFileSizeW`로 잰다", reviewer: Claude (Scope Challenge) + 설계 문서 spec review R2-5
Plan baseline: 핸들로 파일 ID·링크 수를 얻고, 디스크상 크기는 경로 기반 `GetCompressedFileSizeW`로 따로 잰다 (D7 승인안의 세부 구현, 미확정)
Runtime evidence: 코드 없음. 문서상: 경로 기반 호출은 자체적으로 파일을 다시 열어 계획한 열기 플래그를 우회하고 열기 횟수가 두 배. NTFS는 하드링크 파일의 디렉터리 항목 크기를 파일을 열 때만 갱신할 수 있음(MS Learn "Backing Up and Restoring Hard Links", s-schoener 블로그). unknown: WOF(CompactOS) 압축 파일을 OPEN_REPARSE_POINT로 열었을 때 핸들 기반 크기 값
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R2 크기 출처 | 경로 기반 GetCompressedFileSizeW (추가 열기) | 같은 핸들: `GetFileInformationByHandleEx`(FileStandardInfo: EndOfFile·AllocationSize, FileCompressionInfo). 허용 목록 파일의 logical도 핸들 값 사용. M2에서 WinSxS 샘플로 GetCompressedFileSizeW와 비교 검증, 실패 시 logical+미검증 | 경로 기반 유지. 링크·클라우드·동기화 루트 판정 뒤에만 호출하고 동작·실패 처리를 문서화 |
| 클라우드·동기화 루트 파일 미개봉 (D7 승인) | 승인됨 | 유지 | 유지 |
| 열기 실패 시 logical + 미검증 (설계 문서) | 승인됨 | 유지 | 유지 |
Question D11:
D11 — 확보량 계산에서 파일 크기를 어디서 읽을까요?
Project/branch/task: ClearCache main, M2 계획 F2(설계 리뷰 R2-5 포함).
ELI10: 하드링크를 가려내려고 파일마다 '속성만 읽기' 모드로 한 번 엽니다. 지금 계획은 거기서 끝내지 않고 압축 크기를 재려고 파일 경로로 한 번 더 여는데, 이 두 번째 열기는 우리가 정한 안전한 열기 방식을 따르지 않고 시간도 두 배 듭니다. 또 하드링크 파일은 폴더 목록에 적힌 크기가 옛날 값일 수 있습니다. A는 이미 연 핸들에서 크기까지 한 번에 읽습니다.
Stakes if we pick wrong: B를 고르면 WinSxS·uv 캐시 같은 수십만 개 파일에서 스캔이 느려지고, 열기 방식이 두 갈래가 돼 release gate에서 설명할 경로가 늘어납니다.
Recommendation: A because 열기를 한 번으로 줄여 속도와 안전 약속(정한 플래그로만 연다)을 함께 지키고, 하드링크 파일의 옛날 크기 문제도 같이 풀립니다.
Completeness: A=9/10, B=6/10
Net: 한 번 열어 다 읽을지(A), 구현이 조금 더 단순한 두 번 열기를 유지할지(B)의 선택입니다.
Header: 크기 출처
Options:
A) 같은 핸들에서 읽기 (recommended)
`GetFileInformationByHandleEx`(FileStandardInfo, FileCompressionInfo)로 크기를 얻고, 허용 목록 파일은 logical도 이 값을 씀. M2에서 WinSxS 샘플 100개로 `GetCompressedFileSizeW`와 비교하는 테스트를 추가하고, 다르면 결과를 보고한 뒤 방식 확정. human ~3시간 / CC ~20분.
B) 경로 기반 유지
`GetCompressedFileSizeW`를 그대로 쓰되 링크·클라우드·동기화 루트 판정 뒤에만 호출하고, 실패 시 logical+미검증으로 처리한다고 계획에 명시. human ~1시간 / CC ~5분.
State: approved
Actual answer: A) 같은 핸들에서 읽기 (recommended) — D11 사용자 답변
Accepted scope: 크기와 디스크상 크기를 파일 ID와 같은 핸들에서 `GetFileInformationByHandleEx`(FileStandardInfo, FileCompressionInfo)로 읽는다. 허용 목록 파일의 logical도 핸들 값을 쓴다. 경로 기반 `GetCompressedFileSizeW`는 쓰지 않는다. WinSxS 샘플 100개 비교 테스트(ignored, 읽기만)를 추가하고, 차이가 나면 보고한 뒤 확정한다. 계획의 "확보량 계산"과 "테스트" 절을 고쳤다.
History: —

### R3: F3 — 깊은 폴더에서의 재귀 스택
Finding: F3, P2, confidence 6/10, docs/plans/m2-scanner.md "스캐너 설계" 절 "순회: `std::fs::read_dir` + `rayon` 병렬 재귀", reviewer: Claude (Scope Challenge)
Plan baseline: rayon으로 폴더마다 재귀 호출 (깊이 제한·스택 크기 미정)
Runtime evidence: 코드 없음. 알려진 사례: 깊은 폴더 구조에서 재귀 순회가 스택 오버플로를 일으킴(Rust 포럼, ripgrep #1178). Windows 긴 경로(최대 약 32,767자)에서는 이론상 수천 단계 깊이가 가능. unknown: 실제 PC의 최대 깊이
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R3 깊이 대응 | 없음 | rayon 스레드 풀 스택 8 MiB + 깊이 512 초과 폴더는 `skipped`(이유: "너무 깊음")로 기록 | 재귀 대신 명시적 작업 큐(스택 없음) | 그대로 둠 |
| 테스트 | 없음 | 깊이 600 픽스처에서 크래시 없이 `skipped`에 기록되는지 | 깊이 600 픽스처에서 전체가 측정되는지 | 없음 |
Question D12:
D12 — 아주 깊은 폴더 구조에서 스캐너가 멈추지 않게 할까요?
Project/branch/task: ClearCache main, M2 계획 F3(재귀 순회의 스택 한계).
ELI10: 스캐너는 폴더 안의 폴더로 계속 들어가며 함수를 겹겹이 부릅니다. 폴더가 수백 단계로 깊으면(잘못 만든 복사본, 옛 npm node_modules) 이 겹이 쌓여 앱이 통째로 꺼질 수 있습니다. A는 쌓을 공간을 넉넉히 주고 너무 깊으면 건너뛰며 기록합니다.
Stakes if we pick wrong: 아무것도 안 하면 드물게 스캔 중 앱이 경고 없이 꺼지고, 사용자는 이유를 알 수 없습니다.
Recommendation: A because 코드 몇 줄로 크래시를 없애고, 건너뛴 사실을 기존 '건너뜀' 목록에 남겨 정직함도 지킵니다.
Completeness: A=9/10, B=10/10, C=3/10
Net: 몇 줄로 막을지(A), 구조를 바꿔 근본적으로 없앨지(B), 드문 일로 보고 둘지(C)의 선택입니다.
Header: 깊이 대응
Options:
A) 스택 확대 + 깊이 제한 (recommended)
rayon 스레드 스택 8 MiB, 깊이 512 초과는 `skipped`("너무 깊음")로 기록, 깊이 600 픽스처 테스트. human ~1시간 / CC ~5분.
B) 작업 큐 방식
재귀 대신 명시적 큐로 순회해 깊이 제한 없이 전부 측정. 부모 합산 로직이 복잡해짐. human ~1일 / CC ~40분.
C) 그대로 둠
드문 경우로 보고 M2에서는 대응하지 않음. human 0 / CC 0.
State: approved
Actual answer: A) 스택 확대 + 깊이 제한 (recommended) — D12 사용자 답변
Accepted scope: rayon 전용 스레드 풀 스택 8 MiB, 깊이 512 초과 폴더는 들어가지 않고 `skipped`("너무 깊음")로 기록, 깊이 600 픽스처 테스트. 계획의 "스캐너 설계"와 "테스트" 절을 고쳤다.
History: —

### R4: A1 — 스캔 결과 표시와 확보량 계산의 순서
Finding: A1, P1, confidence 7/10, docs/plans/m2-scanner.md "진행률" 절 `phase: "walk" | "accounting"`, reviewer: Claude (Section 1 Architecture)
Plan baseline: 순회와 확보량 계산을 한 스캔 안에서 하고, 진행률에 phase만 표시한다. 결과 표시 시점과 30초 목표의 측정 구간은 미정.
Runtime evidence: 코드 없음. uv·pnpm 캐시는 수만~수십만 파일이고 파일마다 열기가 필요(D11). unknown: 소유자 PC의 실제 accounting 시간
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R4 표시 순서 | 미정 | 두 단계: 순회 결과를 먼저 반환·표시(확보량 칸은 "계산 중"), accounting 결과는 Channel로 노드별로 채움. 30초 목표는 순회 단계로 측정, `accounting_ms` 따로 기록 | 한 단계: accounting까지 끝난 뒤 결과를 한 번에 표시. 30초 목표는 전체로 측정 |
| 취소 (계획) | 순회·accounting 모두 | 유지 (accounting만 취소되면 순회 결과는 남고 확보량 칸은 "취소됨") | 유지 (전체 취소) |
Question D13:
D13 — 스캔 결과를 확보량 계산이 끝나기 전에 먼저 보여줄까요?
Project/branch/task: ClearCache main, M2 계획 A1(결과 표시 순서와 30초 목표).
ELI10: 스캔은 두 일을 합니다. 폴더 크기를 훑는 일(빠름)과, uv·pnpm·WinSxS에서 하드링크를 가려 실제 확보량을 계산하는 일(파일마다 열어서 느림)입니다. A는 크기 표를 먼저 띄우고 확보량 칸을 나중에 채웁니다. B는 둘 다 끝날 때까지 기다렸다 한 번에 보여줍니다.
Stakes if we pick wrong: B를 고르면 캐시가 큰 PC에서 30초 목표를 넘기고 그동안 화면이 비어 있어, '빠르고 쉬운' 제품 핵심이 흐려집니다.
Recommendation: A because 사용자는 몇 초 안에 큰 폴더를 보고, 느린 확보량 계산은 그 위에 채워지며, 30초 목표도 사용자가 실제로 기다리는 구간을 잽니다.
Completeness: A=9/10, B=7/10
Net: 빨리 보여주고 나중에 채울지(A), 조금 늦더라도 완성된 표를 한 번에 보여줄지(B)의 선택입니다.
Header: 표시 순서
Options:
A) 두 단계 표시 (recommended)
순회 결과를 먼저 표시하고 확보량 칸은 "계산 중"→값으로 채움. 30초 목표는 순회 단계 기준, accounting_ms 별도 기록. accounting만 취소되면 순회 결과는 유지. human ~4시간 / CC ~25분.
B) 한 번에 표시
accounting까지 끝난 뒤 결과를 한 번에 표시. 30초 목표는 전체 기준. human ~2시간 / CC ~10분.
State: approved
Actual answer: A) 두 단계 표시 + 추가 조건 — D13 사용자 답변: "A로 하자. 다만 M3·M4용 규칙으로 하나 적어줘: 확보량이 "계산 중"이거나 취소된 폴더는 선택·격리할 수 없고, 예상 확보량 합계에도 넣지 않는다. 설계 문서와 M4 계획에 반영."
Accepted scope: 순회 결과를 먼저 표시하고, 확보량은 Channel로 노드별로 채운다. 30초 목표는 순회 단계로 측정하고 accounting_ms를 따로 기록한다. accounting만 취소돼도 순회 결과는 유지한다. 두 단계 테스트를 추가한다. 추가 규칙은 계획 "스캐너 설계"에 적고, 설계 문서의 "판정 모델"·"격리와 영수증"과 SPEC.md "4. 메인 화면"·M4 완료 조건에 반영했다(M4 계획 문서는 아직 없으므로 SPEC의 M4 완료 조건이 그 역할을 한다).
History: —

### R5: A2 — 동기화 루트 감지 실패 처리
Finding: A2, P2, confidence 7/10, docs/plans/m2-scanner.md "동기화 루트 (`syncroots.rs`)" 절, reviewer: Claude (Section 1 Architecture)
Plan baseline: 스캔 시작 때 레지스트리 3곳과 환경 변수로 동기화 루트를 한 번 수집한다. 수집 실패 처리는 없음.
Runtime evidence: 코드 없음. 클라우드 속성 판별(attrs)은 감지와 무관하게 동작하므로 "클라우드 전용 파일 미개봉"은 유지됨. 감지가 실패하면 약해지는 것은 "동기화 루트 안의 수화된(로컬에 있는) 파일은 열지 않음"과 이후 S7 격리 차단. unknown: SyncRootManager 키를 비관리자가 읽을 수 있는지
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R5 감지 실패 처리 | 없음(조용히 실패 가능) | 소스별 결과(찾은 루트 수·오류)를 ScanSummary와 scan.log에 기록. 하나라도 실패하면 화면 하단에 "동기화 폴더 감지 일부 실패" 경고. 모든 소스가 실패하면 사용자 폴더 안의 accounting을 건너뛰고(보수적) 확보량 칸을 "미검증"으로 표시. 레지스트리 읽기를 트레이트로 주입해 실패 테스트 | 그대로 둠 |
| 클라우드 속성 파일 미개봉 (D7) | 승인됨 | 유지 | 유지 |
Question D14:
D14 — 동기화 폴더(OneDrive 등) 감지가 실패하면 어떻게 할까요?
Project/branch/task: ClearCache main, M2 계획 A2(동기화 루트 감지 실패).
ELI10: 스캐너는 OneDrive 같은 동기화 폴더 안의 파일은 열지 않기로 했고, 나중에는 격리도 막습니다. 그러려면 먼저 어디가 동기화 폴더인지 레지스트리에서 찾아야 하는데, 찾기에 실패해도 지금 계획은 아무 표시 없이 넘어갑니다. A는 실패를 기록하고 화면에 알리며, 전부 실패하면 사용자 폴더의 확보량 계산을 안전하게 건너뜁니다.
Stakes if we pick wrong: 조용히 실패하면 동기화 폴더 파일을 열게 되고, M4에서는 격리 차단(S7)이 빠진 줄 모른 채 동작할 수 있습니다.
Recommendation: A because 감지 실패는 드물지만 실패했을 때 안전 약속이 조용히 무너지는 유형이라, 기록·경고·보수적 동작으로 드러나게 해야 합니다.
Completeness: A=9/10, B=4/10
Net: 실패를 드러내고 보수적으로 움직일지(A), 드문 경우로 보고 둘지(B)의 선택입니다.
Header: 감지 실패
Options:
A) 기록·경고·보수적 동작 (recommended)
소스별 결과를 요약과 로그에 기록, 일부 실패 시 경고, 전부 실패 시 사용자 폴더 accounting 건너뜀(미검증 표시). 레지스트리 읽기 주입 테스트. human ~2시간 / CC ~15분.
B) 그대로 둠
감지 실패를 따로 처리하지 않음. 클라우드 속성 판별만 믿음. human 0 / CC 0.
State: approved
Actual answer: A) 기록·경고·보수적 동작 (recommended) — D14 사용자 답변
Accepted scope: 소스별 감지 결과를 ScanSummary와 scan.log에 기록한다. 일부 실패하면 화면 경고를 띄운다. 전부 실패하면 사용자 폴더 accounting을 건너뛰고 "미검증"으로 표시한다. 레지스트리·환경 변수 읽기는 주입하고, 실패 테스트를 추가한다. 계획의 "동기화 루트"와 "테스트" 절을 고쳤다.
History: —

### R6: Q1 — "스캔되지 않은 용량" 계산 (설계 리뷰 R2-11)
Finding: Q1, P2, confidence 7/10, docs/plans/m2-scanner.md "결과" 절 `unaccounted_bytes` (계획 원문: 드라이브 사용량 − 스캔 합계), reviewer: Claude (Section 2) + 설계 spec review R2-11
Plan baseline: 드라이브 전체 스캔에서 `drive_used_bytes − total_logical_bytes`
Runtime evidence: 코드 없음. 하드링크 파일은 목록 합계에서 링크마다 세어져 합계가 부풀고, 차이가 줄거나 음수가 될 수 있음. unknown: 소유자 PC에서의 크기
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R6 계산 방식 | 사용량 − logical 합계 (음수 가능) | 사용량 − logical 합계를 0에서 자르고 "근사치"로 표시, 툴팁에 포함 항목(측정 안 한 시스템 폴더, 접근 거부, 하드링크 중복 집계로 인한 오차) 설명 | 이 숫자를 표시하지 않음(드라이브 사용량과 스캔 합계만 따로 표시) |
Question D15:
D15 — "스캔되지 않은 용량"을 어떻게 보여줄까요?
Project/branch/task: ClearCache main, M2 계획 Q1(설계 리뷰 R2-11).
ELI10: 드라이브 전체 스캔에서 "Windows가 말하는 사용량 − 우리가 잰 합계"를 스캔되지 않은 용량으로 보여주기로 했습니다. 그런데 하드링크 파일은 우리 합계에 여러 번 들어가서 합계가 부풀고, 그러면 이 숫자가 너무 작거나 음수가 될 수 있습니다. A는 0 아래로는 자르고 '근사치'라고 밝힙니다. B는 이 숫자를 아예 빼고 두 숫자만 따로 보여줍니다.
Stakes if we pick wrong: 그대로 두면 "-3 GB 스캔되지 않음" 같은 이상한 숫자가 나와 '정직한 숫자'라는 제품 핵심이 흔들립니다.
Recommendation: A because 측정하지 않은 시스템 폴더가 대략 얼마인지 알려주는 쓸모는 살리면서, 근사치임을 밝혀 정직함을 지킵니다.
Completeness: A=8/10, B=7/10
Net: 근사치라도 보여줄지(A), 틀릴 수 있는 숫자는 아예 빼 버릴지(B)의 선택입니다.
Header: 스캔 안 된 용량
Options:
A) 0에서 자르고 근사치 표시 (recommended)
max(0, 사용량 − 합계)를 "약 N GB (근사치)"로 표시, 툴팁에 포함 항목과 하드링크 오차 설명, 음수 케이스 단위 테스트. human ~1시간 / CC ~5분.
B) 표시하지 않음
드라이브 사용량과 스캔 합계만 따로 보여주고 차이는 계산하지 않음. human ~30분 / CC ~3분.
State: approved
Actual answer: A) 0에서 자르고 근사치 표시 (recommended) — D15 사용자 답변
Accepted scope: `max(0, 사용량 − 합계)`를 "약 N GB (근사치)"로 표시하고, 툴팁에 포함 항목과 하드링크 오차를 설명한다. 음수 케이스 단위 테스트를 추가한다. 계획의 "결과"와 "테스트" 절을 고쳤다.
History: —

### R7: Q2 — 일부만 측정된 폴더 표시 (설계 리뷰 R2-9)
Finding: Q2, P2, confidence 7/10, docs/plans/m2-scanner.md "시스템 항목 매핑" 표 "`C:\Windows.old` 순회하고 접근 가능한 만큼만 측정", reviewer: Claude (Section 2) + 설계 spec review R2-9
Plan baseline: 접근 거부 폴더는 `skipped`에 기록한다. 그 조상 폴더의 크기가 일부만 측정됐다는 표시는 없다.
Runtime evidence: 코드 없음. `Windows\Minidump`, `Windows\LiveKernelReports`, `Windows.old`의 일부는 보통 관리자 없이 읽을 수 없음. unknown: 소유자 PC의 실제 거부 범위
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R7 일부 측정 표시 | 없음 | 노드에 `partial: bool`과 `skipped_descendants: u32`를 두고 아래에서 위로 전파. 화면 크기 칸에 "일부만 측정 (N개 폴더 읽기 불가)" 표시. Minidump·LiveKernelReports는 매핑표에 "관리자 없이 보통 읽기 불가"로 명시 | 그대로 둠(하단 요약의 건너뜀 개수만) |
Question D16:
D16 — 일부 하위 폴더를 읽지 못한 폴더에 "일부만 측정"이라고 표시할까요?
Project/branch/task: ClearCache main, M2 계획 Q2(설계 리뷰 R2-9).
ELI10: Windows.old나 메모리 덤프 폴더처럼 관리자 권한 없이는 안쪽 일부를 읽을 수 없는 폴더가 있습니다. 지금 계획은 읽은 만큼만 더하고, 그 폴더 크기가 일부만 잰 값이라는 표시가 없습니다. A는 그런 폴더와 그 위 폴더에 "일부만 측정 (N개 폴더 읽기 불가)"을 붙입니다.
Stakes if we pick wrong: 표시가 없으면 사용자가 "Windows.old가 2 GB뿐이네"처럼 실제보다 작은 값을 믿고 판단합니다.
Recommendation: A because 숫자가 불완전할 때 그 사실을 숫자 옆에 밝히는 것이 이 제품의 '정직한 숫자' 원칙이고, 구현 비용이 작습니다.
Completeness: A=9/10, B=5/10
Net: 불완전한 숫자에 표시를 붙일지(A), 하단 요약의 건너뜀 개수로만 알릴지(B)의 선택입니다.
Header: 일부 측정 표시
Options:
A) "일부만 측정" 표시 (recommended)
`partial`·`skipped_descendants`를 위로 전파하고 크기 칸에 표시, 매핑표에 Minidump·LiveKernelReports 접근 불가 예상 명시, 전파 단위 테스트. human ~1시간 / CC ~8분.
B) 그대로 둠
하단 요약의 건너뜀 개수로만 알림. human 0 / CC 0.
State: approved
Actual answer: A) "일부만 측정" 표시 (recommended) — D16 사용자 답변
Accepted scope: `partial`·`skipped_descendants` 필드를 위로 전파하고 크기 칸에 "일부만 측정 (N개 폴더 읽기 불가)"을 표시한다. 매핑표에 Minidump·LiveKernelReports를 접근 불가 예상으로 명시하고, 전파 단위 테스트를 추가한다. 계획의 "시스템 항목 매핑", "결과", "테스트" 절을 고쳤다.
History: —

### R8: T1 — 화면 로직 테스트
Finding: T1, P2, confidence 8/10, docs/plans/m2-scanner.md "화면" 절(크기 칸 라벨 규칙, 트리 정렬)과 "테스트" 절(프론트엔드 테스트 없음), reviewer: Claude (Section 3 Tests)
Plan baseline: 프론트엔드 테스트 없음. 화면은 수동 검증(검증 3단계)만 한다.
Runtime evidence: package.json에 test 스크립트 없음, 테스트 파일 0개(감지 결과)
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R8 화면 로직 테스트 | 없음 | Vitest 추가(`npm test`). 라벨 규칙·format·트리 정렬을 순수 함수(`src/lib/`)로 빼서 단위 테스트. 컴포넌트 렌더 테스트는 하지 않음 | 추가하지 않음. 수동 검증 체크리스트만 |
Question D17:
D17 — 화면 로직에 자동 테스트를 붙일까요?
Project/branch/task: ClearCache main, M2 계획 T1(프론트엔드 테스트 없음).
ELI10: 크기 칸에 무엇을 쓸지는 규칙이 꽤 많습니다. 실제 확보량이 있으면 "실제 확보", 없으면 "최대치(미검증)", 시스템 항목은 "차지하는 크기", 그 밖에 "계산 중", "취소됨", "일부만 측정"이 있습니다. 이 규칙이 틀리면 사용자가 지울 수 있는 양을 잘못 믿게 됩니다. A는 이 규칙과 바이트 표기, 트리 정렬을 작은 함수로 빼서 Vitest로 자동 테스트합니다.
Stakes if we pick wrong: 테스트가 없으면 M3·M4에서 라벨 규칙이 늘어날 때 "최대치"가 "실제 확보"로 잘못 표시되는 회귀를 눈으로만 잡아야 합니다.
Recommendation: A because 이 제품의 핵심인 '정직한 숫자'가 화면에서 결정되는 곳이고, 순수 함수 테스트는 CC 기준 10분이면 됩니다.
Completeness: A=9/10, B=5/10
Net: 지금 작은 테스트 틀을 깔지(A), 화면은 눈으로만 확인할지(B)의 선택입니다.
Header: 화면 테스트
Options:
A) Vitest로 순수 함수 테스트 (recommended)
Vitest 추가, `npm test` 스크립트, 라벨 규칙·format·정렬을 `src/lib/`로 분리해 단위 테스트. 컴포넌트 렌더 테스트는 제외. human ~3시간 / CC ~10분.
B) 추가하지 않음
화면은 수동 검증 체크리스트로만 확인. human 0 / CC 0.
State: approved
Actual answer: A) Vitest로 순수 함수 테스트 (recommended) — D17 사용자 답변
Accepted scope: Vitest devDependency와 `npm test` 스크립트를 추가한다. 라벨 규칙·format·트리 정렬을 `src/lib/`의 순수 함수로 빼서 단위 테스트한다. 컴포넌트 렌더 테스트는 하지 않는다. 계획의 "파일", "테스트", "검증" 절을 고쳤다.
History: —

Approval readiness: PASS — R1(D10), R2(D11), R3(D12), R4(D13, 추가 규칙 포함), R5(D14), R6(D15), R7(D16), R8(D17) 모두 사용자 실제 답변으로 승인. 리뷰 중 추가한 테스트 3건(열기 실패, 진행률, 동시 스캔 거부)은 승인된 동작의 증명이라 별도 승인 없이 포함.

## Review: NOT in scope

- M3로 미룸: 등급·action 판정, 규칙 묶음, 선택 정책, 체크하거나 펼칠 때 하는 exclusive 계산, 보호 검사 S2·S3·S9
- M4로 미룸: 격리·복원·완전 삭제, 영수증, S1~S12 테스트, "계산 중/취소됨 선택 불가" 규칙의 구현(D13)
- v2 이후: MFT 가속(관리자), 재생성 추적, 드라이브별 격리, 관리자 권한 공식 도구 실행
- TODOS.md: 새 TODO 없음. v2 항목은 설계 문서 Open Questions와 SPEC "v2 아이디어"에 있음

## Review: What already exists

- 저장소에는 M1 빈 화면(`src/App.tsx`, `src-tauri/src/lib.rs`)만 있어 재사용할 로직이 없다.
- 표준 라이브러리 `std::fs::read_dir`/`DirEntry::metadata`(파일을 열지 않음)와 `rayon`을 쓴다. `windows` 크레이트로 Win32를 호출한다(`CreateFileW`, `GetFileInformationByHandle(Ex)`, 레지스트리).
- 기존 도구(jwalk, pdu, dua-cli)는 쓰지 않는다. 메타데이터를 얻으려면 파일을 다시 열어야 하고, 파일 속성 기반의 DirPolicy·클라우드 미개봉 요구를 끼울 수 없다.

## Review: Diagrams

```
[화면] 대상 선택(id) --start_scan(id, Channel)--> [commands.rs]
                                                   | id -> 경로 (targets.rs, 목록 재조회, 모르는 id 거부)
                                                   | 동시 스캔 거부
                                                   v
                              [syncroots.rs] 레지스트리·환경변수 -> 루트 목록 + 소스별 결과
                                                   | (일부 실패 -> 경고, 전부 실패 -> 사용자 폴더 accounting 끔)
                                                   v
   +---------------- 1단계: 순회 (walk.rs, rayon 풀 스택 8 MiB) ----------------+
   | read_dir -> DirEntry.metadata (파일 열지 않음)                             |
   |   +- attrs: 리파스 포인트 -> 들어가지 않음, is_link                        |
   |   +- attrs: 클라우드 전용 -> 0바이트, cloud_only_files++ (절대 열지 않음)  |
   |   +- policy: 시스템 항목 매핑 / 격리함 제외 / 깊이 > 512 -> skipped        |
   |   +- 접근 거부 -> skipped, 조상에 partial 전파                             |
   |   +- DirAgg 합산, 1 GiB 미만 자식은 버림 (시스템 노드는 유지)              |
   +-------------------------------+--------------------------------------------+
                                   v ScanResult 반환 -> 화면 즉시 표시 (확보량 "계산 중")
   +---------------- 2단계: 확보량 (accounting.rs) -----------------------------+
   | 허용 목록 노드만: 파일마다                                                 |
   |   클라우드 속성 or 동기화 루트? -- 예 --> 열지 않음                        |
   |        | 아니오                                                            |
   |   CreateFileW(READ_ATTRIBUTES, 전체 공유, OPEN_REPARSE_POINT|BACKUP)       |
   |        +- 실패 -> logical로, unverified_files++                            |
   |        +- 성공 -> 같은 핸들: 파일 ID·링크 수·크기(FileStandard/Compression)|
   |   범위 안 링크 수 == nNumberOfLinks ? exclusive : shared                   |
   +-------------------------------+--------------------------------------------+
                                   v AccountingUpdate{node_id,...} -> Channel -> 화면 칸 갱신
                             취소 시: 순회 결과 유지, 확보량 칸 "취소됨"
```

코드 안 다이어그램: `accounting.rs` 모듈 문서에 exclusive/shared 판정 규칙과 위 2단계 흐름을 요약해 둔다(release gate 설명 대비).

## Review: Failure modes

| 새 경로 | 현실적인 실패 | 테스트 | 오류 처리 | 사용자에게 보이나 |
| --- | --- | --- | --- | --- |
| targets | 스캔 중 이동식 드라이브 제거 | 모르는 id 거부만 | read_dir 오류 -> skipped | 보임(건너뜀 수) |
| walk | 아주 깊은 폴더 | 깊이 600 픽스처 | 512 초과 -> skipped | 보임("너무 깊음") |
| walk | 관리자 전용 폴더 | partial 전파 주입 | skipped + partial | 보임("일부만 측정") |
| syncroots | 레지스트리 읽기 실패 | 일부·전부 실패 주입 | 경고 / accounting 끔 | 보임(경고, "미검증") |
| accounting | 파일 잠김(공유 위반) | 열기 실패 주입 | logical + unverified | 보임("일부 미검증 N개") |
| accounting | 클라우드 파일을 열어 다운로드 | 열기 호출 0회 주입 | 속성 먼저 판별 | 해당 없음(일어나지 않음) |
| accounting | WOF 압축 파일 크기 오차 | ignored 비교 테스트(D11) | 비교 후 방식 확정 | 보고 |
| channel | 창을 닫아 전송 실패 | — | 전송 오류 무시, 스캔 종료 | 해당 없음 |
| summary | 하드링크로 합계가 부풂 | 0 자르기 | max(0, …) + 근사치 | 보임("근사치") |

**Critical gaps: 0** — 테스트도, 오류 처리도 없이 조용히 실패하는 경로는 없다.

## Review: Worktree parallelization strategy

| Step | Modules touched | Depends on |
|------|----------------|------------|
| Rust core (targets, scan, syncroots) | `src-tauri/src/core/` | — |
| accounting | `src-tauri/src/core/accounting` | Rust core(attrs, syncroots) |
| 화면 순수 함수 + Vitest | `src/lib/`, `package.json` | — (타입 계약만 먼저 합의) |
| 커맨드 + 화면 연결 + CLI 예제 | `src-tauri/src/commands`, `src/components`, `src-tauri/examples` | 위 세 단계 모두 |

- Lane A: Rust core → accounting (`src-tauri/src/core/` 공유라 순차)
- Lane B: `src/lib/` 순수 함수 + Vitest (독립)
- 실행 순서: `src/types.ts` 계약을 먼저 정하고 A와 B를 동시에 시작한다. 둘 다 합친 뒤 커맨드, 화면 연결, CLI 예제를 한다.
- 충돌 주의: `src/types.ts`(A의 결과 구조와 B의 입력)는 먼저 확정하고 바꿀 때 두 레인을 함께 고친다.

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific finding above. Run with Claude Code or Codex; checkbox as you ship.

- [ ] **T1 (P1, human: ~3h / CC: ~15min)** — core/targets — 스캔 대상 목록과 id 해석, 순수 판정 함수 테스트
  - Surfaced by: 계획 "스캔 대상" (D7 승인 범위)
  - Files: `src-tauri/src/core/targets.rs`
  - Verify: `cargo test targets`
- [ ] **T2 (P1, human: ~1d / CC: ~40min)** — core/scan — walk·attrs·policy: 속성 판별, 시스템 매핑, 깊이 제한, partial 전파, 두 단계 반환
  - Surfaced by: F3(D12), Q2(D16), A1(D13)
  - Files: `src-tauri/src/core/scan/{walk,attrs,policy,progress,mod}.rs`
  - Verify: `cargo test scan` (깊이 600, 정션, partial, 취소, 두 단계)
- [ ] **T3 (P1, human: ~3h / CC: ~15min)** — core/syncroots — 동기화 루트 감지와 실패 처리(주입)
  - Surfaced by: A2(D14)
  - Files: `src-tauri/src/core/scan/syncroots.rs`
  - Verify: `cargo test syncroots`
- [ ] **T4 (P1, human: ~1d / CC: ~40min)** — core/accounting — 같은 핸들에서 크기를 읽는 exclusive/shared, 클라우드·동기화 미개봉, 열기 실패 폴백
  - Surfaced by: F2(D11), 설계 R2-5
  - Files: `src-tauri/src/core/accounting.rs`
  - Verify: `cargo test accounting`, `cargo test -- --ignored` (WinSxS 샘플 비교)
- [ ] **T5 (P1, human: ~4h / CC: ~20min)** — commands — start_scan/cancel/get_scan_result, Channel 두 단계 갱신, 동시 스캔 거부
  - Surfaced by: A1(D13), Section 3 추가 테스트
  - Files: `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`
  - Verify: `cargo test commands`
- [ ] **T6 (P2, human: ~30min / CC: ~5min)** — CLI — `examples/scan.rs`
  - Surfaced by: F1(D10)
  - Files: `src-tauri/examples/scan.rs`
  - Verify: `cargo run --example scan -- --target user_home --json`
- [ ] **T7 (P2, human: ~3h / CC: ~10min)** — 화면 로직 — `src/lib/{format,sizeLabel,sortTree}.ts` + Vitest
  - Surfaced by: T1(D17), Q1(D15)
  - Files: `src/lib/*`, `package.json`
  - Verify: `npm test`
- [ ] **T8 (P2, human: ~1d / CC: ~30min)** — 화면 — TargetPicker, ProgressBar, FolderTree, Summary(경고, 근사치, 보기 전용)
  - Surfaced by: A1(D13), A2(D14), Q1(D15), Q2(D16)
  - Files: `src/components/*`, `src/App.tsx`, `src/types.ts`
  - Verify: `npm run tauri dev` 수동 체크리스트(Test Plan artifact)
- [ ] **T9 (P3, human: ~30min / CC: ~5min)** — 문서 — `LICENSE`(MIT 임시), SPEC 본문에 설계 문서의 네 종류 분류·확보량 모델 반영(v1.3 약속)
  - Surfaced by: 설계 문서 승인(D8), SPEC v1.3 개정 이력
  - Files: `LICENSE`, `SPEC.md`
  - Verify: 문서 검토

JSONL 작업 파일: `jq`가 설치돼 있지 않아 만들지 않았다(not persisted). /autoplan 집계가 필요하면 jq를 설치하고 다시 실행한다.

## Review: Unresolved decisions

없음. 이번 리뷰의 선택(D9~D17)은 모두 답변을 받았다.

## Review: Completion summary

- Step 0: Scope Challenge — scope accepted as-is(기능 삭제 없음, 구조 A, D9). F1~F3 모두 권장안 채택
- Architecture Review: 2 issues found (A1, A2)
- Code Quality Review: 2 issues found (Q1, Q2)
- Test Review: diagram produced, 1 gap identified (T1 화면 로직). 승인된 동작의 증명 테스트 3건 추가
- Performance Review: 0 issues found (A1에서 처리)
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 0 items proposed to user (v2 항목은 설계 문서와 SPEC에서 추적)
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 0 in this review
- Outside voice: codex, unavailable (CLI 미설치, 네이티브 폴백에 필요한 TaskOutput 도구 없음)
- Parallelization: 2 lanes, 2 parallel / 1 sequential integration step
- Lake Score: 8/8 = 커버리지 차이가 있는 선택 8개(D10~D17)에서 모두 완성도 높은 쪽을 골랐다

## Suppressed findings (appendix)

- [P3] (confidence: 4/10) "진행률" 절 `Mutex<String>`(지금 보는 폴더): rayon 스레드가 폴더마다 이 잠금을 잡으면 경합이 생길 수 있다. 200ms 표본 방식이라 영향은 작을 것으로 보여 본문에서 뺐다. 구현할 때 `try_lock`으로 실패하면 건너뛰는 방식을 고려한다.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Outside Review | codex via `/plan-eng-review` outside voice | Independent 2nd opinion | 1 | unavailable | Codex CLI 미설치, 네이티브 폴백 불가(TaskOutput 없음) |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | ISSUES OPEN (PLAN) | 8 issues, 0 critical gaps (8건 모두 이번 리뷰에서 승인된 조치로 계획에 반영) |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex, phase plan-review, unavailable (CLI not installed; native fallback unavailable), no findings. 같은 세션의 /office-hours에서는 Claude 서브에이전트가 두 번째 의견을 냈다(외부 모델 커버리지는 아님).
- **VERDICT:** CLEAR인 리뷰 없음 — eng review required (상태 ISSUES OPEN은 발견 8건이 모두 계획에 반영된 작업이라는 뜻이며, 미해결 결정은 없음)

NO UNRESOLVED DECISIONS
