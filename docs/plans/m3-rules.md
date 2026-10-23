# M3 계획 (초안): 규칙 DB + 등급 판정 + 시스템 폴더 보호

> **현재 상태 (2026-10-24): 초안, 범위 질문 Q1~Q5 결정 완료.** 승인 전에 `/plan-design-review`와 `/plan-eng-review`를 거친다. 구현은 시작하지 않았다.
> - Q1~Q5는 사용자가 결정했다(아래 "결정됨"). 사용자 검토(2026-10-24)의 1~3번은 반영했다(자격 증명 보호 경로의 S2 전파, `node_modules` 제외 범위, 규칙 안 `.git` 비전파). 4~10번은 미결 U3~U9로 eng 리뷰에서 다룬다.
> - 첫 작업은 라이선스 정리(T0)다. MIT로 확정됐고, 규칙을 한 줄이라도 쓰기 전에 관련 파일의 표기를 끝낸다.

기준 문서: [SPEC.md](../../SPEC.md) v1.5, 설계 문서 [clearcache-reclaim-core.md](../designs/clearcache-reclaim-core.md)(접근 B), [m2-scanner.md](m2-scanner.md)(M2 완료, "남은 할 일"과 "다음 단계로 미루는 것")

## 완료 기준

SPEC "개발 단계" M3 행을 그대로 따르고, 이 계획의 범위에서 생기는 기준을 더한다.

- 개발 캐시를 AI 없이 알아본다: `%LOCALAPPDATA%\npm-cache`와 git 저장소 안의 `node_modules`는 "안전", 그 저장소 루트는 "사용자 데이터"로 뜬다(SPEC M3 기준).
- 폴더마다 등급 배지(안전 / 아마 안전 / 사용자 데이터 / 모름), 근거 한 줄, 출처(안전규칙 / 규칙 / —)가 나온다. AI 출처는 M5부터다.
- 같은 규칙에 걸린 폴더들이 크기와 관계없이 묶음으로 나온다(예: `node_modules × 143개, 18.2 GB`). 펼치면 개별 폴더가 보인다.
- 규칙에 걸린 폴더 아래로는 결과 트리를 더 내리지 않는다(크기는 끝까지 잰다).
- 보호 대상은 Rust에서 판정하고, 화면에서 선택할 수 없다. 보호 판정 함수는 M4의 격리·복원 직전 재검사(S3, S12)가 그대로 다시 쓴다.
- **안전 규칙 단위 테스트가 모두 통과한다**(SPEC M3 기준). 경로 대소문자, 끝의 `\`, 8.3 짧은 이름(`PROGRA~1`), `\\?\` 접두사 변형을 포함한다.
- M4 전이므로 **파일을 옮기거나 지우는 코드는 만들지 않는다**(SPEC "에이전트에게 줄 공통 지시").

## 범위

**이번에 하는 것**
- **라이선스 정리**(T0, 선행 조건): MIT 확정(Q5)에 맞춰 표기 정리
- **규칙 DB**: 내장 `rules.json`(버전 포함) + SQLite `rules` 테이블, 실행할 때마다 버전 비교로 내장 규칙 갱신, 사용자 규칙(`source=user`) 분리 보관. 규칙 묶음 두 개(Windows 기본, 개발·AI).
- **등급 판정**: SPEC "판정 우선순위" 1(하드코딩 안전 규칙) → 2(규칙 DB, 가장 구체적인 규칙) → 4(`unknown`). 3(AI)은 M5에서 끼운다. 등급과 별도로 `action`(`quarantine` / `official_tool` / `uninstall_app` / `explain_only`)을 판정한다.
- **시스템 폴더 보호와 S 규칙 중 선택 단계 규칙**: 시스템 보호 경로, 드라이브·사용자 폴더 루트, S2(보호 대상을 품은 폴더), S7(동기화 루트 안), S9(리파스 포인트 폴더), S11(가상 디스크와 그 폴더). S8은 M2에서 이미 지킨다.
- **선택 정책**(체크박스 활성화): 기본 체크, 경고 모달, 부모·자식 동시 선택 금지, "계산 중/취소됨" 선택 불가(D13).
- **선택 합계**: 선택한 항목들의 합집합 범위로 계산(R2-3), 일부 미검증 폴더의 처리(R2-4).
- **체크하거나 펼칠 때 `exclusive_bytes` 계산**(M2에서 미룬 것). 허용 목록 밖 폴더에도 적용한다.
- 화면: 등급 배지·근거·출처 열, 묶음 행, 선택 합계 바, 경고 모달, 네 종류 카드(디자인 리뷰 대상).
- SPEC 정리: "절대 목록에 올리지 않는 경로"를 "절대 선택 불가"로 바꿈(Q4, 이 계획 작성 때 반영 완료).

**다음 단계로 미루는 것**
- M4: 격리·복원·완전 삭제, S1·S3·S4·S5·S6·S10·S12의 실행 단계 검사와 테스트, action_log. M3는 S3·S12가 쓸 **판정 함수**까지만 만든다.
- M5: AI 판정(판정 우선순위 3), `verdicts` 캐시.
- M6: 등급 필터 탭, "직접 할 일" 카드의 딥링크·명령 복사 버튼. M3는 공식 도구 안내를 **글로만** 보여준다.
- M3 제외(Q1, 단계 미정): 앱 연결(R2-15), 마지막 실행 표시(R2-14), BAM 조사. 해결책은 "결정됨" Q1에 기록해 둔다.

## 결정됨

M2와 이전 리뷰에서 확정되어 이 계획이 따르는 것. 리뷰에서 다시 논의하지 않는다.

- **크기 단위 (사용자, 2026-10-23):** 탐색기와 같은 1024 단위에 "GB" 표기를 쓴다(GiB 표기 안 함). 크기에 마우스를 올리면 정확한 바이트 수를 툴팁으로 보여준다(크기, 실제 확보 또는 공유되지 않음, 공유). DISM처럼 10⁹ 단위를 쓰는 도구와 숫자가 달라 보이는 문제는 툴팁의 바이트 수로 대조한다. M2에서 구현했다(`src/lib/format.ts` `formatExactBytes`, `src/lib/sizeLabel.ts`). M3의 새 숫자(묶음 합계, 선택 합계, 카드 합계)도 같은 규칙을 따른다.
- **"실제 확보" 라벨**은 `exclusive_bytes`가 있을 때만 쓴다. 그 밖은 "최대치(미검증)", 선택할 수 없는 항목은 "차지하는 크기"(R2-10, M2에서 구현).
- **WinSxS 중립 라벨** 유지: "Windows와 공유되지 않는 파일 N GB (전부 확보 가능한 것은 아님)". 근거는 M2의 DISM 비교다. 판정은 DISM과 일치하고, 0.8~1.5% 차이는 할당 크기 기준 때문이다.
- **D13:** 확보량이 "계산 중"이거나 계산이 취소된 폴더는 선택·격리할 수 없고, 예상 합계에도 넣지 않는다.
- **D7 설계 원칙:** 시스템 폴더 파일은 ClearCache가 직접 삭제·격리하지 않는다. 크기와 공식 확보 방법만 보여준다.

아래 Q1~Q5는 이 계획 초안에서 물었고, 사용자가 2026-10-24에 권장안대로 결정했다.

- **Q1. 앱 연결·마지막 실행은 M3에서 제외.** M3는 Program Files 하위를 `uninstall_app`으로 판정하고 "앱 제거 화면에서 확인하세요"만 보여준다. 앱 이름과 마지막 실행은 표시하지 않는다. 넣을 단계는 아직 정하지 않았다. 그때 다시 찾지 않도록 리뷰 해결책을 여기 남긴다.
  - R2-15: `DisplayIcon`·`UninstallString`에서 얻은 폴더는 Program Files, Program Files (x86), 알려진 사용자별 앱 루트 아래일 때만 받는다. 공유 벤더 상위 폴더, `C:\Windows\Installer\{GUID}`, System32의 `msiexec.exe`는 연결하지 않는다.
  - R2-14: UserAssist 값 이름의 KNOWNFOLDERID GUID 접두사를 경로로 풀고, `.lnk` 항목은 대상 exe로 푼다. 값은 ROT13으로 디코딩하고, 값 구조(실행 횟수, 마지막 실행 FILETIME)를 명시한다. 일치하는 기록이 없으면 "알 수 없음"으로 표시하고, "사용 안 함"이라고는 절대 표시하지 않는다.
  - BAM을 관리자 없이 읽을 수 있는지는 그 단계에서 조사한다.
- **Q2. 기본 action(R2-8).**
  - 규칙에 안 걸린 폴더: `grade=unknown`, `action=quarantine`, 체크하면 경고 모달.
  - 규칙 DB가 "사용자 데이터"로 판정한 폴더: `action=quarantine`, 경고 모달.
  - 안전 규칙이 "사용자 데이터"로 고정한 폴더:
    - **자격 증명·브라우저 프로필·스토어 앱 데이터**(`.ssh`, `.aws`, `.gnupg`, `.azure`, `.kube`, 브라우저 `User Data`/`Profiles`, `%LOCALAPPDATA%\Packages`): `action=explain_only`, **선택 불가**. `Packages` 안의 캐시 폴더도 M3에서는 전부 선택 불가다(아래 미결 항목 U1).
    - 나머지(Documents, Desktop, Pictures, Videos, Music, git 저장소 루트, 큰 `.pst`·`.kdbx` 폴더): `action=quarantine`, 경고 모달. 일반 경고보다 강한 형태로 할지는 디자인 리뷰에서 정한다.
  - 이유: 자격 증명은 격리해도 공간 이득이 거의 없고, 앱이 깨지는 피해가 크다.
- **Q3. 일부 미검증 폴더(R2-4): "실제 확보"와 "미검증"을 나눠 표시한다.**
  - `AccountingUpdate`에 `unverified_bytes`를 추가해 미검증 파일의 바이트를 따로 센다.
  - 화면 표시: "실제 확보 N GB + 미검증 M GB(최대치)".
  - 선택 합계: N은 확정 값으로, M은 "최대치" 칸으로 나눠 더한다.
  - 성공 기준의 10% 예측 오차 측정에는 미검증 파일이 없는 항목만 넣는다.
- **Q4. SPEC 안전 규칙 문구 변경 승인.** "절대 목록에 올리지 않는 경로"를 "**절대 선택·격리·삭제 대상이 될 수 없는 경로**"로 바꿨다(SPEC v1.5). 목록에는 "시스템 (보호됨)"으로 표시만 한다. 경로 목록은 그대로이고, 격리함 폴더는 계속 목록에서도 뺀다.
- **Q5. 라이선스 MIT 확정.** BleachBit(GPL) 규칙은 참고만 하고 복사하지 않으며, 규칙은 직접 작성한다. 남은 일은 T0의 표기 정리뿐이다.

## 미결 항목

리뷰나 이후 단계에서 정한다. M3 구현을 막지 않는다.

- **U1. `%LOCALAPPDATA%\Packages` 안의 캐시 폴더를 개별로 풀 수 있는가** (사용자 요청, 2026-10-24)
  - M3: `Packages` 전체를 선택 불가로 둔다(Q2). 하위 `LocalCache`, `TempState`, `AC\INetCache` 같은 캐시 폴더도 예외 없이 막는다.
  - 나중에 확인할 것:
    - 앱마다 이 폴더들을 지워도 다시 만드는지(앱이 실행 중일 때 포함). 대표 앱 몇 개(Claude, Teams, 스토어 게임)로 실측한다.
    - `LocalCache`는 앱에 따라 진짜 데이터를 두기도 한다. 예를 들어 데스크톱 브리지 앱은 `LocalCache\Roaming`에 AppData를 리디렉션한다. M2 실측에서 `Claude_…\LocalCache\Roaming\Claude`가 9.55 GB였다. 그래서 폴더 이름만으로는 "안전"이라 할 수 없다.
    - 풀 경우의 형태: 앱 패키지 이름별 허용 규칙(`source=builtin`, 등급 "아마 안전")으로만 풀고, `Packages` 전체 규칙보다 구체적인 규칙이 이기는 판정 우선순위 2를 따를지. 안전 규칙 1이 고정한 폴더 "자체"만 바꿀 수 없다는 현재 규칙과 충돌하지 않는지 확인한다.
  - 정할 단계: M4 격리가 동작한 뒤(복원으로 되돌릴 수 있게 된 다음).
- **U2. 묶음 구성원 수 상한**: 규칙에 걸린 폴더가 수만 개일 때 결과 크기. eng 리뷰에서 정한다(아래 "스캔 변경").

아래 U3~U9는 사용자 검토(2026-10-24)에서 나왔고, **eng 리뷰에서 다룬다.**

- **U3. 순회 중 1차 패턴 매칭과 순회 후 최종 판정의 역할 정리.** 묶음을 만들고 트리를 멈추려면 순회 중에 규칙 매칭이 필요하다. 그런데 "설계 > 스캔 변경"은 판정을 순회 후 한 번 한다고 적었다. 두 단계가 각각 무엇을 정하는지, 결과가 다를 때 어느 쪽을 따르는지 정한다. 예: 순회 중에는 `not_inside`·`when`까지 판정해 멈출 곳을 정하고, 순회 후에는 안전 규칙 고정·S2 전파로 최종 등급과 선택 가능 여부를 정한다.
- **U4. 기본 체크된 "안전" 항목들의 exclusive 계산 동시 실행 제한.** 스캔 직후 기본 체크가 여러 개면 계산이 한꺼번에 시작된다. 동시 실행 수, 대기열, 취소 동작을 정한다.
- **U5. 묶음 선택에 선택 불가 구성원이 섞일 때.** 예: `node_modules × 143개` 중 일부가 동기화 루트 안이거나 계산 중일 때. "143개 중 140개 선택"처럼 선택 가능한 것만 고르고 개수를 보여줄지, 묶음 전체를 막을지 정한다.
- **U6. 규칙 구체성 비교.** 패턴 문자열 길이 대신 **전개된 경로의 깊이(구성요소 수)**로 비교한다. 동점이면 **보수적인 등급**(사용자 데이터 > 모름 > 아마 안전 > 안전)이 이긴다. "설계 > 판정 우선순위"의 "패턴이 가장 긴 것"을 이 기준으로 바꿀지 확정한다.
- **U7. Temp 기준일은 `max(생성일, 수정일)`.** 압축을 풀거나 복사한 파일은 수정일이 옛날이어도 방금 생긴 것일 수 있다. 목록 정보의 생성일·수정일 중 늦은 쪽으로 "7일 넘음"을 판정한다. 폴더 단위 판정 방법(하위에서 가장 최근 값)도 함께 정한다.
- **U8. 동기화 루트 감지가 전부 실패했을 때 사용자 폴더 선택 차단이 M3인지 M4인지.** M2는 이 경우 사용자 폴더 안의 확보량 계산만 건너뛴다(D14). 선택까지 막을지, 막는다면 M3 선택 정책에 넣을지 M4 격리 직전 검사에 넣을지 정한다.
- **U9. `.kdbx`를 자격 증명 쪽(선택 불가)으로 옮기기.** 지금 계획(Q2)은 큰 `.kdbx` 폴더를 "경고 모달 후 선택 가능"으로 둔다. 비밀번호 DB는 자격 증명과 같은 성격이므로 자격 증명 보호 경로처럼 선택 불가로 옮긴다(크기 기준도 없앨지 함께 정한다). 확정하면 SPEC 안전 규칙도 고친다.

## 구조

```
src-tauri/src/core/
  rules/
    mod.rs          규칙 타입, 판정 진입점 (grade + action + reason + source + rule_id)
    builtin.rs      include_str!("../../../rules/rules.json"), 버전 파싱
    pattern.rs      경로 패턴 매칭 (환경 변수 전개, `**\name`, 조건) ← 순수 함수
    db.rs           SQLite: rules 테이블, 내장 규칙 버전 동기화, 사용자 규칙
  protect.rs        보호 판정 (시스템 경로, 루트, S2·S7·S9·S11) ← 순수 함수 + 경로 정규화
  scan/walk.rs      (수정) 규칙에 걸린 폴더에서 트리 멈춤, 묶음 수집, 보호 플래그 상향 전파
  accounting.rs     (수정) 여러 루트 합집합 범위, unverified_bytes
  selection.rs      선택 가능 여부, 부모·자식 배제, 합집합 합계
src-tauri/rules/rules.json   내장 규칙 (버전 번호 포함)
src/lib/{grade,selection}.ts + *.test.ts
src/components/{GradeBadge,RuleGroupRow,SelectionBar,WarningModal,CategoryCards}.tsx
```

- `rusqlite`(bundled) 의존성을 추가한다. DB 위치는 `%LOCALAPPDATA%\ClearCache\clearcache.db`다. M3는 `rules` 테이블과 스키마 버전 테이블만 만든다. `verdicts`, `quarantine`, `action_log`는 쓰는 단계(M4·M5)에서 만든다.
- 커맨드(아키텍처 경계 유지, id만 받음): `toggle_select(node_id)`, `compute_exclusive(node_id)`, `get_selection_total()`. 경로를 받는 커맨드는 만들지 않는다. 사용자 규칙 편집 화면은 M6이고, M3는 DB 구조만 준비한다.

## 설계

### 판정 우선순위와 결과

- 노드마다 `Verdict { grade, action, reason, source, rule_id, protection: Option<Protection> }`를 붙인다.
  - `grade`: `safe` / `likely_safe` / `user_data` / `unknown`
  - `source`: `safety` / `rule` / `none`(M5에서 `ai` 추가)
  - `action`: `quarantine` / `official_tool` / `uninstall_app` / `explain_only`
- 우선순위(SPEC):
  1. **하드코딩 안전 규칙**: 시스템 보호 경로 → 선택 불가. 사용자 데이터 고정 목록 → `user_data`.
  2. **규칙 DB**: 여러 규칙이 걸리면 가장 구체적인 것(패턴이 가장 긴 것)이 이긴다. 단, 1이 `user_data`로 고정한 폴더 **자체**는 바꿀 수 없다.
  3. (M5) AI
  4. 그 외 `unknown`
- `user_data` 고정은 그 폴더 자체와, 규칙에 걸리지 않은 하위에 적용된다. 하위에서 규칙에 걸린 폴더(예: 저장소 안의 `node_modules`)는 규칙을 따른다.
- **네 종류 분류는 `action`에서 나온다**: `quarantine` → (1), `official_tool` → (2), `uninstall_app` → (3), `explain_only` → (4). 시스템 항목 매핑(SPEC "1-1")의 분류 열을 그대로 `action`으로 옮긴다.

### 규칙 DB

- 규칙 필드(SPEC "2. 규칙 DB" + 이번 추가):
  - `id`, `pattern`, `name`, `grade`, `action`, `description`, `restore_hint`, `target_mode`(`folder` / `contents_older_than`), `older_than_days`, `bundle`(`windows` / `dev_ai`), `when`(조건, 아래), `source`(`builtin` / `user`), `builtin_version`
- **패턴**:
  - 환경 변수 접두(`%LOCALAPPDATA%\npm-cache`)와 어느 깊이든 맞는 이름(`**\node_modules`) 두 가지만 지원한다. 정규식은 쓰지 않는다.
  - 매칭은 대소문자를 무시하고, `paths::norm`으로 정규화한 뒤 경로 구성요소 경계에서 비교한다.
- **조건(`when`)**: 같은 이름이 다른 뜻일 때를 가른다.
  - `sibling_exists: ["package.json"]`: 예를 들어 `**\target`은 옆에 `Cargo.toml`이 있을 때만 Rust 빌드 산출물이다.
  - `not_inside: ["%LOCALAPPDATA%\\Packages"]`: 이 경로 아래에서는 규칙이 걸리지 않는다.
    - 예: `**\node_modules`의 `not_inside`는 `%LOCALAPPDATA%\Packages`, `%LOCALAPPDATA%\Programs`, `%APPDATA%\npm`, `%ProgramFiles%`, `%ProgramFiles(x86)%`다. Electron 앱의 `resources\app\node_modules`와 전역 npm 패키지(`%APPDATA%\npm\node_modules`)는 지우면 앱이나 명령이 깨지므로 "안전"으로 잡히면 안 된다.
  - 조건은 스캔이 이미 읽은 디렉터리 목록만으로 판정한다. 파일을 열지 않는다.
- **동기화**:
  - 실행할 때마다 내장 `rules.json`의 버전과 DB의 `builtin_version`을 비교한다. 내장 버전이 다르면 `source=builtin` 행을 통째로 바꾼다. `source=user` 행은 건드리지 않는다.
  - 내장 JSON이 깨졌으면 앱을 멈추지 않고 규칙 없이 동작한다(전부 `unknown`). 화면에는 경고를 띄운다.
- **초기 규칙**(T2에서 확정. 출처 문서 링크만 남기고, BleachBit 등에서 복사하지 않는다):

| 묶음 | 패턴 | 등급 | action | 대상 |
| --- | --- | --- | --- | --- |
| 개발·AI | `%LOCALAPPDATA%\npm-cache` | 안전 | quarantine | 폴더 |
| 개발·AI | `%LOCALAPPDATA%\pip\Cache` | 안전 | quarantine | 폴더 |
| 개발·AI | `%LOCALAPPDATA%\uv\cache` | 안전 | quarantine | 폴더 |
| 개발·AI | `%LOCALAPPDATA%\pnpm\store` | 아마 안전 (프로젝트 재설치 필요) | quarantine | 폴더 |
| 개발·AI | `%USERPROFILE%\.gradle\caches` | 안전 | quarantine | 폴더 |
| 개발·AI | `**\node_modules` (옆에 `package.json`; `%LOCALAPPDATA%\Packages`·`%LOCALAPPDATA%\Programs`·`%APPDATA%\npm`·Program Files 안은 제외) | 안전 (`npm install`로 복구) | quarantine | 폴더 |
| 개발·AI | `**\.next` (옆에 `package.json`) | 안전 | quarantine | 폴더 |
| 개발·AI | `**\target` (옆에 `Cargo.toml`) | 안전 (`cargo build`로 복구) | quarantine | 폴더 |
| 개발·AI | `%USERPROFILE%\.cache\huggingface` | 아마 안전 (다시 받기) | quarantine | 폴더 |
| 개발·AI | `%USERPROFILE%\.ollama\models` | 아마 안전 (`ollama pull`로 다시 받기) | quarantine | 폴더 |
| Windows | `%LOCALAPPDATA%\Temp` | 안전 | quarantine | 7일 넘은 항목만 |
| Windows | `%LOCALAPPDATA%\Programs\*` (사용자별 설치 앱 폴더 각각) | 모름 (설치된 앱. 앱 제거로 해결) | uninstall_app (선택 불가) | 폴더 |
| Windows | `%LOCALAPPDATA%\Google\Play Games` | 아마 안전 (앱 제거 권장) | quarantine | 폴더 |
| Windows | `%USERPROFILE%\Downloads` | 사용자 데이터 | quarantine (경고) | 폴더 |

- `contents_older_than` 규칙은 폴더 전체가 아니라 기준일보다 오래된 하위 항목의 크기만 확보 대상으로 표시한다. 크기는 목록 정보의 수정일로 계산한다. Temp 폴더 자체는 선택할 수 없고, "7일 넘은 항목 N GB"가 선택 단위가 된다.

### 시스템 폴더 보호 (`protect.rs`)

- **보호 경로**(선택·격리·삭제 불가, 하위 포함):
  - 스캔한 드라이브 루트의 `Windows`, `Program Files`, `Program Files (x86)`, `ProgramData`, `System Volume Information`, `$Recycle.Bin`, `Recovery`, `$WinREAgent`, `PerfLogs`
  - `%SystemRoot%`(C:가 아닐 때 포함)
  - 루트 시스템 파일 `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`
  - 격리함 루트
- **자격 증명 보호 경로**(선택 불가, 하위 포함, S2 전파 대상):
  - Q2의 자격 증명 폴더: `.ssh`, `.aws`, `.gnupg`, `.azure`, `.kube`
  - 브라우저 프로필: `Google\Chrome\User Data`, `Microsoft\Edge\User Data`, `Mozilla\Firefox\Profiles`
  - `%LOCALAPPDATA%\Packages`
  - Windows 자격 증명·키 저장소: `%APPDATA%\Microsoft\Protect`(DPAPI 마스터 키), `%APPDATA%\Microsoft\Credentials`, `%APPDATA%\Microsoft\Crypto`
  - 이 폴더를 품은 상위 폴더(`%LOCALAPPDATA%\Google`, `AppData\Local`, `AppData\Roaming` 등)는 S2에 따라 선택 불가가 된다.
- **통째로 격리 불가**: 드라이브 루트(`C:\`), `C:\Users`, `C:\Users\<사용자>`
- **경로 정규화**:
  - 비교 전에 `\\?\` 접두를 떼고, 끝의 `\`를 정리하고, 대소문자를 무시한다.
  - 8.3 짧은 이름은 `GetLongPathNameW`로 긴 이름으로 바꾼다.
  - 존재하지 않는 경로라 바꿀 수 없으면 보호 쪽으로 판정한다(실패하면 거부).
  - 이 정규화 함수는 M4 격리 커맨드가 그대로 다시 쓴다.
- **S 규칙 중 M3에서 하는 것**(선택 단계 판정과 단위 테스트):

| 규칙 | M3에서 하는 일 | M4에서 더할 일 |
| --- | --- | --- |
| S2 [R2-6] | 스캔이 하위 트리의 보호 대상을 위로 전파한다. 그런 폴더는 선택 불가로 표시하고 이유를 보여준다. 1 GiB 기준 아래 하위도 놓치지 않도록 `contains_protected` 플래그는 크기와 무관하게 전파한다. 보호 대상(S9의 링크는 제외): 시스템 보호 경로, 동기화 루트, `.vhdx`·`.vhd`·`.vmdk`, 격리함 루트, **자격 증명 보호 경로**(아래). 예: `%LOCALAPPDATA%\Google`이나 `AppData\Local`은 크롬 프로필을 품으므로 "모름+경고"로도 선택할 수 없다. | 격리 직전 재검사(S3) |
| S7 | 동기화 루트 안의 노드는 선택 불가(`in_sync_root`, M2에서 표시) | 격리 직전 재검사 |
| S8 | (M2 완료) 클라우드 파일은 어디서도 열지 않음 | 삭제 경로 검사 |
| S9 | 리파스 포인트 폴더 자체는 선택 불가 | — |
| S11 | `.vhdx` 등 가상 디스크와 그것을 품은 폴더는 선택 불가(`explain_only` + "직접 할 일" 안내 문구) | 격리 직전 재검사 |
| S3·S12 | 판정 함수 `check_item(path, scan_snapshot) -> Result<(), Refusal>`을 만들고 단위 테스트한다 | 격리·복원 커맨드에서 호출 |

- **git 저장소**: 스캔 중에 `.git` 항목이 있는 폴더를 저장소 루트로 표시한다. 그 폴더와 모든 상위 폴더를 `user_data`로 고정한다(SPEC 안전 규칙). 저장소 안의 하위 폴더는 규칙을 따른다.
  - **규칙에 걸린 폴더 안에서 발견된 `.git`은 상위로 전파하지 않는다.** 예: git 의존성으로 받은 `node_modules\<패키지>\.git`, Cargo의 git 체크아웃, 캐시 안의 저장소 사본. 전파하면 그 `node_modules`와 상위 프로젝트 폴더 전체가 `user_data`로 고정되어 SPEC M3 기준("저장소 안 `node_modules`는 안전")이 깨진다.
  - 전파를 멈추는 지점은 규칙에 걸린 폴더다. 그 폴더 아래의 `.git`은 저장소 루트 표시도 하지 않는다(결과 트리에 올리지 않으므로 표시할 노드도 없다).
- **큰 민감 파일**: `.vhdx`, `.vhd`, `.vmdk`, `.pst`, `.ost`, `.kdbx` 파일이 합쳐서 1 GB 이상인 폴더는 `user_data`로 고정한다. 크기는 확장자별 정확한 합을 따로 센다. M2의 확장자 맵은 상위 32개만 남기므로 그것으로는 셀 수 없다.

### 스캔 변경 (`walk.rs`)

- **규칙에 걸린 폴더**: 크기는 끝까지 재지만, 그 아래 노드는 결과 트리에 올리지 않는다(SPEC). 노드에 `rule_id`를 붙인다.
- **묶음**: 규칙에 걸린 폴더는 1 GiB 기준 아래라도 `RuleGroup { rule_id, count, logical_bytes, members: [node_id] }`에 모은다. 묶음의 개별 폴더는 크기와 관계없이 펼쳐서 볼 수 있어야 하므로, 규칙에 걸린 노드는 기준과 관계없이 남긴다(`pinned`처럼).
  - 수만 개일 때 결과 크기가 커질 수 있다. 묶음 구성원 수에 상한을 둘지 eng 리뷰에서 정한다.
- **상향 전파**: 보호 대상 포함(S2), 저장소 루트 포함, 동기화 루트 포함을 M2의 `partial`처럼 자식에서 부모로 올린다. 단, 저장소 루트 포함은 규칙에 걸린 폴더를 넘어 올리지 않는다(위 "git 저장소"). 보호 대상 포함(S2)은 규칙에 걸린 폴더를 넘어서도 올린다. 보호 대상은 어디에 있든 막아야 하기 때문이다.
- 판정은 순회가 끝난 뒤 트리 위에서 한 번 한다. 순회 중에는 규칙 판정에 필요한 사실(이름, 옆 파일 존재 여부, `.git` 존재, 확장자별 합)만 모은다.

### 선택 정책과 합계

- 기본 체크: 규칙 DB의 "안전" 판정만. 안전 규칙·AI 판정은 기본 해제다.
- 체크할 수 없는 경우:
  - 보호 대상, `action ≠ quarantine`, 동기화 루트 안, 리파스 포인트 폴더, 보기 전용 볼륨(C: 이외)
  - 자격 증명 보호 경로(자격 증명·브라우저 프로필·`%LOCALAPPDATA%\Packages`·`%APPDATA%\Microsoft\{Protect,Credentials,Crypto}`)와 그 하위 전부(Q2, U1), 그리고 이를 품은 상위 폴더(S2)
  - `%LOCALAPPDATA%\Programs` 하위(설치된 앱, `uninstall_app`)
  - 확보량이 "계산 중"이거나 "취소됨"(D13)
- 체크하면 경고 모달이 뜨는 경우: 그 밖의 "사용자 데이터"와 "모름"(Q2)
- **부모·자식 배제**: 부모를 체크하면 자식은 비활성화된다. 판정은 Rust가 하고(`toggle_select`), 화면은 결과만 그린다.
- **체크하거나 펼칠 때 `exclusive_bytes` 계산**:
  - 허용 목록 밖 폴더는 체크하는 순간 계산을 시작한다. 그동안 "계산 중"으로 표시하고 선택은 보류한다. 값이 나오면 선택된다(설계 문서).
  - 속도 실측(Open Question): `node_modules` 수만 개 파일 기준 시간을 T4에서 잰다.
- **선택 합계(R2-3)**:
  - 합계는 선택 항목 각각의 exclusive를 더하지 **않는다**. 선택 항목 전체의 **합집합 범위**에서 다시 계산한다.
  - 파일의 링크가 모두 합집합 범위 안에 있으면 확정 값으로 센다. 예: pnpm 저장소와 프로젝트 `node_modules`를 함께 고르면, 둘 사이에서만 하드링크된 파일이 합계에 들어간다.
  - 구현은 `accounting::Scope`를 여러 루트로 넓혀 같은 코드를 다시 쓴다. 부모·자식 동시 선택은 막혀 있으므로 범위가 겹치지 않는다.
  - 표시: "비우면 N GB 확보 (확정) + 미검증 M GB (최대치)". 실제 확보와 미검증을 나눠 표시한다(Q3).

## 화면 (디자인 리뷰 대상)

- **열**: 등급 배지, 근거 한 줄, 출처(안전규칙 / 규칙). M2의 "—" 자리를 채운다.
- **묶음 행**: `node_modules × 143개, 18.2 GB`. 펼치면 구성원 목록이 나오고, 체크하면 묶음 전체를 선택한다(부모·자식 배제를 따른다).
- **선택 합계 바**(상단): SPEC "4. 메인 화면"의 "비우면 N GB 확보"와 "격리함에 있는 용량(아직 공간 차지 중)"이다. 격리함은 M4부터 값이 생기며, M3에서는 0 또는 숨김이다(디자인 리뷰에서 결정).
- **경고 모달**: "사용자 데이터"와 "모름"을 체크할 때 뜬다. 안전 규칙이 고정한 사용자 데이터(Documents 등, 저장소 루트)에 일반보다 강한 형태를 쓸지 정한다(Q2).
- **"실제 확보 + 미검증" 표시**(Q3): 크기 칸과 합계 바 모두 두 값을 나눠 보여준다. 배치와 강조는 디자인 리뷰에서 정한다.
- **네 종류 카드**(설계 문서: "첫 화면은 네 종류 카드"): 스캔 뒤 (1)~(4)별 합계와 대표 항목을 보여준다. 표와의 관계(카드가 필터 역할을 하는지)는 디자인 리뷰에서 정한다. (2) 카드의 공식 도구 안내는 M3에서 글로만 보여준다. 딥링크·명령 복사는 M6이다.
- **선택 불가 이유**: 비활성 체크박스에 마우스를 올리면 이유를 보여준다("시스템 (보호됨)", "자격 증명·앱 데이터 (보호됨)", "동기화 폴더 안", "링크", "가상 디스크 포함", "계산 중").
- 크기 숫자는 "결정됨"의 단위 규칙(1024 + GB, 바이트 툴팁)을 따른다.

## 테스트

픽스처는 M2처럼 `C:\ClearCache_TestZone\scan-tests\<무작위>`에만 만든다. 테스트 이름에 규칙 번호를 붙인다(예: `s2_folder_containing_vhdx_not_selectable`).

- **판정 우선순위(SPEC M3 기준)**:
  - `%LOCALAPPDATA%\npm-cache` 모양의 픽스처는 "안전"이다(환경 변수 주입).
  - 저장소 안의 `node_modules`는 "안전"이고, 저장소 루트와 그 상위는 "사용자 데이터"다.
  - `node_modules\<패키지>\.git`(git 의존성)이 있어도 그 `node_modules`는 "안전"이고, 그 `.git`은 상위로 전파되지 않는다. 저장소 루트 판정은 프로젝트 자체의 `.git`으로만 한다.
  - 규칙이 여러 개 걸리면 가장 구체적인 규칙이 이긴다.
  - 안전 규칙이 고정한 폴더 자체는 규칙으로 바꿀 수 없다.
- **패턴(`pattern.rs`)**: 환경 변수 전개, `**\name`, 구성요소 경계(`node_modules2`는 불일치), 대소문자, `when` 조건(옆 파일 있음/없음).
- **`not_inside`**: `%LOCALAPPDATA%\Programs\<앱>\resources\app\node_modules`(옆에 `package.json` 있음), `%APPDATA%\npm\node_modules`, `Program Files\<앱>\...\node_modules`는 "안전"이 아니다. `%LOCALAPPDATA%\Programs\<앱>`은 `uninstall_app`이고 선택 불가다.
- **규칙 DB**:
  - 버전이 올라가면 내장 규칙이 바뀌고 사용자 규칙은 남는다.
  - 같은 버전이면 아무것도 바꾸지 않는다.
  - JSON이 깨졌으면 규칙 없이 동작하고 경고 플래그가 선다.
  - 테스트 DB는 픽스처 폴더에 만든다.
- **보호(`protect.rs`)**: 보호 경로마다 대소문자, 끝 `\`, `\\?\` 접두, 8.3 이름(`PROGRA~1`; 8.3 생성이 꺼진 볼륨이면 건너뛰고 기록) 변형. 드라이브 루트와 사용자 폴더 루트. `%SystemRoot%`가 C:가 아닐 때. 정규화 실패 시 거부.
- **S2**: 하위에 가짜 동기화 루트, `.vhdx`, 격리함 이름 폴더, 시스템 보호 경로, 자격 증명 보호 경로(예: 가짜 `Google\Chrome\User Data`, `Microsoft\Protect`)가 있는 폴더는 선택 불가다. 1 GiB 기준 아래에 숨은 경우도 포함한다. 예: 가짜 `%LOCALAPPDATA%\Google`은 규칙이 없어도("모름") 선택이 거부된다.
- **S7·S9·S11**: 동기화 루트 안 노드, 정션 폴더, `.vhdx`를 품은 폴더는 선택 불가다.
- **S3·S12 판정 함수**: 스캔 뒤 폴더를 정션으로 바꾸거나 동기화 루트를 추가하면 `check_item`이 이유와 함께 거부한다(M4가 이 함수를 그대로 쓴다).
- **선택 정책**: 기본 체크는 규칙 "안전"만이다. 부모를 체크하면 자식은 비활성화된다. "계산 중/취소됨"은 선택이 거부되고 합계에서 빠진다(D13). 자격 증명 폴더와 `Packages` 하위(`LocalCache`, `TempState` 포함)는 규칙이 "안전"으로 걸려도 선택 불가다(Q2, U1).
- **합집합 합계(R2-3)**: 두 선택 항목 사이에서만 하드링크된 파일은 각 항목의 exclusive에는 0이지만, 합집합 합계에는 들어간다.
- **일부 미검증(R2-4/Q3)**: 열기 실패를 주입하면 `unverified_bytes`가 따로 잡히고, 합계의 "최대치" 칸으로 간다.
- **화면 로직(Vitest)**: 등급 배지 매핑, 선택 불가 이유 문구, 합계 바 문구(확정 + 최대치), 묶음 행 정렬.

## 검증

1. `cargo test`, `cargo clippy`, `npm test`, `npm run build`
2. 소유자 PC에서 사용자 폴더를 스캔해 SPEC M3 기준을 화면으로 확인한다: npm-cache "안전", 저장소 안 node_modules "안전", 저장소 루트 "사용자 데이터", 묶음 행.
3. C: 전체를 스캔해 시스템 항목이 전부 선택 불가이고 이유가 보이는지 확인한다.
4. 체크할 때 하는 exclusive 계산 시간을 `node_modules`가 큰 저장소에서 잰다(Open Question).
5. 사용자에게 화면 확인을 부탁하고, 끝나면 커밋·push 여부를 묻는다.

## 우려 사항 대응표

| 출처 | 내용 | 이 계획에서 |
| --- | --- | --- |
| m2 남은 할 일 | 디자인 리뷰(네 종류 카드 화면) | "화면" 절 전체가 디자인 리뷰 대상. 단위 결정은 "결정됨"으로 옮김 |
| m2 남은 할 일 | 라이선스 확정(규칙 작성 전) | Q5 결정(MIT), T0 표기 정리 |
| R2-3 | 선택 합계 이중 집계, 항목 사이 하드링크 | "선택 정책과 합계": 합집합 범위 |
| R2-4 | 일부 미검증 폴더의 합계 처리 | Q3 결정, `unverified_bytes` |
| R2-8 | 규칙 없는 폴더의 기본 action | Q2 결정 |
| R2-14 | UserAssist 매칭 | Q1: M3 제외, 해결책 기록 |
| R2-15 | 앱 연결 폴백 오류 | Q1: M3 제외, 해결책 기록 |
| 설계 Open Question | 라이선스 최종 확정 | Q5 결정(MIT) |
| 설계 Open Question | 체크·펼칠 때 exclusive 속도 | T4, 검증 4 |
| 설계 Open Question | BAM 읽기 가능 여부(M3) | Q1: M3 제외 |
| SPEC 안전 규칙 | 드라이브 전체 스캔 시 시스템 폴더 보호(M3 구현) | `protect.rs` |
| SPEC 안전 규칙 | 사용자 데이터 고정 목록, git 저장소, 큰 민감 파일 | 판정 우선순위 1, 스캔 변경 |
| SPEC 문구 모순 | "절대 목록에 올리지 않는 경로" vs M2 표시 | Q4 결정, SPEC v1.5 반영 완료 |
| 사용자 요청(2026-10-24) | `Packages` 안 캐시 폴더 개별 허용 가능 여부 | 미결 U1 |
| 사용자 검토(2026-10-24) 1 | 크롬 프로필 등을 품은 상위 폴더가 "모름+경고"로 선택 가능 | S2 보호 대상에 자격 증명 보호 경로 추가(`%APPDATA%\Microsoft\Protect·Credentials·Crypto` 포함) |
| 사용자 검토(2026-10-24) 2 | Electron 앱·전역 npm의 `node_modules`가 "안전"으로 잡힘 | `not_inside` 추가, `%LOCALAPPDATA%\Programs` 하위는 `uninstall_app` |
| 사용자 검토(2026-10-24) 3 | git 의존성 `.git` 때문에 `node_modules`가 `user_data`로 고정 | 규칙에 걸린 폴더 안의 `.git`은 전파하지 않음 |
| 사용자 검토(2026-10-24) 4~10 | 판정 단계, 동시 실행, 묶음 부분 선택, 구체성, Temp 기준일, 감지 실패, `.kdbx` | 미결 U3~U9(eng 리뷰) |
| M2 다음 단계 목록 | 규칙에 걸린 폴더에서 탐색 멈추기, 선택 정책, S2·S3·S9 | 스캔 변경, 선택 정책, 보호 |

## Implementation Tasks

리뷰 전 초안이다. 리뷰 뒤 크기와 순서를 다시 매긴다.

- [ ] **T0** — 라이선스 표기 정리(Q5: MIT 확정). `Cargo.toml`·`package.json`에 `license = "MIT"` 추가, 설계 문서·m2 계획의 "임시" 문구 정리(`LICENSE`와 SPEC은 반영 완료). **이 작업이 끝나기 전에는 `rules.json`을 쓰지 않는다.**
- [ ] **T1** — `protect.rs`: 경로 정규화(8.3 포함), 보호 경로, 루트 보호, `check_item` 판정 함수, S2·S7·S9·S11 판정. 순수 함수 테스트
- [ ] **T2** — 규칙 DB: `rules.json`(초기 규칙 확정), `pattern.rs`, `db.rs`(rusqlite, 버전 동기화), 판정 우선순위 `rules/mod.rs`
- [ ] **T3** — 스캔 변경: 규칙에 걸린 폴더에서 트리 멈춤, 묶음, 상향 전파(보호 포함·저장소·동기화 루트), 확장자별 정확한 합, `.git` 감지
- [ ] **T4** — accounting 확장: 여러 루트 합집합 범위, `unverified_bytes`, 체크할 때 계산(`compute_exclusive`), 속도 실측
- [ ] **T5** — 선택: `selection.rs`, 커맨드(`toggle_select`, `get_selection_total`), D13 규칙
- [ ] **T6** — 화면 로직(Vitest): `src/lib/{grade,selection}.ts`
- [ ] **T7** — 화면: 등급 배지·근거·출처, 묶음 행, 선택 합계 바, 경고 모달, 선택 불가 이유, 네 종류 카드(디자인 리뷰 결과 반영)
- [ ] **T8** — 문서: 구현 결과를 SPEC에 반영(묶음, 선택 합계, 네 종류 카드), 개정 이력. Q2·Q4 문구는 v1.5에서 반영 완료
