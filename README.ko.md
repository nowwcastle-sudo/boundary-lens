# Boundary Lens

[English](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/README.md) | 한국어

Boundary Lens는 Windows에서 작업 폴더 하나와 접근에 실패한 경로 하나를 지정해 경로, 재분석 지점, ACL 증거를 읽는 진단 도구이며 Apache-2.0으로 공개한 실험 단계 소프트웨어입니다. 보고서는 권한 허용 여부나 보안을 인증하지 않으며, 시스템을 복구하지도 않습니다. 종료 코드 `0`은 보고서를 만들었다는 뜻입니다.

Windows x64와 보안 업데이트가 제공되는 PowerShell 7이 필요합니다. 로컬 NTFS/ReFS 경로를 받지만, 실제 ReFS 환경과 모든 기업 정책에서 동작을 인증한 것은 아닙니다. 설치 프로그램이나 서비스가 없으며, 관리자 권한이나 실행 중 의존성 설치도 필요하지 않습니다. 정책이 네이티브 연동을 막으면 수집 실패로 표시합니다. 정책을 완화하거나 경로 이름만으로 수집하는 우회 방식을 쓰지 마세요.

Windows 앱이 로컬 경로에 접근하지 못할 때, 담당자와 원인을 검토할 증거를 모으는 데 사용합니다. ACL(접근 제어 목록)은 파일이나 폴더에 붙은 권한 항목입니다. 재분석 지점은 정션이나 심볼릭 링크처럼 경로를 다른 대상으로 연결할 수 있는 파일시스템 항목입니다. 사용자가 입력한 경로, 관측한 대상, 확인하지 못한 사실을 따로 보존합니다.

## 기능과 옵션

| 기능 | 입력·옵션 | 얻는 결과 | 한계 |
|---|---|---|---|
| 사건 하나 조사 | 필수 `-Workspace`, `-FailedPath` | 두 경로의 경로·ACL 증거 | 작업 폴더 전체를 재귀 조사하거나 파일 내용을 분석하지 않음 |
| 로컬 경로 입력 | 한 글자 드라이브명으로 시작하는 로컬 NTFS/ReFS 절대 경로, 공백뿐인 입력은 불가 | 원래 입력과 문법적으로 정규화한 경로를 따로 보존 | 상대 경로·공급자 지정 경로·예약 DOS 장치명·UNC·원격 URI·WSL 형식·확인된 UNC 연결 드라이브 거부 |
| 경로 연결 관측 | 존재하는 경로 구성 요소와 지원하는 재분석 지점 | 최종 경로, 재분석 관측, 작업 폴더 안팎의 논리적·최종 관계 | 대상 누락·미지원 대상·경로 구조 변화는 수집 공백으로 남음. 자동 복구 없음 |
| ACL 메타데이터 관측 | 열린 객체에서 읽은 보안 설명자 | 일부 식별자 지문과 접근 마스크 | 실제 유효 권한이나 전체 상속 관계를 판정하지 않음. 미지원 ACL 형식은 공백으로 남음 |
| 화면에서 읽기 | `-Format Text`(기본값) | 증거 레코드 4개의 집계와 상태·코드·증거 참조·다음 관측 | 집계는 수집 현황이며 안전 판정이 아님 |
| 상세 증거 보관 | `-Format Json` | `schema_version = 1`, `incident`, `evidence`, `results`가 있는 압축 JSON | 표준 출력으로만 전달. 저장과 검토는 사용자가 수행 |
| 다음 조사 안내 | 결과 행 | 관측 관계가 뒷받침할 때 `REPARSE_TARGET_MISMATCH` 원인 후보와 실패·미확인 항목 | 원인 확정이 아님. `RUNTIME_ENFORCEMENT_UNKNOWN`은 남음 |
| PowerShell에서 호출 | 스크립트를 dot-source한 뒤 `Invoke-BoundaryLens` 호출 | 같은 보고서 형식과 로컬 도움말 | 일반 PowerShell 종료 오류가 발생할 수 있음. 고정 지원 오류는 직접 프로세스 실행에서 제공 |

`-Workspace`는 사건의 작업 폴더 루트, `-FailedPath`는 접근에 실패한 원래 경로입니다. 출력 폴더를 지정하는 옵션이 아닙니다. 직접 실행할 때 세 옵션의 순서와 대소문자는 자유지만, 축약·중복·알 수 없는 옵션·위치 인자·콜론으로 붙인 옵션은 거부합니다. 출력 파일 옵션은 없으므로 아래 저장 절차를 사용하세요.

## 처음 시작하기

Windows x64에서 일반 사용자 권한으로 PowerShell 7(`pwsh`)을 여세요. Windows PowerShell 5.1은 대상 런타임이 아닙니다. 승인된 PowerShell 7 설치본을 사용하고 정책 제한은 그대로 두세요. 네이티브 연동을 차단하는 정책에서는 수집하지 못할 수 있습니다.

같은 PowerShell 창에서 **다운로드 → 검증·압축 해제 → 합성 예제로 첫 실행** 순서로 한 줄씩 실행하세요. 앞 단계의 변수를 다음 단계에서도 사용합니다. 저장소 복제본으로 패키지를 만들려는 경우에만 소스 빌드 절차를 선택하면 됩니다. 먼저 결과를 읽고 그다음 저장·공유 여부를 판단하세요. 다운로드 명령은 GitHub에 접속합니다. 진단 도구에는 보고서를 업로드하는 기능이 없지만, 네트워크 격리가 필요하면 아래 제한도 확인해야 합니다.

영문과 한국어 README는 저장소 문서이며 고정 릴리스 `v0.2.0-experimental.1` ZIP 안의 README보다 최신일 수 있습니다. 그 ZIP에는 파일 4개가 들어 있으며 `README.ko.md`는 포함하지 않습니다. 이번 문서 변경으로 릴리스의 스크립트·압축 파일·공개 체크섬을 바꾸지 않습니다.

## 실험 릴리스 다운로드

릴리스: [v0.2.0-experimental.1](https://github.com/nowwcastle-sudo/boundary-lens/releases/tag/v0.2.0-experimental.1).
GitHub 계정 없이 내려받을 수 있습니다. PowerShell 7에서 실행하세요.

```powershell
$boundaryAssets = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-download-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $boundaryAssets -ErrorAction Stop | Out-Null
$boundaryRelease = 'https://github.com/nowwcastle-sudo/boundary-lens/releases/download/v0.2.0-experimental.1'
$boundaryZip = Join-Path $boundaryAssets 'boundary-lens-0.2.0-experimental.1.zip'
Invoke-WebRequest -Uri "$boundaryRelease/boundary-lens-0.2.0-experimental.1.zip" -OutFile $boundaryZip -ErrorAction Stop
Get-FileHash -LiteralPath $boundaryZip -Algorithm SHA256
```

계속하기 전에 ZIP의 전체 SHA-256을 해당 릴리스 설명에 있는 값과 비교하세요. 이전 릴리스의 체크섬을 대신 쓰면 안 됩니다. 실패한 폴더와 로그는 보존하고, 덮어쓰기나 `--clobber` 옵션으로 재시도하지 마세요. 체크섬 일치는 파일 바이트가 같다는 뜻이며 안전을 인증하지 않습니다.

## 검증과 압축 해제

압축 파일에는 스크립트, LICENSE, README, SHA256SUMS 파일이 정확히 4개 있어야 합니다. 먼저 파일명을 확인하고 압축을 푼 뒤, 체크섬 파일에 적힌 본문 파일 3개의 해시를 확인합니다.

```powershell
$boundaryArchive = [IO.Compression.ZipFile]::OpenRead($boundaryZip)
try {
    $expectedMembers = @('BoundaryLens.ps1', 'LICENSE', 'README.md', 'SHA256SUMS.txt')
    $actualMembers = @($boundaryArchive.Entries | ForEach-Object FullName | Sort-Object)
    if (($actualMembers -join ',') -cne (($expectedMembers | Sort-Object) -join ',')) {
        throw 'Unexpected archive member set; preserve the ZIP and stop.'
    }
} finally { $boundaryArchive.Dispose() }
$extractDir = Join-Path $boundaryAssets ('extracted-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $extractDir) { throw 'Extraction directory already exists; stop.' }
New-Item -ItemType Directory -Path $extractDir -ErrorAction Stop | Out-Null
Expand-Archive -LiteralPath $boundaryZip -DestinationPath $extractDir -ErrorAction Stop
$sums = @(Get-Content -LiteralPath (Join-Path $extractDir 'SHA256SUMS.txt') -ErrorAction Stop)
if ($sums.Count -ne 3) { throw 'Expected exactly three checksum entries.' }
$seenNames = @{}
foreach ($line in $sums) {
    if ($line -notmatch '^([A-Fa-f0-9]{64})  (BoundaryLens\.ps1|LICENSE|README\.md)$') { throw 'Unexpected checksum entry.' }
    $expected = $Matches[1]
    $name = $Matches[2]
    if ($seenNames.ContainsKey($name)) { throw 'Duplicate checksum entry.' }
    $seenNames[$name] = $true
    if ((Get-FileHash -LiteralPath (Join-Path $extractDir $name) -Algorithm SHA256 -ErrorAction Stop).Hash -ine $expected) {
        throw 'Checksum mismatch; stop use.'
    }
}
Set-Location -LiteralPath $extractDir
```

## 소스에서 빌드

저장소를 복제한 폴더에서 기존 패키징 스크립트를 사용합니다. 출력 폴더는 시스템 임시 폴더 바로 아래의 새 폴더여야 하며, 예제의 접두어를 사용해야 합니다.

```powershell
$boundaryCandidate = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-package-candidate-' + [guid]::NewGuid().ToString('N'))
pwsh -NoProfile -NonInteractive -File .\tests\package.ps1 -OutputDirectory $boundaryCandidate
if ($LASTEXITCODE -ne 0) { throw 'Package preparation failed; preserve the directory.' }
Set-Location -LiteralPath $boundaryCandidate
```

결과에는 ZIP과 단독 실행용 스크립트가 포함되며 두 스크립트의 바이트는 같습니다. 아래 합성 예제로 첫 실행을 진행하세요. 빌드 시각과 README 바이트가 달라질 수 있으므로, 소스 빌드 결과를 다른 릴리스의 ZIP 해시와 비교하지 마세요.

새 소스 빌드 후보 ZIP에는 `BoundaryLens.ps1`, `BoundaryIncident.ps1`, `IncidentInput.psm1`, `IncidentObservations.psm1`, `IncidentHandoff.psm1`, `LICENSE`, `README.md`, `SHA256SUMS.txt`가 정확히 들어갑니다. 이미 공개된 `v0.2.0-experimental.1` ZIP은 아래 검증 절차대로 4개 파일이며, 이번 소스 변경으로 그 파일이나 체크섬을 교체하지 않습니다.

## 합성 예제로 첫 실행

검증한 스크립트가 있는 폴더에서 실행합니다. 아래 준비 명령은 새 연습 폴더와 파일 하나를 씁니다. 사용자가 준비하는 단계이며 읽기 전용 진단과 별개입니다. 기존 사건 데이터를 사용하지 않고, 도구가 실행 후 파일을 삭제하지도 않습니다.

```powershell
$demo = Join-Path ([IO.Path]::GetTempPath()) ('boundary-lens-demo-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $demo) { throw 'Synthetic directory already exists; stop.' }
New-Item -ItemType Directory -Path $demo -ErrorAction Stop | Out-Null
Set-Content -LiteralPath (Join-Path $demo 'synthetic.txt') -Value 'Boundary Lens synthetic example only.' -Encoding utf8
```

진단을 실행한 직후 프로세스 종료 코드를 저장합니다.

```powershell
pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Text
$existingExit = $LASTEXITCODE
$existingExit
```

## 인계용 JSON 보고서 저장

검증한 `BoundaryLens.ps1`이 있는 폴더에서 아래 명령을 실행하세요. 도구는 지정한 입력을 읽고, 현재 PowerShell 세션이 보고서 파일을 만듭니다. 출력 폴더는 조사하는 입력 폴더(여기서는 `$demo`)와 원래 사건 폴더 밖에 두세요.

1. 별도 출력 폴더와 새 보고서 이름 2개를 정합니다. 지정된 ENVIRONMENT 출력 폴더를 사용하는 평가자는 `$boundaryOutput` 대입문의 오른쪽만 교체할 수 있습니다. 나머지 줄은 유지합니다.

```powershell
$boundaryOutput = Join-Path ([IO.Path]::GetTempPath()) ('boundary-reports-' + [guid]::NewGuid().ToString('N'))
if (-not (Test-Path -LiteralPath $boundaryOutput -PathType Container)) { New-Item -ItemType Directory -Path $boundaryOutput -ErrorAction Stop | Out-Null }
$reportRun = [guid]::NewGuid().ToString('N')
$existingReport = Join-Path $boundaryOutput ("boundary-existing-$reportRun.json")
$missingReport = Join-Path $boundaryOutput ("boundary-missing-$reportRun.json")
```

2. 존재하는 파일의 JSON을 생성한 직후 종료 코드를 저장하고, `0`일 때만 보고서를 저장합니다.

```powershell
$existingJson = & pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Json
$existingExit = $LASTEXITCODE
$existingExit
if ($existingExit -ne 0) { throw "Existing-file diagnostic failed with exit $existingExit; preserve the output directory and stop." }
$existingJson | Out-File -LiteralPath $existingReport -Encoding utf8 -NoClobber -ErrorAction Stop
```

3. 없는 파일의 JSON은 별도로 만듭니다. 해당 입력 파일을 만들거나 앞 보고서 경로를 재사용하지 마세요.

```powershell
$missingJson = & pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'missing.txt') -Format Json
$missingExit = $LASTEXITCODE
$missingExit
if ($missingExit -ne 0) { throw "Missing-file diagnostic failed with exit $missingExit; preserve the output directory and stop." }
$missingJson | Out-File -LiteralPath $missingReport -Encoding utf8 -NoClobber -ErrorAction Stop
```

4. 저장된 파일 2개를 JSON으로 다시 읽습니다. 인계 전 해석과 다음 관측 항목을 로컬에서 검토하세요.

```powershell
$existingSaved = Get-Content -Raw -LiteralPath $existingReport | ConvertFrom-Json -ErrorAction Stop
$missingSaved = Get-Content -Raw -LiteralPath $missingReport | ConvertFrom-Json -ErrorAction Stop
$existingSaved.results | Select-Object status, code, next_observation
$missingSaved.results | Select-Object status, code, next_observation
$existingReport
$missingReport
```

두 보고서에는 `RUNTIME_ENFORCEMENT_UNKNOWN`이 남아야 합니다. 정적 증거만으로 실행 중 권한 경계가 실제로 적용되는지 알 수 없습니다. 전체 JSON에는 경로와 환경 정보가 들어갈 수 있으므로 특히 `incident.workspace_input`, `incident.failed_path_input`, `incident.observed_at`을 확인하세요. 저장한 증거 원본은 보존하고, 공유가 승인되었다면 별도 사본에서 필요한 정보만 남긴 뒤 로컬에서 검토하세요. 위 명령은 보고서를 전송하지 않으며 공유해도 안전하다는 판정도 하지 않습니다.

### 사건 전달본 만들기 (새 소스 빌드 후보 전용)

위 절차로 저장한 `$existingReport`를 사용합니다. 동반 도구는 기존 JSON만 읽고 진단기나 다른 제품을 자동으로 실행하지 않습니다. 후보 파일 8개는 같은 폴더에 두세요.

```powershell
$incidentPath = Join-Path $boundaryOutput ("incident-$([guid]::NewGuid().ToString('N')).json")
if (Test-Path -LiteralPath $incidentPath) { throw 'Incident file already exists; stop.' }
[IO.File]::WriteAllText($incidentPath, '{"schema":"boundary-incident/1","product":"synthetic example"}', [Text.UTF8Encoding]::new($false))
$handoffPath = Join-Path $boundaryOutput ("handoff-$([guid]::NewGuid().ToString('N')).json")
pwsh -NoProfile -NonInteractive -File .\BoundaryIncident.ps1 -CoreReport $existingReport -Incident $incidentPath -Output $handoffPath -Format Json
$handoffExit = $LASTEXITCODE
$handoffExit
```

로컬 `.json`·`.jsonl` 로그는 `-LogPath FILE`을 반복해서 지정할 수 있습니다. 자동 검색은 하지 않습니다. `-Format Html`을 쓰면 외부 자원과 스크립트가 없는 정적 HTML 파일을 만듭니다. 종료 코드 `0`은 요청한 전달본을 만들었고 추가 관측에 실패가 없다는 뜻, `1`은 수집·저장 실패 또는 불완전한 전달본 생성, `2`는 옵션·스키마·경로 거부입니다. 불완전한 파일이 만들어졌다면 그대로 보존하고 검토하세요. 출력은 조사 경로 밖의 새 로컬 파일이어야 하며 기존 파일을 덮어쓰지 않습니다.

현재 작업 폴더의 실제 경계를 확인할 수 없으면 파일을 만들기 전에 전달본 저장을 거부합니다. 접근에 실패한 대상이 없는 경우에는 가장 가까운 기존 상위 폴더를 확인할 수 있어야 합니다. 이 조건 때문에 전달본을 만들지 못할 수 있으므로, 원래 진단 JSON은 보존해 조사에 사용하세요.

전달본은 알려진 결과·상태 코드, 경로 별칭, 자료 출처와 `UNKNOWN`을 남깁니다. 전달본에서는 제품명·버전·오류 문자열·프로세스명·필터·런타임·로그 문자열을 원문 대신 사건 안에서만 쓰는 별칭으로 바꿉니다. 원문은 별도의 로컬 입력 파일에 남습니다. 따라서 기본 전달본만으로 제품을 알아볼 수 없는 손실이 있습니다. 전달본은 최소화본이지 익명본이 아닙니다. 시각과 파일시스템 크기 정보도 사건을 식별할 수 있고, 허용 목록 밖의 자유 입력 문자열은 비밀값이 없다고 보장할 수 없습니다. 공유하기 전에 실제 파일을 직접 확인하세요. 자세한 계약은 [로컬 사건 안내](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/docs/local-incident.md)를 참고하세요.

### 단독 스크립트

검증한 스크립트를 직접 실행합니다. 재배포할 때는 LICENSE를 함께 두세요.

### ZIP 패키지

릴리스 ZIP에는 BoundaryLens.ps1, LICENSE, README.md, SHA256SUMS.txt가 들어 있습니다. 과거 비공개 릴리스의 파일명·해시·파일 3개 구성을 재사용하지 마세요. 이 저장소는 별도의 공개 이력으로 시작했으며, 비공개 개발 기록과 산출물은 공개 릴리스에 포함되지 않습니다.

## 결과 읽기

| 프로세스 종료 코드 | 뜻 | 다음 행동 |
|---|---|---|
| `0` | 보고서 생성. 수집 실패나 미확인 항목이 있어도 가능 | `results`와 `next_observation`을 읽고 종료 코드만으로 사건을 종결하지 않음 |
| `2` | 잘못된 입력(`BOUNDARY_INPUT_INVALID`) 또는 거부한 원격 입력(`BOUNDARY_REMOTE_UNSUPPORTED`) | 옵션 전체 이름과 원래 로컬 절대 경로를 확인하고 원래 오류를 보존 |
| `3` | 예상하지 못한 제품 오류(`BOUNDARY_INTERNAL_ERROR`) | 로컬 증거를 보존하고 고정 코드·종료 코드·승인된 버전/해시 정보로 비공개 지원 요청 |

JSON의 `evidence`에는 `workspace_path`, `failed_path`, `workspace_acl`, `failed_path_acl`, `path_relation`이 있습니다. `results`에는 분류한 실패·원인 후보·미확인 항목이 들어갑니다. 관측 레코드는 `evidence`에 있으며, Text 형식은 먼저 집계한 뒤 결과 행을 출력합니다.

- `observed`: 해당 탐침이 증거를 수집했습니다.
- `cause-candidate`: 증거가 제한된 원인 유형과 부합합니다. 근본 원인을 확정한 것은 아닙니다.
- `collection-failure`: 탐침이 필요한 관측을 얻지 못했습니다. 그 속성이 없거나 정상이라는 뜻은 아닙니다.
- `unknown`: 현재 증거로는 그 사실을 확인하지 못했습니다.

현재 수집기는 네이티브 핸들로 객체를 열린 상태로 유지한 채 검증한 로컬 경로 구성 요소를 탐색합니다. 볼륨을 포함한 객체 식별자와 관측한 상위 경로 관계를 비교합니다. 수집한 확인 결과가 서로 모순되거나 재검증에 실패하면 최종 포함 관계는 null로 남습니다. 갱신 중 새로 발견한 대상으로 따라 들어가지 않습니다.

최종·재분석·가장 가까운 경로는 \Device\HarddiskVolumeN\folder\file 같은 NT 장치 표기를 사용하며, 원래 입력과 정규화한 경로도 함께 남습니다. 식별자 지문은 이전 방식의 계정 표시명이 아닌 SID 문자열을 해시합니다. 이 두 구현 사이에서 지문을 직접 비교하지 마세요.

ACL 행은 일부 식별자와 접근 마스크 메타데이터입니다. 유효 권한이나 전체 상속 관계의 판정이 아닙니다. 일반 마스크의 권한은 숫자로 표시될 수 있습니다. null/없는 DACL, 조건부·콜백·객체별 ACE 중 미지원 형식은 수집 공백으로 남습니다. `existing_segment_count`는 선언한 경로의 문법상 구성 요소 수이며, 내부 네이티브 열기 횟수나 확장된 대상의 깊이가 아닙니다.

보고서 보관 기간과 위치는 사용자가 정합니다. 도구 자체는 보고서를 저장·업로드·전송하지 않습니다. 네이티브 조회는 읽기 전용이지만 관측으로 접근 시각이 달라질 수 있으며, 컴퓨터 전체가 전혀 바뀌지 않는다고 보장하지 않습니다. 커널·장치 네임스페이스와 설정된 매핑은 신뢰하는 전제입니다. 보고서 전체의 원자적 스냅샷, 모든 파일시스템 필터, 모든 순간적 변화는 다루지 못합니다. 네트워크 격리가 필요하면 외부에서 강제하는 별도 환경을 검증해 사용하세요. 눈에 보이는 원격 입력을 거부한다는 사실만으로 네트워크 통신이 없다고 인증할 수 없습니다.

수집기 버전을 바꿀 때는 PowerShell 프로세스도 새로 여세요. 이미 로드된 네이티브 타입은 수집기 계약과 일치해야 합니다. 이는 실수로 버전이 섞이는 것을 막는 장치이며, 같은 프로세스에서 이미 실행 중인 악성 코드를 막는 장치는 아닙니다.

[네이티브 수집 설계](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/docs/adr/0005-native-identity-collection.md)와
[Windows 호환성](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/docs/compatibility/windows.md) 문서도 참고하세요.

## 예제 해석과 원래 사건 보존

존재하는 파일의 보고서에서는 관측 레코드 4개, `RUNTIME_ENFORCEMENT_UNKNOWN`, 종료 코드 `0`을 예상합니다. 이 수는 수집 현황입니다. 정적 경로·ACL 관측으로 실행 중 권한 경계 적용을 확인할 수는 없습니다.

이번에는 연습용 파일명을 지정하되 파일을 만들지 않고 관측합니다.

```powershell
pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace $demo -FailedPath (Join-Path $demo 'missing.txt') -Format Text
$missingExit = $LASTEXITCODE
$missingExit
```

보고서가 만들어지므로 예상 종료 코드는 여전히 `0`입니다. `TARGET_NOT_OBSERVED`, `FINAL_PATH_UNKNOWN`, `FINAL_CONTAINMENT_UNKNOWN`, `RUNTIME_ENFORCEMENT_UNKNOWN`이 예상됩니다. 미확인 행 4개는 증거의 한계이며 파일은 없는 상태로 남습니다.

존재하는 파일과의 비교가 성공해도 원래의 파일 누락 사건이 해결된 것은 아닙니다. 원래 경로와 보고서를 보존하고, 철자와 그 파일을 만들어야 할 앱을 확인하세요. 제품·버전·원래 오류 코드·발생 시각은 로컬에 기록합니다. 정적 관측으로 원인을 좁히지 못하면 별도 승인을 받아 실행 시점의 증거를 확보해야 합니다.

## 도움말과 고정 지원 오류

직접 프로세스 실행은 필수 `-Workspace`, `-FailedPath`와 선택 `-Format Text` 또는 `-Format Json`을 받습니다. 순서와 대소문자는 자유입니다. 두 경로는 비어 있으면 안 됩니다. 축약·중복·알 수 없는 옵션·위치 인자·콜론으로 붙인 옵션은 거부하며, 상대 경로나 지원하지 않는 경로 형식은 수집 전에 거부합니다.

로컬 호출자는 기존 dot-source API를 사용할 수 있습니다. dot-source는 스크립트의 함수를 현재 PowerShell 세션에 불러오는 방식입니다.

```powershell
. .\BoundaryLens.ps1
Get-Help Invoke-BoundaryLens -Full
Invoke-BoundaryLens -Workspace $demo -FailedPath (Join-Path $demo 'synthetic.txt') -Format Json
```

고정 지원 오류가 필요하면 직접 프로세스 진입점을 사용하세요. 아래는 일부러 잘못된 합성 입력을 넣는 예제이며, 조사 경로 보고서를 만들지 않습니다.

```powershell
pwsh -NoProfile -NonInteractive -File .\BoundaryLens.ps1 -Workspace relative -FailedPath (Join-Path $demo 'synthetic.txt')
$supportExit = $LASTEXITCODE
$supportExit
```

표준 오류 출력은 `BOUNDARY_ERROR code=BOUNDARY_INPUT_INVALID exit=2`뿐입니다. 잘못된 입력과 거부한 원격 입력의 종료 코드는 `2`입니다. 예상하지 못한 제품 결함의 고정 오류 코드는 `BOUNDARY_INTERNAL_ERROR`이고 종료 코드는 `3`입니다. 예상된 수집 실패나 미확인 항목이 있어도 보고서를 만들면 `0`입니다.

비공개 지원에는 고정 코드·프로세스 종료 코드·릴리스/런타임 버전·승인된 해시만 전달하세요. 실제 인자·보고서·조사 문서·ACL 출력은 검토하고 필요한 정보만 남기기 전까지 로컬에 보관합니다. dot-source 호출은 일반 PowerShell 종료 오류를 유지합니다.

이 오류 처리는 PowerShell이 정상 스크립트를 로드한 뒤에만 적용됩니다. 스크립트 누락·손상, 실행 정책 거부, 잘못된 `pwsh` 시작 옵션은 제품 코드 실행 전에 로컬 정보가 포함된 호스트 오류를 출력할 수 있습니다. 해당 오류는 비공개로 보관하고, 숨기기 위해 전역 정책이나 오류 설정을 바꾸지 마세요. 파일 식별 검증에 실패하거나 소유자가 사용을 철회하면 스크립트 호출을 중단하세요. 제거해야 할 설치 서비스나 데이터베이스는 없습니다.

## 메타데이터 증거의 범위

동적 비교 대상은 이름을 지정한 합성 파일의 내용 해시·길이, 그리고 새로 조회한 최종 수정 시각·속성·ACL SDDL입니다. 컴퓨터 전체의 변경 감시나 모든 메타데이터가 그대로라는 증거가 아닙니다. 관측이 접근 시각에 영향을 줄 수 있고, 준비 후 폴더 메타데이터가 뒤늦게 반영될 수도 있습니다. 다른 스냅샷은 보존하고 원인 귀속을 따로 조사하세요.

원래 Boundary B 시험은 `FixtureUnchanged=false`, 제품을 실행하지 않은 대조군은 `Identical=false`를 기록했습니다. 두 기록은 그대로 보존됩니다. 내용·ACL·구성 항목 보존은 관측했지만, 모든 메타데이터가 불변인지와 원래 폴더 수정 시각이 바뀐 원인은 `UNKNOWN`입니다. 나중에 성공한 검사로 실패 증거를 대체하지 않습니다. 합성 실험은 실제 파일럿 재사용이나 지불 의사를 입증하지 않습니다.

## 기여와 제보

합성 데이터만 사용하는 이슈와 PR을 받습니다.
[CONTRIBUTING](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/CONTRIBUTING.md),
[SECURITY](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/SECURITY.md),
[CODE_OF_CONDUCT](https://github.com/nowwcastle-sudo/boundary-lens/blob/main/CODE_OF_CONDUCT.md)를 읽어주세요.

민감한 보안 정보는 비공개 취약점 제보를 이용하세요. 실제 사건 경로·ACL 출력·계정 식별자·인증정보를 공개 이슈에 붙여 넣지 마세요. 유지관리자는 가능한 범위에서 응답합니다.

이 실험 단계 소스 릴리스는 실제 사용자 채택, 향후 사례의 정확도, 법적 정확성, 모든 환경의 지원을 입증하지 않습니다. 라이선스는 Apache License 2.0이며 [LICENSE](LICENSE)를 확인하세요.
