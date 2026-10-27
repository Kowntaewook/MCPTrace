# MCPTrace

Windows·Linux 프로세스 메모리에서 MCP/JSON-RPC 메시지 후보를 추출하는 **Volatility 3 플러그인**.
수집된 메모리 이미지를 분석하고, 메시지 원문·주소·도구 인자·정책 검사 결과를 남깁니다.

**상태: 초기 구현.** 프레임워크 패키지 버전은 `volatility3==2.28.2`로 고정했습니다.
분석 대상은 Windows x64와 Linux x86-64입니다. Windows의 첫 실증 대상은 Windows 11 x64입니다.
현재 검증은 합성 데이터, 실제 Volatility 메모리 레이어·출력기, CLI 플러그인 로딩까지입니다.
실제 Windows/Linux RAM 이미지에서의 복원율과 OS 빌드·커널별 호환성은 아직 검증하지 않았습니다.

| 분석할 이미지 | 명령 | 프로세스 메모리 영역 |
| --- | --- | --- |
| Windows x64 | `windows.mcptrace.MCPTrace` | VAD |
| Linux x86-64 | `linux.mcptrace.MCPTrace` | VMA |

명령의 OS는 **메모리 덤프의 OS**입니다. 분석 프로그램을 실행하는 호스트 OS와 구분합니다.
현재 어댑터는 64비트 Intel/AMD 이미지용이며 ARM·32비트 이미지 지원을 선언하지 않습니다.

## 기능

- Windows `pslist`의 VAD, Linux `pslist`의 VMA에서 UTF-8·UTF-16LE JSON 후보 추출.
- Linux는 프로세스 대표 태스크만 열거하고 Volatility의 `get_vma_iter()`로 메모리 영역 접근.
  사용자 주소 공간이 없는 태스크와 프로세스 레이어를 만들지 못한 태스크는 건너뛴 이유를 기록.
- 문자열 안의 중괄호, 이스케이프, 중첩 객체, 청크 경계 처리. 누락된 페이지와 VAD/VMA 경계는 연결하지 않음.
- MCP 메서드, `tools/call` 도구명과 인자, 응답의 `result`/`error` 보존.
- PID·VAD/VMA 시작 주소·프로세스 가상 주소·인코딩·원문 SHA-256 표시.
- 동일 PID와 **타입까지 같은 요청 ID**를 기준으로 요청·응답 후보 제시. ID 충돌은 모호함으로 표시.
- 선택적으로 사용자 정책에 맞는 호출을 표시하고, 원문 바이트를 포함한 JSONL 내보내기.
- 프로세스마다 읽은 바이트, 누락된 바이트, 검색 제한, 오류를 요약 행으로 표시.

메모리에서 JSON이 발견됐다는 사실만으로 실제 전송, 도구 실행, 공격 성공을 입증할 수는 없습니다.
로그·캐시·예제 문자열도 같은 형태로 남을 수 있습니다. `complete`는 아래 파서가 완전한 JSON-RPC
형태로 읽었다는 뜻이며, MCP 전체 스키마 검증이나 실제 통신 여부 검증을 의미하지 않습니다.

## 설치

Python 3.10 이상과 이 저장소의 체크아웃이 필요합니다. 저장소 루트에서 실행합니다.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\vol.exe -p .\plugins windows.mcptrace.MCPTrace -h
```

Linux 분석 호스트에서도 두 종류의 플러그인을 실행할 수 있습니다.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/vol -p ./plugins windows.mcptrace.MCPTrace -h
.venv/bin/vol -p ./plugins linux.mcptrace.MCPTrace -h
```

`mcptrace/`는 설치할 Python 패키지이고 `plugins/`는 `-p`로 지정할 Volatility 플러그인 경로입니다.
두 경로를 함께 유지해야 합니다. 개발 도구가 불필요하면 `pip install -e .`로 설치합니다.
아래 예시는 가상환경의 `vol`이 PATH에 있다는 전제입니다. PowerShell에서는 위의 `vol.exe` 전체 경로를
사용해도 됩니다. 플러그인 폴더를 옮긴 경우 `-p`에 절대 경로를 지정합니다.

## 실행

### Windows 이미지

먼저 Volatility가 이미지와 Windows 심볼을 정상적으로 해석하는지 확인합니다.

```powershell
vol -f C:\Evidence\memory.raw windows.info.Info
vol -f C:\Evidence\memory.raw windows.pslist.PsList
```

MCP 클라이언트와 서버는 서로 다른 프로세스에 있을 수 있으므로 해당 PID들을 함께 확인합니다.
아래 PID는 예시입니다. PID를 생략하면 `pslist`가 열거한 모든 프로세스를 시도합니다.

```powershell
vol -p .\plugins -f C:\Evidence\memory.raw windows.mcptrace.MCPTrace --pid 4242 5252
```

정책 적용 및 JSONL 저장:

```powershell
New-Item -ItemType Directory -Force .\output | Out-Null
vol -p .\plugins -f C:\Evidence\memory.raw -o .\output windows.mcptrace.MCPTrace --pid 4242 --policy .\examples\policy.json --dump
```

전체 TreeGrid를 JSON으로 저장할 때는 전역 렌더러 옵션을 플러그인 이름 앞에 둡니다.

```powershell
vol -p .\plugins -f C:\Evidence\memory.raw -r json windows.mcptrace.MCPTrace --pid 4242 > findings.json
```

Volatility는 심볼 확보를 위해 네트워크를 사용할 수 있습니다. 사전에 필요한 심볼·캐시를 준비한 환경에서는
전역 옵션 `--offline`을 사용할 수 있습니다. MCPTrace 자체는 외부 API나 LLM을 호출하지 않습니다.

### Linux 이미지

대상 이미지의 **커널 버전·빌드에 맞는 Linux ISF 심볼**을 준비해야 합니다. 먼저 배너를 확인한 뒤
해당 심볼을 `./symbols/linux/`에 배치합니다. 사전 생성 심볼을 구할 수 없으면 해당 커널의 디버그 정보와
`dwarf2json`으로 생성합니다. 준비 절차는 [Volatility Linux 문서](https://volatility3.readthedocs.io/en/stable/getting-started-linux-tutorial.html)를 참고합니다.

아래 경로와 PID는 예시이며 Volatility에서 정상 해석할 수 있는 Linux 메모리 이미지가 필요합니다.

```bash
vol -f ./evidence/linux.lime banners.Banners
vol -s ./symbols -f ./evidence/linux.lime linux.pslist.PsList
mkdir -p ./output
vol -p ./plugins -s ./symbols -f ./evidence/linux.lime -o ./output linux.mcptrace.MCPTrace --pid 4242 --policy ./examples/policy-linux.json --dump
```

`linux.pslist` 단계에서 커널·심볼 요구사항 오류가 발생하면 먼저 이미지/심볼 연결을 해결해야 합니다.
`--pid`는 `linux.pslist`의 프로세스 PID를 사용하며 출력 PID는 TGID입니다. 사용자 스레드를 별도로
열거하지 않아 같은 프로세스 주소 공간을 반복 검사하지 않습니다. 일반적인 Linux `comm` 이름은
전체 실행 파일 경로가 아니며 잘릴 수 있습니다.

커널의 기존 `mmap` 목록과 Maple Tree 선택은 Volatility의 `mm.get_vma_iter()`에 맡깁니다.
이 API 사용이 모든 커널 빌드의 지원을 보증하지는 않습니다. 커널 스레드의 `active_mm`에는 다른
프로세스 주소 공간이 연결될 수 있으므로 대체 분석 대상으로 사용하지 않습니다.

## 옵션

| 옵션 | 기본값 | 의미 |
| --- | --- | --- |
| `--pid 4242 5252` | 전체 | 지정한 PID만 분석 |
| `--include-partial` | 끔 | 파싱되지 않은 JSON-RPC 앵커 주변 조각을 별도 표시 |
| `--include-rpc` | 끔 | MCP 관련성이 확인되지 않은 일반 JSON-RPC 후보도 표시 |
| `--max-object-bytes` | 65536 | 완전한 JSON 하나의 최대 바이트 크기, 256–4194304 |
| `--max-records` | 10000 | 프로세스당 후보 수 제한, 필터 적용 **전** 기준 |
| `--max-bytes` | 0 | 프로세스당 읽기를 시도할 VAD/VMA 범위 바이트 예산, 0은 제한 없음 |
| `--policy` | 없음 | 로컬 정책 JSON 파일 |
| `--suspicious-only` | 끔 | `policy-match`인 후보와 요약만 표시, 비어 있지 않은 정책 필요 |
| `--dump` | 끔 | 표시되는 후보를 `-o` 디렉터리에 JSONL로 내보내기 |

`--include-rpc`가 없으면 알려진 MCP 메서드, MCP 형태의 응답, 해당 요청과 같은 PID·ID의 응답을
표시합니다. 메서드 목록은 `mcptrace/core.py`의 `MCP_METHODS`에서 관리합니다.
MCP 메서드명과 응답 형태는 다른 프로토콜과 겹칠 수 있으므로 이 필터는 관련성 휴리스틱입니다.

## 결과 해석

| 필드 / 값 | 의미 |
| --- | --- |
| `VirtualAddress` | 해당 PID의 프로세스 가상 주소. 이미지 파일 오프셋이 아님 |
| `VADStart` / `VMAStart` | 각각 Windows VAD / Linux VMA의 시작 가상 주소 |
| `complete` | 중복 키·잘못된 인코딩 등을 거부하는 파서가 읽은 JSON-RPC 형태의 객체 |
| `fragment` | JSON-RPC 앵커부터 최대 512바이트의 원문 조각. ID·인자·응답을 추정하지 않음 |
| `candidate-only` | 같은 PID·타입별 ID의 상대 메시지가 있음. 실제 세션 연결은 미확정 |
| `ambiguous-id` | 같은 PID·ID에 서로 다른 요청 또는 응답 텍스트가 남음 |
| `unpaired` | 비교 대상 요청/응답이 발견되지 않음 |
| `not-applicable` | ID가 없거나 파싱하지 못해 연결을 시도하지 않음 |
| `CandidateAddresses` | 상대 후보 주소 목록·전체 주소 수·목록 생략 여부. 목록은 최대 256개 |
| `policy-match` | 사용자가 정의한 조건과 인자가 일치함. 악성 판정이 아님 |
| `not-evaluated` | 정책 대상 도구이지만 인자가 없거나 지원하지 않는 형식이라 검사 불가 |
| `scan-summary` | 검사 범위, 제한, 오류. `Raw` 열에 JSON으로 표시 |

요약의 `regions_scanned`는 읽기를 시도한 영역 수, `invalid_regions`는 어댑터에 전달됐지만 시작·크기가
잘못되어 건너뛴 영역 수입니다. Volatility 내부에서 열거하지 못하거나 먼저 제외한 영역까지 세지는 않습니다.
`skipped_reason`이 `no-user-address-space`이면 사용자 주소 공간이 없고, `no-process-layer`이면 프로세스
레이어를 구성하지 못한 것입니다. 커널 스레드·종료 중인 프로세스·페이지 테이블 손상 등을 구분하려면
다른 증거를 함께 확인합니다. 후속 메모리 영역에서 오류가 나도 앞서 추출한 증거는 유지합니다.

요청 ID `1`과 `"1"`은 구분하며 서로 다른 PID의 메시지는 연결하지 않습니다.
같은 JSON 텍스트가 여러 주소·인코딩으로 남은 경우 각각의 증거를 유지합니다.
서로 다른 공백이나 멤버 순서도 보수적으로 다른 텍스트로 취급합니다.
메모리 주소의 크기로 시간 순서를 추정하지 않으며 세션과 통신 방향은 복원하지 않습니다.
`RequestID`의 JSON `null`은 ID 없음과 명시적 null을 모두 나타낼 수 있으므로 원문을 확인합니다.

`--dump` 출력은 프로세스별 `mcptrace.pid-4242.jsonl` 파일입니다. 이름이 이미 존재하면 Volatility가
접미사를 추가하며 요약의 `export`에 실제 파일명을 기록합니다.
첫 줄은 메타데이터, 중간 줄은 아티팩트, 마지막 줄은 검사 요약입니다.
`target_os`로 분석 대상 OS를 구분하고, 아티팩트의 `region_kind`/`region_start`로 메모리 영역을 나타냅니다.
Windows JSONL의 기존 `vad_start` 필드는 유지하며 Linux는 `vma_start`를 추가합니다.
아티팩트의 `raw_base64`는 **추출된 범위의 원문 바이트**, `raw_sha256`은 그 바이트의 해시입니다.
전체 메모리 이미지의 해시가 아닙니다. `message`는 해석된 JSON이고 숫자는 Python의 정수·실수 표현을
사용하므로 원문 검증에는 `raw_base64`를 사용합니다. 터미널의 `Raw`는 제어 문자를 이스케이프해 표시합니다.

## 정책

`examples/policy.json`은 Windows, `examples/policy-linux.json`은 Linux 경로를 위한 예제입니다.
두 파일 모두 예시 도구 `read_file`, `fetch`의 허용 경로·호스트를 검사합니다.
사용 중인 MCP 서버의 **정확한 도구 이름과 인자 구조**에 맞게 수정해야 합니다.

```json
{
  "version": 1,
  "rules": [{
    "id": "outside-case-directory",
    "description": "사건 분석 디렉터리 밖의 파일 접근 요청",
    "severity": "medium",
    "tool": "read_file",
    "argument": "/path",
    "operator": "windows_path_outside",
    "value": ["C:\\Cases"]
  }]
}
```

`argument`는 `params.arguments`에 대한 JSON Pointer이며 `~0`, `~1`, 배열 인덱스를 지원합니다.
완전하게 파싱된 `tools/call`의 문자열 인자에만 적용합니다.

| 연산자 | 비교 |
| --- | --- |
| `equals` | 문자열 전체 일치, 대소문자 구분 |
| `contains` | 문자열 포함, 대소문자 구분 |
| `url_host_not_in` | HTTP(S) URL의 파싱된 호스트가 허용 목록 밖인지 비교 |
| `windows_path_outside` | 절대 Windows 경로를 정규화한 뒤 허용 디렉터리 경계 밖인지 비교 |
| `posix_path_outside` | 절대 POSIX 경로를 정규화한 뒤 허용 디렉터리 경계 밖인지 비교. 대소문자 구분 |

Linux 경로 규칙은 `"operator": "posix_path_outside", "value": ["/srv/cases"]`와 같이 작성합니다.
`/srv/cases2`는 `/srv/cases`의 하위 경로가 아니며 `/srv/cases/../secret`도 허용 범위 밖입니다.
Windows에서 Linux 이미지를 분석해도 POSIX 경로 의미를 적용하고 역슬래시를 경로 구분자로 바꾸지 않습니다.
상대 경로, 환경 변수, glob, `//`로 시작하는 경로는 추정하지 않고 `not-evaluated`로 표시합니다.

URL 검사는 사용자 정보·경로의 문자열을 호스트로 오인하지 않으며 와일드카드나 암묵적 서브도메인 허용은
없습니다. 포트는 검사 대상이 아니며 IPv6 리터럴은 현재 지원하지 않습니다. DNS·리다이렉트를 조회하지 않습니다.
경로 검사는 문자열 기준이며 정션, 심볼릭 링크, 8.3 별칭의 실제 대상은 해석하지 않습니다.
Linux의 마운트 네임스페이스·chroot·심볼릭 링크도 해석하지 않으므로 규칙의 경로는 대상 프로세스가
사용하는 경로 기준으로 지정해야 합니다. 경로를 분석 호스트 파일시스템에서 조회하지 않습니다.
환경 변수, 상대 경로, ADS, 와일드카드 등 지원하지 않는 입력은 `not-evaluated`로 남깁니다.
규칙에서 경고가 발생하지 않았다고 안전하거나 실행되지 않았다는 뜻은 아닙니다.

## 제한과 검증

- 평문 UTF-8·UTF-16LE JSON을 대상으로 합니다. 압축·암호화·바이너리 객체·V8/Python 힙 객체 재조립은 미지원입니다.
- 리터럴 `"jsonrpc": "2.0"` 앵커를 사용합니다. 키/버전 문자가 `\u` 이스케이프로 표현되면 놓칠 수 있습니다.
- 깊이 128, 앵커당 직전 객체 시작 후보 64개, 인코딩별 버퍼당 앵커 20000개의 제한이 있습니다.
  후보·앵커 제한에 도달하면 요약 카운터에 표시합니다. 한 메시지의 크기 제한은 바이트 단위입니다.
- 빠진 바이트를 0으로 채우거나 다른 VAD/VMA와 이어 붙이지 않습니다. 프로세스 읽기 오류가 나면 이미 추출한
  결과를 유지하고 해당 프로세스의 나머지 검사를 중단합니다.
- `pslist`에서 보이지 않는 프로세스, 해제되어 VAD/VMA 밖에 남은 흔적, 현재 레이어가 읽지 못하는 페이지는 범위 밖입니다.
- `bytes_read`는 읽기에 성공한 바이트 수입니다. 후보 제한으로 중단하면 읽은 버퍼 전체가 처리됐다는 뜻은 아닙니다.
  후보 제한은 일반 JSON-RPC에도 적용되므로 잡음이 많으면 관련 메시지에 도달하기 전에 중단할 수 있습니다.
- 검색 결과 없음은 흔적 부재의 증명이 아닙니다. 모든 프로세스에 요약 행을 남기며 탐지율·복원율 수치를 주장하지 않습니다.

테스트 실행:

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

검증 구성과 실제 Windows/Linux 이미지에서 확인해야 할 항목은 [docs/validation.md](docs/validation.md)에 있습니다.

## 구조

```text
mcptrace/core.py               JSON 추출·증거 모델·ID 후보 연결
mcptrace/memory.py             누락 페이지를 보존하는 레이어 읽기
mcptrace/policy.py             사용자 정의 도구 인자 검사
mcptrace/volatility.py         공통 영역 검사·TreeGrid·JSONL
plugins/windows/mcptrace.py    Windows 프로세스·VAD 어댑터
plugins/linux/mcptrace.py      Linux 프로세스·VMA 어댑터
tests/                        합성 증거와 실제 Volatility API 테스트
```

참고 인터페이스: [Volatility 플러그인 문서](https://volatility3.readthedocs.io/en/stable/simple-plugin.html),
[MCP 2025-11-25 기본 프로토콜](https://modelcontextprotocol.io/specification/2025-11-25/basic),
[MCP 도구 호출](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
