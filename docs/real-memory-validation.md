# 공개 Linux RAM 이미지 검증

검증일: 2026-10-27. 분석 코드: `62b0f655c35044869400577cdaf53b5a3472a4c7` (v0.2.0).
분석 호스트: Ubuntu 24.04.3, Python 3.12.14, `volatility3==2.28.2`.
플러그인 코드는 수정하지 않고 실행했습니다. 메모리 내용은 실행하지 않았습니다.

**결과:** 공개 MCP 활동 샘플의 Python 프로세스 2개에서 완전한 JSON-RPC 형태의 MCP 후보
41개를 추출했습니다. 41개 모두 해당 PID의 가상 주소에서 다시 읽은 바이트, SHA-256,
VMA 범위와 일치했습니다. 다만 이 샘플의 VMware 메타데이터가 공개되지 않아, 아래의
**추정한 물리 메모리 배치**를 적용한 조건부 결과입니다. 복원율이나 정밀도 측정은 아닙니다.

## 입력과 전처리

| 입력 | 출처 | 크기 | 확인한 커널 / 역할 |
| --- | --- | ---: | --- |
| 13Cubed `memory.vmem` + `memory.vmsn` | [제작자 설명](https://www.youtube.com/watch?v=IHd85h6T57E), [원본 ZIP](https://cdn.13cubed.com/downloads/linux_challenge.zip) | VMEM 4,294,967,296 bytes; VMSN 5,567,519 bytes | Ubuntu 6.5.0-41-generic, 실제 VMware 메타데이터를 사용한 실행 확인 |
| MCPRecon `sample.vmem` | [저자 저장소 README](https://github.com/BiTLab-BaggiliTruthLab/MCPRecon), [저자가 연결한 샘플](https://drive.google.com/file/d/16d84BfG19auxwERKwajmNnDD0gVYo2Q9/view) | 8,589,934,592 bytes | Ubuntu 6.14.0-37-generic, MCP 후보 추출 확인 |

13Cubed ZIP의 CRC 검사를 통과한 뒤 전체 VMEM을 추출했습니다. 이 이미지는 2024-07-03
프로세스 생성 시각을 포함하며, MCP 통신 정답 자료는 없습니다. 아래에서 선택한 프로세스에서
후보가 나오지 않았다는 사실만 기록하며, 이미지 전체가 MCP 음성이라고 단정하지 않습니다.

MCPRecon 원본 VMEM만 열면 VMware 메타데이터 누락 경고가 발생하고, 기본 `linux.pslist`
결과가 **종료 코드 0이지만 0행**이었습니다. 이를 성공한 검사로 간주하지 않았습니다.
덤프 안에는 6.14.0-36과 6.14.0-37 배너가 모두 있었으며, 아래 배치를 적용한 뒤 6.14.0-37
심볼로 프로세스 목록과 VMA 목록을 읽을 수 있었습니다.

원본에서 확인한 BIOS-e820 텍스트의 주요 범위:

```text
BIOS-e820: [mem 0x0000000000100000-0x00000000bfecffff] usable
BIOS-e820: [mem 0x00000000bff00000-0x00000000bfffffff] usable
BIOS-e820: [mem 0x0000000100000000-0x000000023fffffff] usable
```

이 단서와 총 크기를 근거로 다음 배치를 **추정**했습니다.

| 원본 파일 범위 (끝 제외) | 물리 주소 범위 (끝 제외) |
| --- | --- |
| `[0, 3 GiB)` | `[0, 3 GiB)` |
| `[3 GiB, 8 GiB)` | `[4 GiB, 9 GiB)` |

`scripts/prepare_mcprecon_sample.py`는 정확히 아래 해시의 원본만 허용하며, 모든 원본 바이트를
순서대로 보존하고 두 개의 32바이트 LiME 헤더를 추가합니다. 물리 주소 `[3 GiB, 4 GiB)`는
누락 범위로 남깁니다. 결과물은 **분석용 파생 컨테이너이며 LiME로 수집한 원본이 아닙니다.**
이 추정은 원본 VMSN/VMSS에 의한 확인을 대체하지 않습니다. 다른 VMware 덤프에 일반화하지 마세요.

SHA-256:

```text
13Cubed ZIP       ca7f3f4c4638dcbf4b667e19d4406e4a3c5ca323abb42bf0e2a803ef711e4ec2
13Cubed VMEM      d718483152a85e82a96c7c260131572556f5aeaf8951f8f73af281fd1840035e
13Cubed VMSN      7953e49f2f2ccef880ad5983ee2e491009f93c0c7837daffa5589aa7560c064f
MCPRecon VMEM     65b5ccea17c6ce82d978d1b258590a42a2723b13f74b88a5335a7b10401c8bbf
MCPRecon 파생 LiME 9c375e111990c55150e6fa42e674e2ef0ddb1e2af1c6c45a4912a58c1d1d6c43
```

심볼은 커뮤니티 [volatility3-symbols](https://github.com/Abyss-W4tcher/volatility3-symbols)의
정확한 배너에 해당하는 ISF를 사용했습니다. 배포판 공식 서명 검증을 했다는 의미는 아닙니다.

| ISF | 다운로드 | SHA-256 |
| --- | --- | --- |
| Ubuntu 6.5.0-41.41~22.04.2 amd64 | [ISF](https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/isf-Ubuntu-amd64-6.5.0/Ubuntu_6.5.0-41-generic_6.5.0-41.41.22.04.2_amd64.json.xz) | `6b1b998a6804bce921e32756d3ca2545516a8b9a7b944f0cbcc2f9b0f2ccdc44` |
| Ubuntu 6.14.0-37.37~24.04.1 amd64 | [ISF](https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/isf-Ubuntu-amd64-6.14.0/Ubuntu_6.14.0-37-generic_6.14.0-37.37.24.04.1_amd64.json.xz) | `2230072c4a1565fbf04000a9d0e8c3d01ccb92e410ce0595b353f3f118f23d43` |

## 실행 결과

`linux.pslist.PsList`: 13Cubed 344행, 파생 MCPRecon 349행.
`linux.proc.Maps`: 아래 사용자 PID에 대해 각각 831개와 360개의 VMA를 열거했습니다.
MCPTrace의 `regions_scanned` 합계와 일치합니다. 전체 프로세스를 검사한 것은 아닙니다.

| 이미지 / PID | 프로세스 | VMA | 읽은 bytes | 읽지 못한 bytes | 표시 후보 |
| --- | --- | ---: | ---: | ---: | ---: |
| 13Cubed / 4453 | bash | 31 | 4,894,720 | 6,647,808 | 0 |
| 13Cubed / 4954 | bash | 31 | 5,238,784 | 6,168,576 | 0 |
| 13Cubed / 6742 | sublime_text | 769 | 90,705,920 | 250,605,568 | 0 |
| 파생 MCPRecon / 41879 | python | 191 | 64,262,144 | 163,250,176 | 24 |
| 파생 MCPRecon / 41880 | python | 169 | 59,805,696 | 164,917,248 | 17 |

13Cubed PID 2 (`kthreadd`)는 0바이트를 읽고 `skipped_reason=no-user-address-space`로
건너뛰었습니다. 선택한 모든 PID의 `error`는 null, `limits_hit`는 빈 배열이었고,
앵커/후보 제한 도달 및 잘못된 VMA 카운터는 0이었습니다. 읽지 못한 바이트의 원인을
swap·비상주 페이지·누락·매핑 오류 등으로 추가 판별한 것은 아닙니다.

MCP 후보 41개는 모두 UTF-8 `complete`입니다.

- 요청 27개, 응답 13개, 알림 1개. `tools/call` 9개 모두 도구명이 `get_current_weather`입니다.
- 원문 SHA-256이 서로 다른 바이트열은 33개입니다. 이를 고유 통신 메시지 33개로 간주하지 않습니다.
- 연결 표시는 `candidate-only` 13개, `unpaired` 27개, `not-applicable` 1개입니다.
  `candidate-only`는 메시지 **행** 수이며 연결 쌍 수나 올바른 요청·응답 연결률이 아닙니다.
- 별도 검증기는 MCPTrace의 스캐너·어댑터를 사용하지 않고 native Volatility `PsList`와
  프로세스 레이어로 다시 읽었습니다. PID 41879의 24개 / 8,879바이트와 PID 41880의
  17개 / 2,151바이트, 합계 **41개 / 11,030바이트**가 원문·해시·VMA 범위 대조를 통과했습니다.
  주소 변환은 여전히 동일한 Volatility 프레임워크와 위 추정 배치를 사용합니다.
- 검증기의 실패 경로도 확인했습니다. 내보낸 후보의 한 바이트와 그 SHA-256을 함께 바꾼 복사본은
  원래 프로세스 메모리와 달라 검증기가 `process memory bytes differ`로 거부했습니다.

검사는 기본 옵션으로 실행했습니다: `max-object-bytes=65536`, `max-records=10000`,
`max-bytes=0`, partial/RPC 전체 표시/정책 검사 끔, JSONL 내보내기 켬.
한 번의 CLI 실행 경과 시간은 13Cubed 11.29초, 파생 MCPRecon 11.68초였습니다.
다운로드·변환·해시·별도 대조 시간은 제외하며 캐시가 있는 공유 실행 환경의 관측값입니다.
8 GiB 전체를 11.68초에 검사했다는 뜻이나 처리 속도 벤치마크가 아닙니다.

## 재현

저장소 설치 후 루트에서 Bash로 실행합니다. `.venv/bin`을 PATH에 추가합니다.
예시 디렉터리의 원본 파일과 위 ISF를 먼저 준비해야 합니다. 심볼은 `symbols/linux/` 안에 둡니다.
원본 12 GiB와 파생 파일 약 8 GiB, 다운로드 압축파일 등을 위한 공간이 필요합니다.

```bash
export PATH="$PWD/.venv/bin:$PATH"
mkdir -p cache symbols/linux output/13cubed output/mcp

# evidence/13cubed/에 memory.vmem과 같은 이름의 memory.vmsn을 함께 둡니다.
vol -q --offline --cache-path cache -s symbols -f evidence/13cubed/memory.vmem -r json linux.pslist.PsList > output/13cubed/pslist.json
vol -q --offline --cache-path cache -s symbols -f evidence/13cubed/memory.vmem -r json linux.proc.Maps --pid 4453 4954 6742 > output/13cubed/maps.json
vol -q --offline --cache-path cache -s symbols -p plugins -f evidence/13cubed/memory.vmem -o output/13cubed -r json linux.mcptrace.MCPTrace --pid 2 4453 4954 6742 --dump > output/13cubed/findings.json 2> output/13cubed/stderr.txt

# 이 해시의 공개 샘플에만 적용되는 추정 배치입니다. 원본은 덮어쓰지 않습니다.
python scripts/prepare_mcprecon_sample.py evidence/sample.vmem evidence/sample-derived.lime > output/mcp/preparation.json
vol -q --offline --cache-path cache -s symbols -f evidence/sample-derived.lime -r json linux.pslist.PsList > output/mcp/pslist.json
vol -q --offline --cache-path cache -s symbols -f evidence/sample-derived.lime -r json linux.proc.Maps --pid 41879 41880 > output/mcp/maps.json
vol -q --offline --cache-path cache -s symbols -p plugins -f evidence/sample-derived.lime -o output/mcp -r json linux.mcptrace.MCPTrace --pid 41879 41880 --dump > output/mcp/findings.json 2> output/mcp/stderr.txt
python scripts/verify_linux_export.py --image evidence/sample-derived.lime --symbols symbols --cache cache --require-artifacts output/mcp/mcptrace.pid-41879.jsonl output/mcp/mcptrace.pid-41880.jsonl > output/mcp/verified.json
```

새 출력 폴더에서 실행하세요. 기존 JSONL이 있으면 Volatility가 이름에 접미사를 붙이므로,
재실행 시 해당 실행의 `scan-summary.export` 파일명을 검증기에 전달해야 합니다.
덤프, 심볼, 원문 메시지가 든 출력 파일은 저장소에 넣지 않습니다.

## 아직 확인하지 못한 것

실제 송수신 메시지 정답 집합과 수집 지연·작업량 조건을 대조하지 않았으므로 정밀도, 재현율,
오연결률, 인자 부분 복원률을 주장할 수 없습니다. JSON은 로그·캐시·예제에서 왔을 수도 있습니다.
Windows 실제 RAM, 기존 mmap 기반 Linux 커널, 다른 배포판·빌드, UTF-16 실제 사례,
부분 조각 추출과 사용자 정책의 실제 사건 판정도 이번 실행 범위 밖입니다.
이 결과는 선택한 프로세스에서의 추출 경로 확인이며, 운영 환경 전반의 검증 완료 선언이 아닙니다.
