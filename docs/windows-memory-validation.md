# Windows 11 실제 RAM 검증

검증일: 2026-10-27. 분석 호스트는 Ubuntu 24.04.3, Python 3.12.14이며
`volatility3==2.28.2`를 사용했습니다. 분석 대상 덤프가 Windows이며 분석 호스트는 Linux입니다.

**결과:** 실제 Windows 11 x64 빌드 22000 이미지에서 사용자 프로세스 4개의 VAD 1,561개를
검사했습니다. 읽은 바이트는 361,902,080 (약 345.14 MiB), MCP 후보는 0개입니다.
플러그인 실행·VAD 접근·누락 집계·JSONL 출력을 검증한 결과이며,
**Windows에서 실제 MCP 메시지를 추출했다는 결과는 아닙니다.**

## 원본과 심볼

[PassMark의 Volatility Workbench 공식 배포 페이지](https://www.osforensics.com/tools/volatility-workbench.html)에
연결된 [Windows 11 덤프](https://www.osforensics.com/downloads/Win11Dump.zip)를 사용했습니다.
ZIP 멤버를 끝까지 읽어 CRC를 확인했고, 추출한 원본에 메시지나 바이트를 주입하지 않았습니다.
메모리에 포함된 프로그램은 실행하지 않았습니다.

| 파일 | 크기 (bytes) | SHA-256 |
| --- | ---: | --- |
| `Win11Dump.zip` | 1,318,367,225 | `150b62a071debc39651368c89ff2ba990fe825a8363be78af0e7889ce9605412` |
| `Win11Dump.mem` | 3,745,951,744 | `0f00815b8f78f30a63d742c73152474b2a3c35183dbb1d92c8fc6a81fa3de9f1` |
| 생성된 NT ISF JSON.XZ | 629,352 | `811a6a7dacfac7d447e1d9213d28df7273576fa821b7eb522ae312e9703fc5df` |

처음 `windows.info.Info` 실행 시 Volatility의 자동 심볼 다운로드·변환을 사용했고,
이후 검사는 `--offline`으로 실행했습니다. 생성된 ISF의 식별자는
`windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz`입니다.
다른 환경에서 ISF를 다시 생성하면 압축 결과의 해시까지 같다는 보장은 없습니다.

`windows.info.Info` 관측값:

| 항목 | 값 |
| --- | --- |
| Is64Bit / MachineType | True / 34404 (AMD64) |
| Major/Minor | 15.22000 |
| NtMajorVersion / NtMinorVersion | 10 / 0 |
| SystemTime | 2022-07-18 23:26:00 UTC |
| Kernel Base / DTB | `0xf80029800000` / `0x1ae000` |
| 레이어 | WindowsIntel32e → FileLayer |

`windows.pslist.PsList`는 103행을 반환했습니다. 그중 PID `128017663995251`,
이름 `Milliseconds,MS`인 비정상적으로 보이는 행도 포함되어 있어 **103개를 모두 실제 정상
프로세스로 확정하지 않았습니다.** 원인은 이번 검사에서 규명하지 않았습니다.
아래 선택한 네 PID는 종료 시각이 없고, `windows.vadinfo.VadInfo`에서도 VAD를 열거했습니다.

## 발견한 읽기 문제와 수정

Explorer·Teams·Edge의 VAD 목록에서 각각 2 TiB 크기의 가상 주소 예약 영역을 확인했습니다.
이 영역은 실제로 2 TiB의 RAM이 수집됐다는 뜻이 아닙니다. 기존 읽기 방식은 청크 읽기 실패 후
빠진 페이지마다 4 KiB 재시도를 하므로 이런 큰 빈 영역을 처리하기에 부적합했습니다.
수정 전의 전체 2 TiB 영역 검사 완료 시간은 측정하지 않았습니다.

`mcptrace/memory.py`는 이제 Intel 프로세스 레이어의 `PagedInvalidAddressException`에 담긴
부재 영역 크기를 확인하고 그 경계까지 건너뜁니다. 호출자의 VAD/VMA 끝과 바이트 예산을 넘지
않으며 건너뛴 길이는 `unreadable_bytes`에 집계합니다. 물리 레이어 읽기 실패에는 이 추정을
적용하지 않고 4 KiB 재시도를 유지합니다. 따라서 큰 페이지의 일부만 수집된 경우에도 읽을 수
있는 부분을 버리지 않습니다. `pad=False`와 누락 구간 비결합도 유지합니다.

분석 기준: 커밋 `b178f7b9de11ab829d08694b445e5ba8e00d91f3`에 이 읽기 수정을 적용했습니다.
실제 실행한 `mcptrace/memory.py` SHA-256:
`12ff75dc67c8a8d6194e98f086fc2edb4987b8bbb248cadb1f4f2771231754ca`.

## 실제 실행 결과

| PID | 프로세스 | VAD | 읽은 bytes | 읽지 못한 bytes | MCP 후보 |
| --- | --- | ---: | ---: | ---: | ---: |
| 3244 | explorer.exe | 808 | 160,899,072 | 2,203,945,033,728 | 0 |
| 6248 | msteams.exe | 221 | 31,633,408 | 2,220,703,334,400 | 0 |
| 6524 | msedge.exe | 337 | 115,310,592 | 2,272,876,556,288 | 0 |
| 2180 | Calculator.exe | 195 | 54,059,008 | 4,567,629,824 | 0 |

각 PID에서 다음을 확인했습니다.

- `regions_scanned`가 native `windows.vadinfo`의 VAD 개수와 일치.
- `bytes_read + unreadable_bytes`가 해당 VAD들의 가상 주소 범위 길이 합계와 일치.
- `error=null`, `limits_hit=[]`, `skipped_reason=null`이며 앵커/후보 제한 도달과 잘못된 영역은 0.
- JSONL 4개에 올바른 PID, `target_os=windows`, `region_kind=vad` 메타데이터와 요약이 존재.
  아티팩트가 0개이므로 원문·주소·해시 대조를 통과한 Windows 메시지가 있다고 표현하지 않음.

`unreadable_bytes`에는 사용하지 않는 예약 주소 공간도 포함됩니다. 수 TiB의 덤프 데이터가
손실됐다는 의미가 아니며, swap·비상주 페이지·수집 누락 등의 원인을 모두 구분한 값도 아닙니다.
이 이미지는 2022년 시각을 담은 일반 샘플이며 MCP 송수신 정답 자료가 없습니다.

기본 `max-object-bytes=65536`, `max-records=10000`, `max-bytes=0`으로 실행했습니다.
정책·partial·RPC 전체 표시는 끄고 JSONL 내보내기를 켰습니다. 프로세스별 바이트 예산 제한 없이
선택한 VAD 목록 끝까지 검사했지만, 전체 103행의 주소 공간을 검사한 것은 아닙니다.
CLI 경과 시간 7.01초는 심볼과 파일 캐시가 있는 공유 환경의 한 번의 관측값이며,
다운로드·해시·심볼 준비 시간은 제외합니다. 이미지 전체 처리량 벤치마크가 아닙니다.

## 회귀 확인

실제 Volatility `Intel32e`와 구성한 페이지 테이블을 이용하는 테스트 5개를 추가했습니다.
2 TiB 간격을 페이지마다 읽지 않는지, 인접 가상 페이지의 물리 위치가 떨어져 있어도 읽는지,
누락 페이지 양쪽의 JSON을 결합하지 않는지, 예산 경계와 일부만 수집된 큰 페이지를 확인합니다.
전체 테스트 119개와 Ruff 검사·포맷 검사가 통과했습니다.

[Linux 공개 이미지 2개](real-memory-validation.md)도 같은 수정으로 다시 실행했습니다.
13Cubed PID 4개와 MCPRecon PID 2개의 **모든 JSONL 파일이 수정 전 결과와 바이트 단위로
동일**했습니다. MCP 후보 41개와 원문·주소·해시·연결 표시·스캔 통계가 유지됐습니다.

## 재현 명령

저장소 설치 후 루트에서 Bash로 실행합니다. `evidence/Win11Dump.mem`은 위 원본입니다.
첫 `windows.info`는 심볼을 내려받을 수 있으므로 네트워크를 허용한 상태에서 실행하고,
이후에는 같은 심볼 디렉터리와 캐시를 사용합니다.

```bash
export PATH="$PWD/.venv/bin:$PATH"
mkdir -p cache symbols output/win11
vol -q --cache-path cache -s symbols -f evidence/Win11Dump.mem -r json windows.info.Info > output/win11/info.json
vol -q --offline --cache-path cache -s symbols -f evidence/Win11Dump.mem -r json windows.pslist.PsList > output/win11/pslist.json
vol -q --offline --cache-path cache -s symbols -f evidence/Win11Dump.mem -r json windows.vadinfo.VadInfo --pid 3244 6524 6248 2180 > output/win11/vads.json
vol -q --offline --cache-path cache -s symbols -p plugins -f evidence/Win11Dump.mem -o output/win11 -r json windows.mcptrace.MCPTrace --pid 3244 6524 6248 2180 --dump > output/win11/findings.json 2> output/win11/stderr.txt
```

후속 검증에는 실제 MCP 호출과 정답 메시지를 기록한 Windows 덤프가 필요합니다.
이번 결과만으로 Windows의 MCP 복원 성능, 다른 Windows 빌드 호환성, 정밀도·재현율을
주장하지 않습니다. 원본 덤프·심볼·메모리 내용은 저장소에 커밋하지 않습니다.
