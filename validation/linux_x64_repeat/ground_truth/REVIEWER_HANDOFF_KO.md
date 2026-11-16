# MCPTrace Linux RAM 실험: 한국어 검토 안내

이 문서는 검토자가 **원본 RAM에서 직접 다시 계산**할 때 필요한 자료와 확인
범위를 설명합니다. 공개된 수치만 읽는 원고 검토와 원본을 이용한 독립 재계산은
서로 다른 작업입니다. 검토자가 아직 지정되지 않았고, 비공개 원본은 전달되지
않았습니다.

## 실험 묶음 구분

| 묶음 | 원본 접근 | 검토 내용 |
| --- | --- | --- |
| MCPRecon 비교 27개 | RAM·합성 전송 기록 공개 | [공개 재실행 절차](../../mcprecon_comparison/ground_truth/README.md)로 251 대 184를 검산할 수 있습니다. |
| 기존 실제 호스트 6개 | RAM 6개와 Codex 원본 전송 기록 2개 비공개 | [기존 6개 절차](../../linux_x64_real_host_ram/ground_truth/README.md)에 따라 이미지별로 재스캔합니다. Codex 2개는 같은 PID·같은 호출을 두 시점에 찍은 것입니다. |
| 새 반복 본실험 20개 | RAM 20개와 Codex 원본 전송 기록 4개 비공개 | 아래 명령으로 5개 사례 × 2개 시점 × 독립 실행 2회를 재스캔합니다. 별도 HTTP 파일럿 1개는 본실험 합계에서 제외합니다. |

### 새 본실험 20개: 필요한 자료

[검토자용 색인](reviewer_manifest.json)에 이미지별 파일명, 압축 RAM과 복원
이미지의 크기·SHA-256, 대상 PID, 전송 기록 해시, 공개 보고서 경로가 있습니다.
비공개로 제공해야 하는 파일은 다음뿐입니다.

1. `initial` 묶음의 `ram.elf.zst` 10개
2. `second` 묶음의 `ram.elf.zst` 10개
3. Codex 실행 폴더 4곳의 **원본** `traffic.jsonl`
4. Ubuntu 커널 `6.8.0-146-generic`에 맞는 Volatility Linux 심볼 파일

비Codex 전송 기록 16개와 공개 수치 보고서, 재실행 코드는 저장소에 있습니다.
기존 스캐너 출력, VM 디스크, SSH 키는 재계산에 필요하지 않습니다. 압축 RAM
20개의 합계는 4,759,544,561바이트(약 4.43GiB)이며, 실행 시 이미지 하나를
풀고 분석할 임시 공간을 **추가로 최소 2GiB** 확보하는 편이 좋습니다. 원본을
새 위치에 복사한다면 여유 공간은 약 8GiB를 권장합니다. 스캐너 소스는
`ded4c00235f5c41222f72e8529f3dbd617bc3c9f`, Volatility 3은 `2.28.2`로
고정했습니다. 자세한 파일 배치와 검사 항목은 [영문 절차](REVIEWER_HANDOFF.md)에도
기록돼 있습니다.

저장소 루트에서 아래 명령을 실행합니다. `/PRIVATE/...`는 검토자 컴퓨터의
실제 비공개 경로로 바꿉니다. 명령은 bash/zsh 환경 기준입니다.

```sh
PYTHONPATH=. .venv/bin/python \
  validation/linux_x64_repeat/ground_truth/replay_all.py \
  --first-captures /PRIVATE/first/captures \
  --second-captures /PRIVATE/second/captures \
  --symbols /PRIVATE/symbols --cache /PRIVATE/vol-cache \
  --vol .venv/bin/vol --scratch /PRIVATE/scratch \
  --checkpoint /PRIVATE/replay-progress.json \
  --output /PRIVATE/replay-result.json
```

각 캡처 폴더 이름은 색인의 `run_id`와 같아야 합니다. 스크립트는 원본 압축
파일과 복원 RAM의 해시, 전송 기록 바이트, 새 Volatility 추출 결과, 읽을 수
있는 프로세스 메모리에 원본 메시지가 남았는지, 추출 바이트의 가상 주소,
메시지별 MCP 분류를 공개 보고서와 비교합니다. 이미지별 임시 RAM과 추출
파일은 처리 후 삭제합니다. 중간에 중단되면 같은 명령으로 재개할 수 있으며,
체크포인트에는 수치·해시만 저장됩니다.

전체 결과는 `complete_primary_replay: true`, `replayed_images: 20`,
`all_scores_match: true`를 확인합니다. 기대 합계는 **전송 기록 116개 →
읽을 수 있는 클라이언트 메모리에 원본 바이트가 남은 것 90개 → 추출 90개 →
MCP 분류 68개**, 주소에서 재확인한 추출 레코드 264개입니다. 차이가 나면
어느 이미지·항목인지 그대로 기록해 주시면 됩니다. [저자의 20개 재실행
결과](replay_2026-11-16.json)는 검토자의 독립 실행 결과를 대신하지 않습니다.

### 기존 실제 호스트 6개

[기존 6개 파일 색인](../../linux_x64_real_host_ram/ground_truth/manifest.json)과
[재실행 안내](../../linux_x64_real_host_ram/ground_truth/README.md)를 사용합니다.
Inspector·LSP·일반 JSON-RPC 네 건의 원본 전송 기록은 공개돼 있습니다. Codex
두 건은 비공개 원본 전송 기록이 필요합니다. `replay.py`를 이미지마다 한 번씩
실행하며, Codex에는 `--traffic`으로 해당 원본 기록을 지정합니다. 이 6개와
새 20개를 하나의 26개 분모로 합산하지 마십시오. 실험 설계가 다릅니다.

## 비공개 원본 전달

전체 RAM에는 임시 VM 키와 다른 프로세스 상태가, Codex 원본 기록에는 세션·
턴·창 식별자가 남을 수 있습니다. **전달 전에** 비MCP 내용을 검토하고,
검토자·안전한 전달 또는 감독 하 실행 방식·보관 가능 여부·삭제 시점을
합의해야 합니다. 공개 저장소에는 이 원본들을 올리지 않습니다. 검토자에게
먼저 공개 원고와 절차를 보여드리고, 원본 접근 범위는 별도로 정할 수 있습니다.

## 검토 요청 문구 예시

> 안녕하세요. 제가 개발한 MCPTrace의 Linux 메모리 실험에 대해 독립적인
> 재계산 검토를 부탁드리고 싶습니다. 공개 원고와 실험 절차, 해시·수치 보고서를
> 먼저 보내드리겠습니다. 검토가 가능하시다면 원본 RAM에서 도구를 직접
> 재실행해 전송 기록·메모리 잔존·추출·MCP 분류 수치가 재현되는지 확인해
> 주실 수 있을까요? 원본 RAM과 일부 Codex 기록은 비공개 자료이므로,
> 접근 방식과 보관·삭제 조건을 먼저 상의한 뒤 전달하겠습니다. 결과가
> 다르거나 절차가 모호한 부분도 그대로 알려주시면 감사하겠습니다.
