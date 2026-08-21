#!/usr/bin/env bash
# 10개 시나리오 스크립트가 공통으로 쓰는 리포트 출력 헬퍼.
# source _lib.sh 로 불러와서 scene_report를 쓴다.
set -uo pipefail

SCENARIOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCENARIOS_DIR/../.." && pwd)"
AWS_REGION="ap-northeast-2"

tf_output() {
  (cd "$TF_DIR" && terraform output -raw "$1" 2>/dev/null)
}

# scene_report <씬번호> <목적> <PASSED|FAILED> <실행 명령어>
# run-all.sh가 이 줄을 "^\| Scene"로 grep해서 종합 표를 만들기 때문에
# 색 코드 없이 순수 텍스트로 유지한다 - 색은 아래 result_box가 별도로 낸다.
scene_report() {
  local scene="$1" purpose="$2" result="$3" cmd="$4"
  printf '| Scene %-2s | %-55s | %-7s | %s\n' "$scene" "$purpose" "$result" "$cmd"
}

# ---------- 데모 영상용 터미널 시각화 ----------
# 초록=성공, 빨강=위협/차단/실패, 하늘색=진행중인 작업, 노랑=Slack 알림.
# 파이프(run-all.sh로 리다이렉트 등)로 나갈 때는 색 코드를 끈다 - 로그
# 파일에 이스케이프 시퀀스가 그대로 남는 걸 피하기 위함.
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_GREEN=$'\033[0;32m'; C_RED=$'\033[0;31m'
  C_CYAN=$'\033[0;36m'; C_YELLOW=$'\033[1;33m'
else
  C_RESET=''; C_BOLD=''; C_GREEN=''; C_RED=''; C_CYAN=''; C_YELLOW=''
fi

ok()    { echo "  ${C_GREEN}✔ $*${C_RESET}"; }
fail()  { echo "  ${C_RED}✘ $*${C_RESET}"; }
step()  { echo "${C_CYAN}${C_BOLD}[STEP $1]${C_RESET} $2"; }
progress() { echo "${C_CYAN}▶ $*${C_RESET}"; }
notice_slack() { echo "  ${C_YELLOW}🔔 $*${C_RESET}"; }
threat() { echo "  ${C_RED}${C_BOLD}⚠ $*${C_RESET}"; }

# scene_banner <2자리 번호> <제목> <step1> <step2> <step3>
scene_banner() {
  local num="$1" title="$2" s1="$3" s2="$4" s3="$5"
  local line="======================================================================"
  echo "${C_BOLD}${line}${C_RESET}"
  echo "${C_BOLD}[SCENE ${num}] ${title}${C_RESET}"
  echo "${C_BOLD}${line}${C_RESET}"
  echo "${C_CYAN}[STEP 1]${C_RESET} ${s1}"
  echo "${C_CYAN}[STEP 2]${C_RESET} ${s2}"
  echo "${C_CYAN}[STEP 3]${C_RESET} ${s3}"
  echo "----------------------------------------------------------------------"
}

# result_box <PASSED|SUCCESS|FAILED> <한줄 설명>
# 성공계열 문구(PASSED/SUCCESS 등)는 전부 초록, 그 외(FAILED 등)만 빨강 -
# 씬마다 "PASSED"/"SUCCESS" 등 문구가 달라도 색이 어긋나지 않게 함.
result_box() {
  local status="$1" desc="$2" color="$C_GREEN"
  case "$status" in
    *FAIL*) color="$C_RED" ;;
  esac
  echo "----------------------------------------------------------------------"
  echo "${color}${C_BOLD}[결과]: ${status}${C_RESET} (${desc})"
  echo "${C_BOLD}======================================================================${C_RESET}"
}
