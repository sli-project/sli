#!/usr/bin/env bash
# Authentication failures still prove that the API answered; do not send credentials.
watchdog_network() {
  local url code failed=0
  for url in https://github.com https://api.openai.com; do
    code=$(timeout -k 2 15 curl --silent --output /dev/null --write-out '%{http_code}' \
      --connect-timeout 15 --max-time 15 "$url" 2>/dev/null) || code=000
    [[ "$code" =~ ^[1-5][0-9]{2}$ ]] || failed=1
  done
  if (( failed )); then
    NETWORK=offline
    note 'Сеть: нет ответа (перезапустите VPN)'
    return 1
  fi
  NETWORK=online
  note 'Сеть: доступна.'
}
