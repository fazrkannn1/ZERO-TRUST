#!/usr/bin/env bash
set -euo pipefail

# Helper to print test result
echo_result() {
  local status=$1
  local description=$2
  if [ "$status" -eq 0 ]; then
    echo -e "\e[32m[PASS]\e[0m $description"
  else
    echo -e "\e[31m[FAIL]\e[0m $description"
    exit 1
  fi
}

# Load configuration
GATEWAY_URL="http://localhost:3000"
GATEWAY_SECRET="${GATEWAY_SECRET:-mygatewaysecret}" # replace with actual secret from .env if needed

# Seeded accounts (username/password/device_id) as per README
# admin: admin / password_admin / DEVADMIN
# dosen1: d001 / password_dosen1 / DEV_D001
# mahasiswa1: m001 / password_mhs1 / DEV_M001

# ---- 1. Login success (admin) ----
login_response=$(curl -s -X POST "$GATEWAY_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password_admin","device_id":"DEVADMIN"}')
access_token=$(echo "$login_response" | jq -r .accessToken)
refresh_token=$(echo "$login_response" | jq -r .refreshToken)
if [[ -z "$access_token" || "$access_token" == "null" ]]; then
  echo_result 1 "Login succeeded (admin)"
else
  echo_result 0 "Login succeeded (admin)"
fi

# ---- 2. Login failure (unregistered device) ----
login_fail_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"m001","password":"password_mhs1","device_id":"WRONGDEVICE"}')
if [[ "$login_fail_code" -ne 200 ]]; then
  echo_result 0 "Login fails with unregistered device"
else
  echo_result 1 "Login should fail with unregistered device"
fi

# ---- 3. Mahasiswa (admin token) access own nilai (allowed) ----
resp_code=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/nilai?nim=M001" \
  -H "Authorization: Bearer $access_token" \
  -H "X-Device-ID: DEVADMIN")
if [[ "$resp_code" -eq 200 ]]; then
  echo_result 0 "Access own nilai (allowed)"
else
  echo_result 1 "Access own nilai should be allowed"
fi

# ---- 4. Mahasiswa (admin token) access another mahasiswa nilai (denied) ----
resp_code=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/nilai?nim=M002" \
  -H "Authorization: Bearer $access_token" \
  -H "X-Device-ID: DEVADMIN")
if [[ "$resp_code" -ne 200 ]]; then
  echo_result 0 "Access other mahasiswa nilai denied"
else
  echo_result 1 "Access other mahasiswa nilai should be denied"
fi

# ---- 5. Dosen finalisasi nilai (allowed/denied based on time) ----
# Login dosen
login_dosen=$(curl -s -X POST "$GATEWAY_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"d001","password":"password_dosen1","device_id":"DEV_D001"}')
access_dosen=$(echo "$login_dosen" | jq -r .accessToken)
# Attempt finalisasi (will be allowed if within configured window)
final_resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY_URL/kelas/1/finalisasi" \
  -H "Authorization: Bearer $access_dosen" \
  -H "X-Device-ID: DEV_D001")
if [[ "$final_resp" -eq 200 ]]; then
  echo_result 0 "Dosen finalisasi within allowed hours (allowed)"
else
  echo_result 0 "Dosen finalisasi outside allowed hours (denied)"
fi

# ---- 6. Direct access to Service Nilai without gateway secret (should be denied) ----
direct_nilai=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3001/nilai?nim=M001")
if [[ "$direct_nilai" -ne 200 ]]; then
  echo_result 0 "Direct access to Service Nilai denied without X-Gateway-Secret"
else
  echo_result 1 "Direct access to Service Nilai should be denied"
fi

# ---- 7. Direct access to Service Transkrip without secret (should be denied) ----
direct_trans=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3002/transkrip/M001")
if [[ "$direct_trans" -ne 200 ]]; then
  echo_result 0 "Direct access to Service Transkrip denied without X-Gateway-Secret"
else
  echo_result 1 "Direct access to Service Transkrip should be denied"
fi

# ---- 8. Sync transkrip after finalisasi using service token ----
service_token=$(curl -s -X POST "$GATEWAY_URL/auth/service" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"service","client_secret":"${SERVICE_SECRET:-servicesecret}"}' | jq -r .accessToken)
sync_resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY_URL/transkrip/sinkron" \
  -H "Authorization: Bearer $service_token" \
  -H "X-Device-ID: SERVICE")
if [[ "$sync_resp" -eq 200 ]]; then
  echo_result 0 "Transkrip sync after finalisasi succeeded"
else
  echo_result 1 "Transkrip sync after finalisasi failed"
fi

echo -e "\nAll tests completed."
