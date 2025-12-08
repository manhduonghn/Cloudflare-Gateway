#!/usr/bin/env bash
set -euo pipefail

# --- 1. Cấu hình ban đầu ---
LIST_NAME="Ad Blocklist"
LIST_DESC="Daily updated ad-blocking list part"
RULE_NAME="Block Advertising Domains"
PRIORITY=100
MAX_DOMAINS_PER_LIST=1000

# --- Adlists ---
ADLISTS=(
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    "https://small.oisd.nl/domainswild2"
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"
)

TEMPDIR="$(mktemp -d)"
RAW_TEMPFILE="$TEMPDIR/raw_domains.txt"
CLEANFILE="$TEMPDIR/cleaned_domains.txt"

# --- 2. Xử lý tham số dòng lệnh ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --list-name) LIST_NAME="$2"; shift 2 ;;
    --list-desc) LIST_DESC="$2"; shift 2 ;;
    --rule-name) RULE_NAME="$2"; shift 2 ;;
    --priority) PRIORITY="$2"; shift 2 ;;
    --adlists)
      # Ghi đè ADLISTS bằng chuỗi phân cách dấu phẩy
      IFS=',' read -r -a ADLISTS <<< "$2"
      shift 2
      ;;
    *) echo "Unknown argument $1"; exit 1 ;;
  esac
done

# --- 3. Kiểm tra biến môi trường và thiết lập API ---
if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" || -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "❌ Must export CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN"
  exit 2
fi

API_BASE="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}"
CURL_AUTH=(-H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" -H "Content-Type: application/json")

cleanup(){ rm -rf "$TEMPDIR"; }
trap cleanup EXIT

# --- 4. Tải và làm sạch tên miền (ĐÃ DÙNG LOGIC MỚI) ---
echo "1) Fetching and cleaning hostlists..."
> "$RAW_TEMPFILE"

for ADLIST_URL in "${ADLISTS[@]}"; do
    echo " -> Fetching: $ADLIST_URL"
    if [[ "$ADLIST_URL" =~ ^file:// ]]; then
      FILE="${ADLIST_URL#file://}"
      # Xử lý hosts/domain only
      awk '/^[^#]/ {
          if ($1 ~ /^[0-9]/) print $2;
          else if ($1 ~ /^[A-Za-z0-9.-]+$/) print $1;
          else print $0; # Giữ nguyên để hàm extract_domains xử lý sau
      }' "$FILE" >> "$RAW_TEMPFILE"
    else
      curl -fsSL "$ADLIST_URL" | awk '/^[^#]/ {
          if ($1 ~ /^[0-9]/) print $2;
          else if ($1 ~ /^[A-Za-z0-9.-]+$/) print $1;
          else print $0;
      }' >> "$RAW_TEMPFILE"
    fi
done

RAW_COUNT=$(wc -l < "$RAW_TEMPFILE")
echo " -> Raw entries from all lists: $RAW_COUNT"

# --- CLEAN FIX MỚI SIÊU MẠNH ---
echo " → Normalizing and cleaning domains…"

extract_domains() {
  sed -E '
    # Xử lý Adblock/AdGuard: ||domain^... hoặc @@||domain^...
    s/^\|\|([a-zA-Z0-9.-]+)\^.*$/\1/;
    s/^@@\|\|([a-zA-Z0-9.-]+)\^.*$/\1/;
    # Xử lý Dnsmasq/unbound (address=/domain/)
    s/^address=\/([a-zA-Z0-9.-]+)\/.*/\1/;
    # Xử lý hosts file (loại bỏ IP)
    s/^0\.0\.0\.0[[:space:]]+//;
    s/^127\.0\.0\.1[[:space:]]+//;
    s/^::1[[:space:]]+//;
    s/^\[::\][[:space:]]+//;
    s/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+//;
    # Loại bỏ ký tự wildcard ở đầu (thường là * + .)
    s/^[*+.]+//;
  ' | grep -E '^[a-zA-Z0-9.-]+$' # Giữ lại các dòng chỉ chứa ký tự tên miền
}

# Áp dụng các bước làm sạch bổ sung
extract_domains < "$RAW_TEMPFILE" | \
  tr 'A-Z' 'a-z' | \
  grep -vE '\.\.|^\.|\.$|_' | \
  grep -vE '^[0-9.]+$' | \
  sed -E 's/^www\.//' | \
  awk 'length($0) <= 255' | \
  sort -u > "$CLEANFILE"

NUM=$(wc -l < "$CLEANFILE")
echo " → Cleaned valid domains: $NUM"
[[ $NUM -eq 0 ]] && { echo "❌ No valid domains"; exit 4; }

# --- 5. Chia nhỏ tên miền thành các tệp nhỏ (Chunks) ---
NUM_CHUNKS=$(( (NUM + MAX_DOMAINS_PER_LIST - 1) / MAX_DOMAINS_PER_LIST ))
echo "2) Splitting $NUM domains into $NUM_CHUNKS chunks (max $MAX_DOMAINS_PER_LIST/chunk)..."

split -l "$MAX_DOMAINS_PER_LIST" "$CLEANFILE" "$TEMPDIR/chunk."

# --- 6. Tạo/Cập nhật List Gateway và thêm tên miền ---
ALL_LIST_IDS=""
for ((i=1;i<=NUM_CHUNKS;i++)); do
    CHUNK_INDEX=$((i - 1))
    CHUNK_FILE_SUFFIX=$(printf '%s' $CHUNK_INDEX | awk '{
        n=$1; c1=int(n/26); c2=n%26;
        printf("%c%c", 97+c1, 97+c2);
    }')

    CHUNK_FILE="$TEMPDIR/chunk.$CHUNK_FILE_SUFFIX"
    # Kiểm tra tệp chunk có tồn tại không
    if [[ ! -f "$CHUNK_FILE" ]]; then
        # Nếu chunk.aa không tồn tại khi i=1, thì có lỗi. Nếu i > 1 thì có thể bỏ qua.
        if [[ $i -eq 1 ]]; then 
            if [[ ! -f "$TEMPDIR/chunk.aa" ]]; then continue; fi
        else
            continue 
        fi
    fi

    CHUNK_NUM=$(wc -l < "$CHUNK_FILE")
    
    # === PHẦN ĐÃ SỬA: FORMAT SỐ CÓ ĐỆM BẰNG 0 ===
    LIST_NUM_FORMATTED=$(printf "%03d" $i)
    CURRENT_LIST_NAME="$LIST_NAME $LIST_NUM_FORMATTED"
    # ============================================

    echo "---"
    echo "3.$i) Processing List '$CURRENT_LIST_NAME' ($CHUNK_NUM domains)..."

    UPLOAD_ITEMS_PAYLOAD=$(jq -R -s '
        split("\n")[:-1]
        | map(select(length>0))
        | map({value: .})
    ' < "$CHUNK_FILE")

    # Find existing list
    ENCODED_LIST_NAME=$(echo "$CURRENT_LIST_NAME" | sed 's/ /%20/g')
    GET_LIST_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/lists?name=$ENCODED_LIST_NAME")

    LIST_ID=""
    # Lấy ID nếu tên trùng khớp
    EXISTING_LIST_ID=$(echo "$GET_LIST_RESP" | jq -r '.result[]? | select(.name=="'"$CURRENT_LIST_NAME"'") | .id')

    if [[ -n "$EXISTING_LIST_ID" ]]; then
      echo " → Found existing list ID: $EXISTING_LIST_ID. Replacing items..."
      LIST_ID="$EXISTING_LIST_ID"

      # 1. Xóa items cũ (tránh lỗi API khi PATCH quá lớn)
      GET_ITEMS_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/lists/$LIST_ID/items?per_page=1000")
      EXISTING_VALUES=$(echo "$GET_ITEMS_RESP" | jq -r '.result[].value')
      
      if [[ -n "$EXISTING_VALUES" ]]; then
        REMOVE_ARRAY=$(echo "$EXISTING_VALUES" | jq -R -s 'split("\n")[:-1]')
        REMOVE_PAYLOAD=$(jq -n --argjson remove "$REMOVE_ARRAY" '{remove:$remove}')
        PATCH_REMOVE_RESP=$(curl -sS -X PATCH "${CURL_AUTH[@]}" --data-raw "$REMOVE_PAYLOAD" "$API_BASE/gateway/lists/$LIST_ID")
        echo "$PATCH_REMOVE_RESP" | jq -e '.success == true' >/dev/null || { echo "❌ Failed to remove old items"; exit 10; }
      fi
      
      # 2. Thêm items mới
      APPEND_PAYLOAD=$(jq -n --argjson items "$UPLOAD_ITEMS_PAYLOAD" '{append:$items}')
      PATCH_APPEND_RESP=$(curl -sS -X PATCH "${CURL_AUTH[@]}" --data-raw "$APPEND_PAYLOAD" "$API_BASE/gateway/lists/$LIST_ID")
      echo "$PATCH_APPEND_RESP" | jq -e '.success == true' >/dev/null || { echo "❌ Failed to append new items"; exit 10; }
      echo " → Items replaced successfully."

    else
      # Create new
      echo " → List not found. Creating new list..."
      CREATE_PAYLOAD=$(jq -n \
        --arg name "$CURRENT_LIST_NAME" \
        --arg desc "$LIST_DESC (Part $LIST_NUM_FORMATTED)" \
        --argjson items "$UPLOAD_ITEMS_PAYLOAD" \
        '{name:$name, type:"DOMAIN", description:$desc, items:$items}'
      )
      CREATE_RESP=$(curl -sS -X POST "${CURL_AUTH[@]}" --data-raw "$CREATE_PAYLOAD" "$API_BASE/gateway/lists")
      LIST_ID=$(echo "$CREATE_RESP" | jq -r '.result.id')
      echo "$CREATE_RESP" | jq -e '.success == true' >/dev/null || { echo "❌ Failed to create list"; exit 5; }
      echo " → Created new list ID: $LIST_ID"
    fi

    ALL_LIST_IDS+="$LIST_ID "
done

# --- 7. Cập nhật/Tạo Gateway DNS blocking rule ---
echo "---"
echo "4) Checking existing DNS blocking rule '$RULE_NAME'..."

ENCODED_RULE_NAME=$(echo "$RULE_NAME" | sed 's/ /%20/g')
GET_RULE_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/rules?name=$ENCODED_RULE_NAME")

EXISTING_RULE_ID=$(echo "$GET_RULE_RESP" | jq -r '.result[]? | select(.name=="'"$RULE_NAME"'") | .id')

LIST_ID_ARRAY=($ALL_LIST_IDS)
TRAFFIC_EXPRESSION=""
for id in "${LIST_ID_ARRAY[@]}"; do
   TRAFFIC_EXPRESSION+="any(dns.domains[*] in \$$id) or "
done
TRAFFIC_EXPRESSION="${TRAFFIC_EXPRESSION% or }"

# Lấy số thứ tự đầu tiên và cuối cùng để hiển thị trong mô tả (ví dụ: 001 đến 005)
FIRST_LIST_NUM=$(printf "%03d" 1)
LAST_LIST_NUM=$(printf "%03d" $NUM_CHUNKS)

RULE_PAYLOAD=$(jq -n --arg name "$RULE_NAME" \
  --arg desc "Block ads using $NUM_CHUNKS lists: $LIST_NAME $FIRST_LIST_NUM to $LAST_LIST_NUM" \
  --argjson pri "$PRIORITY" \
  --arg traffic "$TRAFFIC_EXPRESSION" \
  '{
     name:$name, description:$desc, enabled:true,
     precedence:$pri, action:"block", filters:["dns"],
     traffic:$traffic
   }'
)

if [[ -n "$EXISTING_RULE_ID" ]]; then
  RESP_RULE=$(curl -sS -X PUT "${CURL_AUTH[@]}" --data-raw "$RULE_PAYLOAD" "$API_BASE/gateway/rules/$EXISTING_RULE_ID")
  RULE_ID="$EXISTING_RULE_ID"
else
  RESP_RULE=$(curl -sS -X POST "${CURL_AUTH[@]}" --data-raw "$RULE_PAYLOAD" "$API_BASE/gateway/rules")
  RULE_ID=$(echo "$RESP_RULE" | jq -r '.result.id')
fi

echo "$RESP_RULE" | jq -e '.success == true' >/dev/null || { echo "❌ Failed to create/update rule"; exit 6; }
echo " → Rule ID: $RULE_ID"

# --- 8. Cleanup old lists ---
echo "---"
echo "5) Removing unused lists..."

GET_ALL_LISTS_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/lists?per_page=100")
CURRENT_LIST_IDS=$(echo "$ALL_LIST_IDS" | tr ' ' '\n' | sort -u)

# Vẫn tìm theo tiền tố $LIST_NAME để xác định tất cả các phần của list này (cũ và mới)
LISTS_TO_DELETE=$(echo "$GET_ALL_LISTS_RESP" | jq -r '
  .result[]? | select(.name | startswith("'"$LIST_NAME"'"))
  | "\(.id) \(.name)"
')

DELETED_COUNT=0
if [[ -n "$LISTS_TO_DELETE" ]]; then
  while IFS= read -r line; do
    ID=$(echo "$line" | awk '{print $1}')
    NAME=$(echo "$line" | cut -d' ' -f2-)

    # Chỉ xóa nếu ID không nằm trong danh sách CURRENT_LIST_IDS (các list đã được cập nhật/sử dụng)
    if ! echo "$CURRENT_LIST_IDS" | grep -q "^$ID$"; then
      DELETE_RESP=$(curl -sS -X DELETE "${CURL_AUTH[@]}" "$API_BASE/gateway/lists/$ID")
      echo "$DELETE_RESP" | jq -e '.success == true' >/dev/null && {
        echo " → Deleted old list: $NAME ($ID)"
        ((DELETED_COUNT++))
      } || {
        echo " → ⚠️ Failed to delete list: $NAME ($ID). API error: $(echo "$DELETE_RESP" | jq -r '.errors[].message')"
      }
    fi
  done <<< "$LISTS_TO_DELETE"
fi

echo "=========================================="
echo " ✅ DONE"
echo "  Total domains processed: $NUM"
echo "  Total lists created/updated: $NUM_CHUNKS (e.g., $LIST_NAME $FIRST_LIST_NUM to $LAST_LIST_NUM)"
echo "  Total lists deleted: $DELETED_COUNT"
echo "  RULE ID: $RULE_ID"
echo "=========================================="
