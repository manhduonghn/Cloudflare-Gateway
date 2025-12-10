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
      IFS=',' read -r -a ADLISTS <<< "$2"
      shift 2
      ;;
    *) echo "Unknown argument $1"; exit 1 ;;
  esac
done

# --- 3. Kiểm tra biến môi trường ---
if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" || -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "❌ Must export CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN"
  exit 2
fi

API_BASE="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}"
CURL_AUTH=(-H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" -H "Content-Type: application/json")

cleanup(){ rm -rf "$TEMPDIR"; }
trap cleanup EXIT

# --- 4. Tải & làm sạch domain ---
echo "1) Fetching and cleaning hostlists..."
> "$RAW_TEMPFILE"

for ADLIST_URL in "${ADLISTS[@]}"; do
    echo " -> Fetching: $ADLIST_URL"
    if [[ "$ADLIST_URL" =~ ^file:// ]]; then
      FILE="${ADLIST_URL#file://}"
      awk '/^[^#]/ {
          if ($1 ~ /^[0-9]/) print $2;
          else if ($1 ~ /^[A-Za-z0-9.-]+$/) print $1;
          else print $0;
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
echo " -> Raw entries: $RAW_COUNT"

extract_domains() {
  sed -E '
    s/^\|\|([a-zA-Z0-9.-]+)\^.*$/\1/;
    s/^@@\|\|([a-zA-Z0-9.-]+)\^.*$/\1/;
    s/^address=\/([a-zA-Z0-9.-]+)\/.*/\1/;
    s/^0\.0\.0\.0[[:space:]]+//;
    s/^127\.0\.0\.1[[:space:]]+//;
    s/^::1[[:space:]]+//;
    s/^\[::\][[:space:]]+//;
    s/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+//;
    s/^[*+.]+//;
  ' | grep -E '^[a-zA-Z0-9.-]+$'
}

extract_domains < "$RAW_TEMPFILE" | \
  tr 'A-Z' 'a-z' | \
  grep -vE '\.\.|^\.|\.$|_' | \
  grep -vE '^[0-9.]+$' | \
  sed -E 's/^www\.//' | \
  grep -vE '^-|-$' | \
  awk 'length($0) <= 255' | \
  sort -u > "$CLEANFILE"

NUM=$(wc -l < "$CLEANFILE")
echo " → Cleaned: $NUM"

[[ $NUM -eq 0 ]] && { echo "❌ No valid domains"; exit 4; }

# --- 5. Chia nhỏ ---
NUM_CHUNKS=$(( (NUM + MAX_DOMAINS_PER_LIST - 1) / MAX_DOMAINS_PER_LIST ))
echo "2) Splitting into $NUM_CHUNKS chunks..."

split -l "$MAX_DOMAINS_PER_LIST" "$CLEANFILE" "$TEMPDIR/chunk."

# --- 6. Tạo/Cập nhật list ---
ALL_LIST_IDS=""

for ((i=1;i<=NUM_CHUNKS;i++)); do
    CHUNK_INDEX=$((i - 1))
    CHUNK_FILE_SUFFIX=$(printf '%s' $CHUNK_INDEX | awk '{n=$1; c1=int(n/26); c2=n%26; printf("%c%c",97+c1,97+c2);}')
    CHUNK_FILE="$TEMPDIR/chunk.$CHUNK_FILE_SUFFIX"

    [[ ! -f "$CHUNK_FILE" ]] && continue

    CHUNK_NUM=$(wc -l < "$CHUNK_FILE")
    LIST_NUM=$(printf "%03d" $i)
    CURRENT_LIST_NAME="$LIST_NAME $LIST_NUM"

    echo "---"
    echo "3.$i) Processing list: $CURRENT_LIST_NAME ($CHUNK_NUM items)"

    GET_LIST_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/lists?name=$(echo "$CURRENT_LIST_NAME" | sed 's/ /%20/g')")
    EXISTING_LIST_ID=$(echo "$GET_LIST_RESP" | jq -r '.result[]? | select(.name=="'"$CURRENT_LIST_NAME"'") | .id')

    if [[ -n "$EXISTING_LIST_ID" ]]; then
        echo " → Found list ID: $EXISTING_LIST_ID"
        LIST_ID="$EXISTING_LIST_ID"

        # ==== DIFF-BASED UPDATE ====
        GET_ITEMS_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" \
            "$API_BASE/gateway/lists/$LIST_ID/items?per_page=1000")

        mapfile -t OLD_ITEMS < <(echo "$GET_ITEMS_RESP" | jq -r '.result[].value')
        mapfile -t NEW_ITEMS < <(cat "$CHUNK_FILE")

        REMOVE_SET=$(comm -23 \
            <(printf "%s\n" "${OLD_ITEMS[@]}" | sort -u) \
            <(printf "%s\n" "${NEW_ITEMS[@]}" | sort -u)
        )

        ADD_SET=$(comm -13 \
            <(printf "%s\n" "${OLD_ITEMS[@]}" | sort -u) \
            <(printf "%s\n" "${NEW_ITEMS[@]}" | sort -u)
        )

        if [[ -n "$REMOVE_SET" ]]; then
            REMOVE_PAYLOAD=$(printf "%s\n" "$REMOVE_SET" | jq -R -s 'split("\n")[:-1]' | jq '{remove: .}')
            RESP_RM=$(curl -sS -X PATCH "${CURL_AUTH[@]}" \
                --data-raw "$REMOVE_PAYLOAD" \
                "$API_BASE/gateway/lists/$LIST_ID")
            echo "   → Removed: $(printf "%s\n" $REMOVE_SET | wc -l)"
        fi

        if [[ -n "$ADD_SET" ]]; then
            ADD_PAYLOAD=$(printf "%s\n" "$ADD_SET" | jq -R -s 'split("\n")[:-1] | map({value: .})' | jq '{append: .}')
            RESP_ADD=$(curl -sS -X PATCH "${CURL_AUTH[@]}" \
                --data-raw "$ADD_PAYLOAD" \
                "$API_BASE/gateway/lists/$LIST_ID")
            echo "   → Added: $(printf "%s\n" $ADD_SET | wc -l)"
        fi

        echo " → Diff update completed."

    else
        # Create new list
        echo " → Creating new list..."
        UPLOAD_ITEMS_PAYLOAD=$(jq -R -s '
            split("\n")[:-1] | map(select(length>0)) | map({value: .})
        ' < "$CHUNK_FILE")

        CREATE_PAYLOAD=$(jq -n \
            --arg name "$CURRENT_LIST_NAME" \
            --arg desc "$LIST_DESC (Part $LIST_NUM)" \
            --argjson items "$UPLOAD_ITEMS_PAYLOAD" \
            '{name:$name, type:"DOMAIN", description:$desc, items:$items}'
        )
        CREATE_RESP=$(curl -sS -X POST "${CURL_AUTH[@]}" --data-raw "$CREATE_PAYLOAD" "$API_BASE/gateway/lists")
        LIST_ID=$(echo "$CREATE_RESP" | jq -r '.result.id')
        echo " → Created: $LIST_ID"
    fi

    ALL_LIST_IDS+="$LIST_ID "
done

# --- 7. Update rule ---
echo "---"
echo "4) Updating rule..."

ENCODED_RULE=$(echo "$RULE_NAME" | sed 's/ /%20/g')
GET_RULE=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/rules?name=$ENCODED_RULE")
EXISTING_RULE_ID=$(echo "$GET_RULE" | jq -r '.result[]? | select(.name=="'"$RULE_NAME"'") | .id')

LIST_ID_ARRAY=($ALL_LIST_IDS)
TRAFFIC=""
for id in "${LIST_ID_ARRAY[@]}"; do
   TRAFFIC+="any(dns.domains[*] in \$$id) or "
done
TRAFFIC="${TRAFFIC% or }"

FIRST=$(printf "%03d" 1)
LAST=$(printf "%03d" $NUM_CHUNKS)

RULE_PAYLOAD=$(jq -n \
  --arg name "$RULE_NAME" \
  --arg desc "Block ads using $NUM_CHUNKS lists: $LIST_NAME $FIRST to $LAST" \
  --argjson pri "$PRIORITY" \
  --arg traffic "$TRAFFIC" \
  '{name:$name, description:$desc, enabled:true,
    precedence:$pri, action:"block", filters:["dns"],
    traffic:$traffic}'
)

if [[ -n "$EXISTING_RULE_ID" ]]; then
  RESP_RULE=$(curl -sS -X PUT "${CURL_AUTH[@]}" --data-raw "$RULE_PAYLOAD" "$API_BASE/gateway/rules/$EXISTING_RULE_ID")
  RULE_ID="$EXISTING_RULE_ID"
else
  RESP_RULE=$(curl -sS -X POST "${CURL_AUTH[@]}" --data-raw "$RULE_PAYLOAD" "$API_BASE/gateway/rules")
  RULE_ID=$(echo "$RESP_RULE" | jq -r '.result.id')
fi

echo " → Rule ID: $RULE_ID"

# --- 8. Cleanup lists cũ không dùng ---
echo "---"
echo "5) Removing unused lists..."

GET_ALL_LISTS=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/lists?per_page=200")
CURRENT_IDS=$(echo "$ALL_LIST_IDS" | tr ' ' '\n' | sort -u)

LISTS_TO_DELETE=$(echo "$GET_ALL_LISTS" | jq -r '
  .result[]? | select(.name | startswith("'"$LIST_NAME"'")) | "\(.id) \(.name)"
')

DELETED=0

if [[ -n "$LISTS_TO_DELETE" ]]; then
  while IFS= read -r line; do
    ID=$(echo "$line" | awk '{print $1}')
    NAME=$(echo "$line" | cut -d' ' -f2-)

    if ! echo "$CURRENT_IDS" | grep -q "^$ID$"; then
      DEL=$(curl -sS -X DELETE "${CURL_AUTH[@]}" "$API_BASE/gateway/lists/$ID")
      if echo "$DEL" | jq -e '.success == true' >/dev/null; then
        echo " → Deleted old list: $NAME ($ID)"
        ((DELETED++))
      fi
    fi
  done <<< "$LISTS_TO_DELETE"
fi

echo "=========================================="
echo " ✅ DONE"
echo "  Total domains: $NUM"
echo "  Lists updated/created: $NUM_CHUNKS"
echo "  Deleted old lists: $DELETED"
echo "  Rule ID: $RULE_ID"
echo "=========================================="
