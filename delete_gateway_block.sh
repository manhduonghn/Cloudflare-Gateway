#!/usr/bin/env bash
set -euo pipefail

# ============================
# CONFIG
# ============================
LIST_NAME="Ad Blocklist"        # prefix của list
RULE_NAME="Block Advertising Domains"

if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" || -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "❌ Must export CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN"
  exit 2
fi

API_BASE="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}"
CURL_AUTH=(-H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" -H "Content-Type: application/json")


echo "======================================="
echo "   🧨 DELETE GATEWAY RULE & LISTS"
echo "======================================="

# ==================================================
# 1) DELETE RULE
# ==================================================
echo ""
echo "1) Checking for rule: \"$RULE_NAME\""

ENC_RULE_NAME=$(echo "$RULE_NAME" | sed 's/ /%20/g')
RULE_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/rules?name=$ENC_RULE_NAME")

# Nếu không có rule thì RULE_ID sẽ rỗng, không lỗi
RULE_ID=$(echo "$RULE_RESP" | jq -r '.result[]? | select(.name=="'"$RULE_NAME"'") | .id')

if [[ -z "$RULE_ID" ]]; then
    echo " → Rule not found — skipping."
else
    echo " → Found Rule: $RULE_NAME"
    echo "   ID: $RULE_ID"
    echo " → Deleting rule..."

    DELETE_RULE_RESP=$(curl -sS -X DELETE "${CURL_AUTH[@]}" "$API_BASE/gateway/rules/$RULE_ID")
    OK=$(echo "$DELETE_RULE_RESP" | jq -r '.success // empty')

    if [[ "$OK" == "true" ]]; then
        echo " ✔ Rule deleted successfully"
    else
        echo " ❌ Failed to delete rule!"
        echo "$DELETE_RULE_RESP" | jq .
    fi
fi


# ==================================================
# 2) DELETE LISTS (THEO TÊN PREFIX)
# ==================================================
echo ""
echo "2) Searching Gateway Lists starting with: \"$LIST_NAME \""

LISTS_RESP=$(curl -sS -X GET "${CURL_AUTH[@]}" "$API_BASE/gateway/lists?per_page=2000")

# Trích ra từng object khớp tên — nếu không có thì MATCHED_LISTS rỗng
MATCHED_LISTS=$(echo "$LISTS_RESP" | jq -c '.result[]? | select(.name | startswith("'"$LIST_NAME "'"))')

if [[ -z "$MATCHED_LISTS" ]]; then
    echo " → No lists found with prefix: \"$LIST_NAME \""
    exit 0
fi

echo ""
echo " → Found Lists:"
printf "%-30s %-40s\n" "LIST NAME" "LIST ID"
printf "%-30s %-40s\n" "------------------------------" "----------------------------------------"

LIST_IDS=()

while IFS= read -r item; do
    NAME=$(echo "$item" | jq -r '.name // empty')
    ID=$(echo "$item" | jq -r '.id // empty')

    [[ -z "$ID" ]] && continue   # skip an toàn

    LIST_IDS+=("$ID")
    printf "%-30s %-40s\n" "$NAME" "$ID"
done <<< "$MATCHED_LISTS"

echo ""
echo " → Deleting lists..."

for ID in "${LIST_IDS[@]}"; do
    NAME=$(echo "$MATCHED_LISTS" | jq -r 'select(.id=="'"$ID"'") | .name // empty')

    echo ""
    echo "   • List Name : $NAME"
    echo "     ID        : $ID"
    echo "     → Deleting..."

    DEL_LIST_RESP=$(curl -sS -X DELETE "${CURL_AUTH[@]}" "$API_BASE/gateway/lists/$ID")
    OK=$(echo "$DEL_LIST_RESP" | jq -r '.success // empty')

    if [[ "$OK" == "true" ]]; then
        echo "     ✔ Deleted successfully"
    else
        echo "     ❌ Failed to delete!"
        echo "$DEL_LIST_RESP" | jq .
    fi
done

echo ""
echo "======================================="
echo "   🎉 DONE — RULE & LISTS REMOVED"
echo "======================================="
