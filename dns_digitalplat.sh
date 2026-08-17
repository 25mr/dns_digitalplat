#!/usr/bin/env sh
# DigitalPlat DNS API hook for acme.sh
# Base: https://domain-api.digitalplat.org/api/v1

DP_API="https://domain-api.digitalplat.org/api/v1"

########  Public functions  ########

dns_digitalplat_add() {
  fulldomain=$1
  txtvalue=$2

  DIGITALPLAT_API_KEY="${DIGITALPLAT_API_KEY:-$(_readaccountconf_mutable DIGITALPLAT_API_KEY)}"
  if [ -z "$DIGITALPLAT_API_KEY" ]; then
    _err "Please set it up first: export DIGITALPLAT_API_KEY=dp_live_xxx"
    return 1
  fi
  _saveaccountconf_mutable DIGITALPLAT_API_KEY "$DIGITALPLAT_API_KEY"

  if ! _get_root "$fulldomain"; then
    _err "Can't find a registered domain for $fulldomain in your account"
    return 1
  fi
  _debug _domain "$_domain"
  _debug _sub "$_sub"

  _info "DigitalPlat: Create a TXT record $_sub.$_domain"
  _dp_set_headers
  _data="{\"type\":\"TXT\",\"name\":\"$_sub\",\"ttl\":300,\"values\":[\"$txtvalue\"]}"

  response="$(_post "$_data" "$DP_API/domains/$_domain/dns/records" "" "POST" "application/json")"
  _debug response "$response"

  if _contains "$response" '"success": true' || _contains "$response" '"success":true'; then
    _info "DigitalPlat: The TXT record has been submitted"
    return 0
  fi
  _err "DigitalPlat: Creation failed: $response"
  return 1
}

dns_digitalplat_rm() {
  fulldomain=$1
  txtvalue=$2

  DIGITALPLAT_API_KEY="${DIGITALPLAT_API_KEY:-$(_readaccountconf_mutable DIGITALPLAT_API_KEY)}"

  if ! _get_root "$fulldomain"; then
    _err "Can't determine the registered domain for $fulldomain"
    return 1
  fi

  _info "DigitalPlat: Check the record ID for $_sub.$_domain"
  _dp_set_headers
  list="$(_get "$DP_API/domains/$_domain/dns/records")"
  _debug list "$list"

  _record_id="$(_dp_find_id "$list" "$_sub" "$txtvalue")"
  _debug _record_id "$_record_id"

  if [ -z "$_record_id" ]; then
    _info "DigitalPlat: No matching records found, skipping (won't affect issuance)"
    return 0
  fi

  _dp_set_headers
  response="$(_post "" "$DP_API/domains/$_domain/dns/records/$_record_id" "" "DELETE" "application/json")"
  _debug response "$response"

  if _contains "$response" '"success": true' || _contains "$response" '"success":true'; then
    _info "DigitalPlat: Deleted record $_record_id"
  else
    _info "DigitalPlat: Delete unconfirmed (leftover TXT doesn't affect usage): $response"
  fi
  return 0
}

########  Private helpers  ########

_dp_set_headers() {
  _idem="$(_dp_uuid)"
  export _H1="Authorization: Bearer $DIGITALPLAT_API_KEY"
  export _H2="Idempotency-Key: $_idem"
  export _H3="Content-Type: application/json"
}

_dp_uuid() {
  if _exists openssl; then
    openssl rand -hex 16 2>/dev/null && return 0
  fi
  printf "%s%s%s" "$(date +%s 2>/dev/null)" "$$" "${RANDOM:-0}"
}

_get_root() {
  domain=$1

  _dp_set_headers
  _domains_json="$(_get "$DP_API/domains")"
  _debug2 _domains_json "$_domains_json"

  i=2
  p=1
  while true; do
    h="$(printf "%s" "$domain" | cut -d . -f "$i"-100)"
    [ -z "$h" ] && break
    if _contains "$_domains_json" "\"name\": \"$h\"" || _contains "$_domains_json" "\"name\":\"$h\""; then
      _sub="$(printf "%s" "$domain" | cut -d . -f 1-"$p")"
      _domain="$h"
      return 0
    fi
    p="$i"
    i="$(_math "$i" + 1)"
  done
  return 1
}

_dp_find_id() {
  _json="$1"
  _want_name="$2"
  _want_val="$3"

  printf "%s" "$_json" \
    | tr '}' '\n' \
    | while read -r line; do
        case "$line" in
          *"\"name\": \"$_want_name\""*|*"\"name\":\"$_want_name\""*)
            case "$line" in
              *"$_want_val"*)
                printf "%s" "$line" \
                  | sed -n 's/.*"id"[ ]*:[ ]*"\([^"]*\)".*/\1/p'
                return 0
                ;;
            esac
            ;;
        esac
      done
}
