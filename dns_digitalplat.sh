#!/usr/bin/env sh
# DigitalPlat DNS API hook for acme.sh
#
# Publishes and removes the DNS-01 TXT challenge through DigitalPlat Hosted
# DNS, using only the endpoints documented in the DigitalPlat API schema:
#   GET    /domains
#   GET    /domains/{domain}/dns
#   GET    /domains/{domain}/dns/records
#   POST   /domains/{domain}/dns/records
#   DELETE /domains/{domain}/dns/records/{record_id}
#
# Requirements:
#   jq, plus curl or wget (provided by acme.sh itself).
#
# Environment:
#   DIGITALPLAT_API_KEY   required, the `dp_live_...` API key.
#                         Stored in account.conf after the first run.
#   DIGITALPLAT_API_BASE  optional, default https://domain-api.digitalplat.org/api/v1
#   DIGITALPLAT_DOMAIN    optional, pin the zone that owns the challenge record
#                         (skips the GET /domains lookup).
#   DIGITALPLAT_TTL       optional, TXT record TTL in seconds, default 300.
#
# State:
#   The hook remembers which challenge values this run published in
#   <DOMAIN_PATH>/digitalplat_dns.state, so a multi-value RRset is removed only
#   when every value in it belongs to this run. If that file cannot be written,
#   shared RRsets are simply left alone (conservative).
#
# Usage:
#   export DIGITALPLAT_API_KEY="dp_live_xxxxxxxxxxxxxxxxx"
#   acme.sh --issue --dns dns_digitalplat -d example.com -d '*.example.com'
#
#   The TXT records are deleted again once the challenge has been validated.
#
# This file is loaded by acme.sh; it relies on the acme.sh helpers _get, _post,
# _err, _info, _debug, _debug2, _readaccountconf_mutable and
# _saveaccountconf_mutable.

DP_API="${DIGITALPLAT_API_BASE:-https://domain-api.digitalplat.org/api/v1}"
DP_API="${DP_API%/}"
DP_DEFAULT_TTL=300

######## Public functions ########

dns_digitalplat_add() {
  DP_FQDN=$1
  DP_TXT_VALUE=$2

  if [ -z "$DP_FQDN" ] || [ -z "$DP_TXT_VALUE" ]; then
    _err "DigitalPlat: add requires a fully-qualified name and TXT value"
    return 1
  fi

  _dp_init || return 1
  _dp_resolve_zone "$DP_FQDN" || return 1
  _dp_check_zone || return 1
  if [ "$DP_ZONE_USABLE" != "yes" ]; then
    _err "DigitalPlat: cannot publish records for $DP_ZONE because Hosted DNS is not active"
    return 1
  fi

  DP_RECORDS_JSON="$(_dp_list_records)" || return 1

  if ! DP_MATCHES="$(printf '%s' "$DP_RECORDS_JSON" | _dp_match_records "$DP_ZONE" "$DP_FQDN" "$DP_TXT_VALUE" "$DP_STATE_FILE")"; then
    _err "DigitalPlat: could not parse the DNS-record list"
    return 1
  fi

  # Avoid creating a duplicate if acme.sh retries this same challenge.
  if [ -n "$DP_MATCHES" ]; then
    DP_MATCH_LINE="$(printf '%s\n' "$DP_MATCHES" | sed -n '1p')"
    IFS='|' read -r DP_MATCH_ID _ DP_MATCH_DISABLED _ _ <<EOF
$DP_MATCH_LINE
EOF
    if [ "$DP_MATCH_DISABLED" = "true" ]; then
      _err "DigitalPlat: a matching TXT record exists at $DP_FQDN but is disabled (id: $DP_MATCH_ID); enable it in the DigitalPlat panel and retry"
      return 1
    fi
    _info "DigitalPlat: matching TXT record already exists at $DP_FQDN (id: $DP_MATCH_ID); skipping create"
    _dp_state_add "$DP_FQDN" "$DP_TXT_VALUE"
    return 0
  fi

  DP_REQUEST_JSON="$(jq -cn \
    --arg name "$DP_SUB" \
    --arg value "$DP_TXT_VALUE" \
    --argjson ttl "$DP_TTL" \
    '{type:"TXT", name:$name, ttl:$ttl, values:[$value]}')" || {
    _err "DigitalPlat: could not encode the TXT record request as JSON"
    return 1
  }

  if ! DP_RESPONSE="$(_dp_post_api "/domains/$DP_ZONE/dns/records" "$DP_REQUEST_JSON")"; then
    _dp_report_api_error "create TXT record (transport error)" "$DP_RESPONSE"
    return 1
  fi
  _debug2 "DigitalPlat create response" "$DP_RESPONSE"
  _dp_expect_success "create TXT record" "$DP_RESPONSE" || return 1

  _dp_state_add "$DP_FQDN" "$DP_TXT_VALUE"
  _info "DigitalPlat: TXT record submitted for $DP_FQDN (name: $DP_SUB, ttl: $DP_TTL)"
  return 0
}

dns_digitalplat_rm() {
  DP_FQDN=$1
  DP_TXT_VALUE=$2

  if [ -z "$DP_FQDN" ] || [ -z "$DP_TXT_VALUE" ]; then
    _err "DigitalPlat: remove requires a fully-qualified name and TXT value"
    return 1
  fi

  _dp_init || return 1
  _dp_resolve_zone "$DP_FQDN" || return 1
  _dp_check_zone || return 1
  if [ "$DP_ZONE_USABLE" != "yes" ]; then
    # Nothing is managed through the Hosted DNS API, so cleanup is a no-op.
    _info "DigitalPlat: $DP_ZONE is not served by Hosted DNS; no record to delete"
    return 0
  fi

  DP_RECORDS_JSON="$(_dp_list_records)" || return 1

  if ! DP_MATCHES="$(printf '%s' "$DP_RECORDS_JSON" | _dp_match_records "$DP_ZONE" "$DP_FQDN" "$DP_TXT_VALUE" "$DP_STATE_FILE")"; then
    _err "DigitalPlat: could not parse the DNS-record list"
    return 1
  fi

  if [ -z "$DP_MATCHES" ]; then
    _info "DigitalPlat: no matching TXT record found; nothing to delete"
    return 0
  fi

  DP_RM_FAILED=0
  while IFS='|' read -r DP_RECORD_ID DP_RECORD_PROTECTED DP_RECORD_DISABLED DP_RECORD_SHARED DP_RECORD_OWNED; do
    [ -z "$DP_RECORD_ID" ] && continue

    # API IDs are opaque path components; accept the documented hex IDs and
    # UUID-style IDs, but refuse unexpected characters before building a URL.
    case "$DP_RECORD_ID" in
    *[!A-Za-z0-9_-]*)
      _err "DigitalPlat: refusing unexpected record ID from API"
      DP_RM_FAILED=1
      continue
      ;;
    esac

    if [ "$DP_RECORD_PROTECTED" = "true" ]; then
      _info "DigitalPlat: record $DP_RECORD_ID is protected by DigitalPlat; leaving it in place"
      continue
    fi
    if [ "$DP_RECORD_DISABLED" = "true" ]; then
      _debug "DigitalPlat: record $DP_RECORD_ID was disabled"
    fi
    if [ "$DP_RECORD_SHARED" = "true" ] && [ "$DP_RECORD_OWNED" != "true" ]; then
      _info "DigitalPlat: record $DP_RECORD_ID holds TXT values that this run did not create; not deleting it so those values survive"
      continue
    fi

    if ! DP_RESPONSE="$(_dp_delete_api "/domains/$DP_ZONE/dns/records/$DP_RECORD_ID")"; then
      _dp_report_api_error "delete TXT record (transport error)" "$DP_RESPONSE"
      DP_RM_FAILED=1
      continue
    fi
    _debug2 "DigitalPlat delete response" "$DP_RESPONSE"
    if ! _dp_expect_success "delete TXT record $DP_RECORD_ID" "$DP_RESPONSE"; then
      DP_RM_FAILED=1
      continue
    fi
    if [ "$DP_RECORD_SHARED" = "true" ]; then
      # The whole RRset went away, so every value we tracked for this name is gone.
      _dp_state_drop "$DP_FQDN"
    else
      _dp_state_drop "$DP_FQDN" "$DP_TXT_VALUE"
    fi
    _info "DigitalPlat: deleted matching TXT record $DP_RECORD_ID"
  done <<EOF
$DP_MATCHES
EOF

  if [ "$DP_RM_FAILED" != "0" ]; then
    return 1
  fi
  return 0
}

######## Private helpers ########

# Per-certificate note of the challenge values this run published, so that a
# multi-value RRset can be deleted when (and only when) every value in it is
# ours. Best effort: if the file cannot be written the hook simply falls back
# to the conservative behaviour (never delete a shared RRset).
_dp_state_path() {
  DP_STATE_DIR="${DOMAIN_PATH:-${LE_WORKING_DIR:-${TMPDIR:-/tmp}}}"
  [ -d "$DP_STATE_DIR" ] || DP_STATE_DIR="${TMPDIR:-/tmp}"
  printf '%s' "$DP_STATE_DIR/digitalplat_dns.state"
}

_dp_state_add() {
  # _dp_state_add <fqdn> <value>
  DP_SF_FILE="$DP_STATE_FILE"
  DP_SF_TMP="$DP_SF_FILE.$$"

  if [ -s "$DP_SF_FILE" ] && jq -e 'type == "array"' "$DP_SF_FILE" >/dev/null 2>&1; then
    if jq -c --arg n "$1" --arg v "$2" '
      if ([.[] | select(.n == $n and .v == $v)] | length) == 0 then . + [{n:$n, v:$v}] else . end
    ' "$DP_SF_FILE" >"$DP_SF_TMP" 2>/dev/null; then
      _debug2 "DigitalPlat state" "value recorded in $DP_SF_FILE"
      mv "$DP_SF_TMP" "$DP_SF_FILE" 2>/dev/null && return 0
    fi
  fi

  if jq -cn --arg n "$1" --arg v "$2" '[{n:$n, v:$v}]' >"$DP_SF_TMP" 2>/dev/null; then
    mv "$DP_SF_TMP" "$DP_SF_FILE" 2>/dev/null
  fi
  rm -f "$DP_SF_TMP" 2>/dev/null
  return 0
}

_dp_state_drop() {
  # _dp_state_drop <fqdn> [<value>] - forget one value, or every value of a name.
  DP_SF_FILE="$DP_STATE_FILE"
  [ -s "$DP_SF_FILE" ] || return 0
  jq -e 'type == "array"' "$DP_SF_FILE" >/dev/null 2>&1 || return 0
  DP_SF_TMP="$DP_SF_FILE.$$"

  if [ "$#" -ge 2 ]; then
    jq -c --arg n "$1" --arg v "$2" '[.[] | select((.n == $n and .v == $v) | not)]' \
      "$DP_SF_FILE" >"$DP_SF_TMP" 2>/dev/null || {
      rm -f "$DP_SF_TMP" 2>/dev/null
      return 0
    }
  else
    jq -c --arg n "$1" '[.[] | select(.n != $n)]' "$DP_SF_FILE" >"$DP_SF_TMP" 2>/dev/null || {
      rm -f "$DP_SF_TMP" 2>/dev/null
      return 0
    }
  fi
  mv "$DP_SF_TMP" "$DP_SF_FILE" 2>/dev/null
  if [ "$(cat "$DP_SF_FILE" 2>/dev/null)" = "[]" ]; then
    rm -f "$DP_SF_FILE" 2>/dev/null
  fi
  return 0
}

_dp_init() {
  if ! command -v jq >/dev/null 2>&1; then
    _err "DigitalPlat: jq is required by dns_digitalplat.sh; install jq and retry"
    return 1
  fi

  DIGITALPLAT_API_KEY="${DIGITALPLAT_API_KEY:-$(_readaccountconf_mutable DIGITALPLAT_API_KEY)}"
  if [ -z "$DIGITALPLAT_API_KEY" ]; then
    _err "DigitalPlat: set DIGITALPLAT_API_KEY first (for example dp_live_xxx)"
    return 1
  fi
  _saveaccountconf_mutable DIGITALPLAT_API_KEY "$DIGITALPLAT_API_KEY"

  DP_TTL="${DIGITALPLAT_TTL:-$DP_DEFAULT_TTL}"
  case "$DP_TTL" in
  '' | *[!0-9]*)
    _err "DigitalPlat: DIGITALPLAT_TTL must be a whole number of seconds (got: $DP_TTL)"
    return 1
    ;;
  esac
  # jq --argjson needs valid JSON: drop leading zeros ("0300" -> "300").
  DP_TTL="$(printf '%s' "$DP_TTL" | sed 's/^0*//')"
  [ -z "$DP_TTL" ] && DP_TTL=0

  DP_ZONE_USABLE=""
  DP_STATE_FILE="$(_dp_state_path)"
  return 0
}

_dp_set_headers() {
  export _H1="Authorization: Bearer $DIGITALPLAT_API_KEY"
  export _H2="Accept: application/json"
  export _H3="Content-Type: application/json"
  # Clear headers left behind by earlier acme.sh requests in this process.
  export _H4=""
  export _H5=""
}

_dp_get_api() {
  _dp_set_headers
  _get "$DP_API$1"
}

_dp_post_api() {
  _dp_set_headers
  _post "$2" "$DP_API$1" "" "POST" "application/json"
}

_dp_delete_api() {
  # No request body: do not advertise a JSON content type for DELETE.
  _dp_set_headers
  _H3=""
  _post "" "$DP_API$1" "" "DELETE" ""
}

_dp_report_api_error() {
  DP_ERROR_CONTEXT=$1
  DP_ERROR_BODY=$2
  DP_ERROR_MESSAGE="$(printf '%s' "$DP_ERROR_BODY" | jq -r '
    if type == "object" then ((.error.message? // .message?) // empty) | tostring else empty end
  ' 2>/dev/null)"
  DP_ERROR_CODE="$(printf '%s' "$DP_ERROR_BODY" | jq -r '
    if type == "object" then ((.error.code? // .code?) // empty) | tostring else empty end
  ' 2>/dev/null)"

  if [ -n "$DP_ERROR_MESSAGE" ]; then
    if [ -n "$DP_ERROR_CODE" ]; then
      _err "DigitalPlat API ${DP_ERROR_CONTEXT}: ${DP_ERROR_MESSAGE} (${DP_ERROR_CODE})"
    else
      _err "DigitalPlat API ${DP_ERROR_CONTEXT}: ${DP_ERROR_MESSAGE}"
    fi
  else
    DP_ERROR_PREVIEW="$(printf '%s' "$DP_ERROR_BODY" | tr '\n' ' ' | cut -c 1-400)"
    if [ -n "$DP_ERROR_PREVIEW" ]; then
      _err "DigitalPlat API ${DP_ERROR_CONTEXT}: ${DP_ERROR_PREVIEW}"
    else
      _err "DigitalPlat API ${DP_ERROR_CONTEXT}: empty response"
    fi
  fi
  _debug2 "DigitalPlat API error response" "$DP_ERROR_BODY"
  return 1
}

_dp_expect_success() {
  if printf '%s' "$2" | jq -e 'type == "object" and .success == true' >/dev/null 2>&1; then
    return 0
  fi
  _dp_report_api_error "$1 (expected JSON with success=true)" "$2"
  return 1
}

_dp_expect_data_array() {
  if printf '%s' "$2" | jq -e '(.data | type) == "array"' >/dev/null 2>&1; then
    return 0
  fi
  _dp_report_api_error "$1 (expected data array)" "$2"
  return 1
}

_dp_expect_data_object() {
  if printf '%s' "$2" | jq -e '(.data | type) == "object"' >/dev/null 2>&1; then
    return 0
  fi
  _dp_report_api_error "$1 (expected data object)" "$2"
  return 1
}

_dp_resolve_zone() {
  # Normalises the challenge name and works out which owned zone holds it.
  # Sets DP_FQDN (lower-case, no trailing dot), DP_ZONE and DP_SUB.
  DP_FQDN="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  DP_FQDN="${DP_FQDN%.}"
  if [ -z "$DP_FQDN" ]; then
    _err "DigitalPlat: empty challenge domain"
    return 1
  fi
  case "$DP_FQDN" in
  *[!a-z0-9._-]*)
    _err "DigitalPlat: unsupported challenge domain '$1'"
    return 1
    ;;
  esac

  if [ -n "${DIGITALPLAT_DOMAIN:-}" ]; then
    # Operator pinned the zone: skip the GET /domains round-trip.
    DP_ZONE="$(printf '%s' "$DIGITALPLAT_DOMAIN" | tr '[:upper:]' '[:lower:]')"
    DP_ZONE="${DP_ZONE%.}"
    case "$DP_ZONE" in
    '' | *[!a-z0-9.-]*)
      _err "DigitalPlat: DIGITALPLAT_DOMAIN contains unexpected characters: $DIGITALPLAT_DOMAIN"
      return 1
      ;;
    esac
    case "$DP_FQDN" in
    "$DP_ZONE" | *".$DP_ZONE") ;;
    *)
      _err "DigitalPlat: $DP_FQDN is not inside DIGITALPLAT_DOMAIN=$DP_ZONE"
      return 1
      ;;
    esac
  else
    if ! DP_DOMAINS_JSON="$(_dp_get_api "/domains")"; then
      _dp_report_api_error "list domains (transport error)" "$DP_DOMAINS_JSON"
      return 1
    fi
    _debug2 "DigitalPlat domains response" "$DP_DOMAINS_JSON"
    _dp_expect_success "list domains" "$DP_DOMAINS_JSON" || return 1
    _dp_expect_data_array "list domains" "$DP_DOMAINS_JSON" || return 1

    # The DigitalPlat API schema returns the zone in .domain (the register response uses
    # .name), so accept either. Take the most specific label-boundary suffix.
    if ! DP_ZONE="$(printf '%s' "$DP_DOMAINS_JSON" | jq -r --arg fqdn "$DP_FQDN" '
      ($fqdn | ascii_downcase) as $f
      | [ .data[]?
          | select(type == "object")
          | ((.domain? // .name? // .fqdn? // empty) | tostring | ascii_downcase | sub("\\.$"; "")) as $candidate
          | select($candidate != "")
          | select($f == $candidate or ($f | endswith("." + $candidate)))
          | {zone: $candidate, len: ($candidate | length)} ]
      | if length == 0 then empty else (max_by(.len) | .zone) end
    ' 2>/dev/null)"; then
      _dp_report_api_error "parse domain list" "$DP_DOMAINS_JSON"
      return 1
    fi

    if [ -z "$DP_ZONE" ]; then
      _err "DigitalPlat: no owned domain is a suffix of $DP_FQDN"
      _info "DigitalPlat: check the API key, or set DIGITALPLAT_DOMAIN to the zone name"
      return 1
    fi
  fi

  if [ "$DP_FQDN" = "$DP_ZONE" ]; then
    DP_SUB="@"
  else
    DP_SUB="${DP_FQDN%".$DP_ZONE"}"
  fi

  _debug "DigitalPlat zone" "$DP_ZONE"
  _debug "DigitalPlat record name" "$DP_SUB"
  return 0
}

_dp_check_zone() {
  # Sets DP_ZONE_USABLE=yes|no. Returns 1 only when the API call or payload is
  # unusable; a zone that is not hosted is reported through DP_ZONE_USABLE.
  if ! DP_ZONE_JSON="$(_dp_get_api "/domains/$DP_ZONE/dns")"; then
    _dp_report_api_error "get DNS hosting status (transport error)" "$DP_ZONE_JSON"
    return 1
  fi
  _debug2 "DigitalPlat DNS status response" "$DP_ZONE_JSON"
  _dp_expect_success "get DNS hosting status" "$DP_ZONE_JSON" || return 1
  _dp_expect_data_object "get DNS hosting status" "$DP_ZONE_JSON" || return 1

  DP_DNS_MODE="$(printf '%s' "$DP_ZONE_JSON" | jq -r '.data.mode // empty' 2>/dev/null)"
  DP_DNS_STATUS="$(printf '%s' "$DP_ZONE_JSON" | jq -r '.data.status // empty' 2>/dev/null)"

  DP_ZONE_USABLE="yes"
  if [ -z "$DP_DNS_MODE" ]; then
    _debug "DigitalPlat: zone mode missing from the response; assuming hosted"
  elif [ "$DP_DNS_MODE" != "hosted" ]; then
    _err "DigitalPlat: $DP_ZONE is not in hosted DNS mode (mode: $DP_DNS_MODE)"
    DP_ZONE_USABLE="no"
  fi

  if [ -n "$DP_DNS_STATUS" ] && [ "$DP_DNS_STATUS" != "active" ]; then
    # Not fatal: the zone is hosted but may still be provisioning.
    _info "DigitalPlat: warning: hosted zone $DP_ZONE reports status '$DP_DNS_STATUS'; records may not resolve until it is active"
  fi
  return 0
}

_dp_list_records() {
  if ! DP_LIST_RESPONSE="$(_dp_get_api "/domains/$DP_ZONE/dns/records")"; then
    _dp_report_api_error "list DNS records (transport error)" "$DP_LIST_RESPONSE"
    return 1
  fi
  _debug2 "DigitalPlat DNS records response" "$DP_LIST_RESPONSE"
  _dp_expect_success "list DNS records" "$DP_LIST_RESPONSE" || return 1
  _dp_expect_data_array "list DNS records" "$DP_LIST_RESPONSE" || return 1
  printf '%s' "$DP_LIST_RESPONSE"
}

# Prints one line per matching TXT record:
#   <id>|<protected>|<disabled>|<shared rrset>|<every value is ours>
# stdin: the JSON returned by GET /domains/{domain}/dns/records
_dp_match_records() {
  DP_SF_ARG="$4"
  [ -r "$DP_SF_ARG" ] || DP_SF_ARG=/dev/null
  jq -r --arg zone "$1" --arg fqdn "$2" --arg target "$3" --rawfile owned "$DP_SF_ARG" '
    def normv:
      tostring
      | sub("^\\s+"; "") | sub("\\s+$"; "")
      | sub("^\""; "") | sub("\"$"; "");

    def absname($z):
      (tostring | ascii_downcase | sub("\\.$"; "")) as $n
      | if ($n == "" or $n == "@") then $z
        elif ($n == $z or ($n | endswith("." + $z))) then $n
        else ($n + "." + $z)
        end;

    def recvals:
      if ((.values? // null) | type) == "array" and ((.values | length) > 0) then .values
      else [.value?]
      end
      | map(select(. != null) | normv);

    ($zone | ascii_downcase) as $z
    | ($fqdn | ascii_downcase) as $f
    | ($target | normv) as $tv
    | [ ($owned | fromjson? // [])[]?
        | select((.n // "") == $f)
        | .v | normv ] as $mine
    | .data[]?
    | select(type == "object")
    | select((((.type // "") | tostring | ascii_upcase)) == "TXT")
    | select(((.name // "") | absname($z)) == $f)
    | recvals as $vals
    | select(($vals | index($tv)) != null)
    | "\(.id // "" | tostring)|\(.protected == true)|\(.disabled == true)|\(($vals | length) > 1)|\([ $vals[] as $v | select(($mine | index($v)) == null) | $v ] | length == 0)"
  '
}
