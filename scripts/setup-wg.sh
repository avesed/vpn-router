#!/usr/bin/env bash
set -euo pipefail

WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/sing-box/wireguard/server.json}"
WG_BIN="$(command -v wg)"
IP_BIN="$(command -v ip)"

if [ ! -f "${WG_CONFIG_PATH}" ]; then
  echo "[wireguard] config ${WG_CONFIG_PATH} not found, skip" >&2
  exit 0
fi

if [ -z "${WG_BIN}" ] || [ -z "${IP_BIN}" ]; then
  echo "[wireguard] wg/ip command not available" >&2
  exit 1
fi

jq_bin="$(command -v jq)"
if [ -z "${jq_bin}" ]; then
  echo "[wireguard] jq not available" >&2
  exit 1
fi

iface=$(jq -r '.interface.name // "wg-ingress"' "${WG_CONFIG_PATH}")
listen_port=$(jq -r '.interface.listen_port // 51820' "${WG_CONFIG_PATH}")
address_json=$(jq -c '.interface.address // empty' "${WG_CONFIG_PATH}")
mtu=$(jq -r '.interface.mtu // empty' "${WG_CONFIG_PATH}")
priv_key=$(jq -r '.interface.private_key // empty' "${WG_CONFIG_PATH}")

if [ -z "${priv_key}" ]; then
  echo "[wireguard] missing interface.private_key" >&2
  exit 1
fi
if [[ "${priv_key}" == REPLACE* ]]; then
  echo "[wireguard] private key placeholder detected, skip WireGuard setup" >&2
  exit 0
fi

# recreate interface for idempotency
if ${IP_BIN} link show "${iface}" >/dev/null 2>&1; then
  ${IP_BIN} link del "${iface}"
fi

${IP_BIN} link add dev "${iface}" type wireguard
if [ -n "${address_json}" ] && [ "${address_json}" != "null" ]; then
  if [[ "${address_json}" == \[?* ]]; then
    echo "${address_json}" | jq -r '.[]' | while read -r addr; do
      [ -n "${addr}" ] && ${IP_BIN} address add "${addr}" dev "${iface}"
    done
  else
    addr=$(jq -r '.interface.address' "${WG_CONFIG_PATH}")
    [ -n "${addr}" ] && ${IP_BIN} address add "${addr}" dev "${iface}"
  fi
fi
if [ -n "${mtu}" ] && [ "${mtu}" != "null" ]; then
  ${IP_BIN} link set dev "${iface}" mtu "${mtu}"
fi

key_file=$(mktemp)
printf '%s' "${priv_key}" >"${key_file}"
chmod 600 "${key_file}"
${WG_BIN} set "${iface}" listen-port "${listen_port}" private-key "${key_file}"
rm -f "${key_file}"

jq -c '.peers[]?' "${WG_CONFIG_PATH}" | while read -r peer; do
  name=$(jq -r '.name // empty' <<<"${peer}")
  pub=$(jq -r '.public_key // empty' <<<"${peer}")
  allowed=$(jq -r '.allowed_ips // [] | join(",")' <<<"${peer}")
  keepalive=$(jq -r '.persistent_keepalive // empty' <<<"${peer}")
  if [ -z "${pub}" ] || [ -z "${allowed}" ]; then
    echo "[wireguard] skip peer ${name:-<unnamed>} (missing public_key or allowed_ips)" >&2
    continue
  fi
  args=(set "${iface}" peer "${pub}" allowed-ips "${allowed}")
  if [ -n "${keepalive}" ] && [ "${keepalive}" != "null" ]; then
    args+=(persistent-keepalive "${keepalive}")
  fi
  ${WG_BIN} "${args[@]}"
done

${IP_BIN} link set up dev "${iface}"
echo "[wireguard] interface ${iface} ready"
