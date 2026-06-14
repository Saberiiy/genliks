#!/usr/bin/env bash
# =============================================================================
# gen-links.sh — 从 sing-box config.json 自动生成客户端节点链接 / 聚合订阅
# -----------------------------------------------------------------------------
# 功能：
#   1. 遍历 config.json 里所有 inbounds，自动识别协议类型，生成单条分享链接
#   2. 生成 Shadowrocket 聚合订阅（多条链接 Base64 打包，导入一次得到全部节点）
#   3. 生成 Clash Verge 聚合配置（YAML：proxies + proxy-groups）
#
# 当前支持的协议：vless、hysteria2、vmess、trojan、shadowsocks(ss)
#   —— 不认识的协议会跳过并提示，不会瞎拼错链接
#
# 用法：
#   bash gen-links.sh <服务器域名> [config路径]
#   例：bash gen-links.sh node.example.com
#   GitHub 远程执行：
#     bash <(curl -fsSL https://raw.githubusercontent.com/<你>/<仓库>/main/gen-links.sh) node.example.com
#
# 安全提醒：
#   - 本脚本不含任何密钥，可公开。但它的【输出】含明文密码/UUID，切勿公开！
#   - 切勿把 config.json 传到 GitHub（里面有密钥）。
#   - 远程执行只用你自己信任的仓库地址。
#
# 依赖：jq（解析 JSON）、base64（系统自带）。缺 jq 时自动安装。
# =============================================================================

set -euo pipefail

CONFIG="${2:-${CONFIG:-/etc/sing-box/config.json}}"   # 第2参数或环境变量 CONFIG 指定路径，默认 /etc/sing-box/config.json
DOMAIN="${1:-}"
TAGNAME="${TAGNAME:-$DOMAIN}"                          # 节点名前缀，默认用域名

# ---- 参数与依赖检查 ----
if [[ -z "$DOMAIN" ]]; then
  echo "用法: bash $0 <服务器域名> [config路径]"
  echo "例:   bash $0 node.example.com"
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "找不到配置文件: $CONFIG"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "[*] 未检测到 jq，尝试安装..." >&2
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq jq
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q jq
  elif command -v yum >/dev/null 2>&1; then yum install -y -q jq
  else echo "请手动安装 jq 后重试"; exit 1; fi
fi

# ---- 工具函数 ----
# URL 编码（密码里的 = 等特殊字符转义，例如 == -> %3D%3D）
urlencode() {
  local s="$1" out="" c i
  for (( i=0; i<${#s}; i++ )); do
    c="${s:$i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v hex '%%%02X' "'$c"; out+="$hex" ;;
    esac
  done
  printf '%s' "$out"
}
# 跨平台 base64（GNU 用 -w0 取消折行；BSD/mac 默认不折行）
b64() {
  if base64 --help 2>&1 | grep -q -- '-w'; then base64 -w0; else base64 | tr -d '\n'; fi
}

# ---- 收集所有单条链接（存进数组，供后面聚合用）----
declare -a LINKS=()          # 存所有 协议:// 链接
declare -a CLASH_PROXIES=()  # 存所有 Clash YAML 片段
declare -a NAMES=()          # 存所有节点名（给 Clash proxy-groups 用）
SKIPPED=""                   # 记录跳过的协议

# 逐个读取 inbound（用 jq 把每个 inbound 压成单行 JSON，循环处理）
while IFS= read -r ib; do
  type=$(echo "$ib" | jq -r '.type')
  port=$(echo "$ib" | jq -r '.listen_port // empty')
  sni=$(echo "$ib"  | jq -r '.tls.server_name // empty')
  [[ -z "$sni" ]] && sni="$DOMAIN"
  name="${TAGNAME}-${type}"

  case "$type" in
    vless)
      uuid=$(echo "$ib" | jq -r '.users[0].uuid')
      flow=$(echo "$ib" | jq -r '.users[0].flow // ""')
      link="vless://${uuid}@${DOMAIN}:${port}?encryption=none&security=tls&sni=${sni}&fp=chrome&type=tcp"
      [[ -n "$flow" && "$flow" != "null" ]] && link+="&flow=${flow}"
      link+="#${name}"
      LINKS+=("$link"); NAMES+=("$name")
      CLASH_PROXIES+=("$(cat <<YAML
  - name: ${name}
    type: vless
    server: ${DOMAIN}
    port: ${port}
    uuid: ${uuid}
    network: tcp
    tls: true
    flow: ${flow}
    servername: ${sni}
    client-fingerprint: chrome
YAML
)")
      ;;

    hysteria2)
      pass=$(echo "$ib" | jq -r '.users[0].password')
      passenc=$(urlencode "$pass")
      link="hysteria2://${passenc}@${DOMAIN}:${port}/?sni=${sni}#${name}"
      LINKS+=("$link"); NAMES+=("$name")
      CLASH_PROXIES+=("$(cat <<YAML
  - name: ${name}
    type: hysteria2
    server: ${DOMAIN}
    port: ${port}
    password: ${pass}
    sni: ${sni}
YAML
)")
      ;;

    vmess)
      # vmess 链接是一段 JSON 再 base64，字段名固定
      uuid=$(echo "$ib" | jq -r '.users[0].uuid')
      vmess_json=$(jq -nc --arg add "$DOMAIN" --arg port "$port" --arg id "$uuid" --arg sni "$sni" --arg ps "$name" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"tcp",type:"none",host:"",path:"",tls:"tls",sni:$sni}')
      link="vmess://$(printf '%s' "$vmess_json" | b64)"
      LINKS+=("$link"); NAMES+=("$name")
      CLASH_PROXIES+=("$(cat <<YAML
  - name: ${name}
    type: vmess
    server: ${DOMAIN}
    port: ${port}
    uuid: ${uuid}
    alterId: 0
    cipher: auto
    network: tcp
    tls: true
    servername: ${sni}
YAML
)")
      ;;

    trojan)
      pass=$(echo "$ib" | jq -r '.users[0].password')
      passenc=$(urlencode "$pass")
      link="trojan://${passenc}@${DOMAIN}:${port}?security=tls&sni=${sni}&type=tcp#${name}"
      LINKS+=("$link"); NAMES+=("$name")
      CLASH_PROXIES+=("$(cat <<YAML
  - name: ${name}
    type: trojan
    server: ${DOMAIN}
    port: ${port}
    password: ${pass}
    sni: ${sni}
YAML
)")
      ;;

    shadowsocks)
      method=$(echo "$ib" | jq -r '.method')
      pass=$(echo "$ib"   | jq -r '.password')
      # ss 链接：base64(method:password)@host:port#name
      userinfo=$(printf '%s:%s' "$method" "$pass" | b64)
      link="ss://${userinfo}@${DOMAIN}:${port}#${name}"
      LINKS+=("$link"); NAMES+=("$name")
      CLASH_PROXIES+=("$(cat <<YAML
  - name: ${name}
    type: ss
    server: ${DOMAIN}
    port: ${port}
    cipher: ${method}
    password: ${pass}
YAML
)")
      ;;

    *)
      SKIPPED+=" ${type}"
      ;;
  esac
done < <(jq -c '.inbounds[]' "$CONFIG")

# ---- 没有任何可用节点就退出 ----
if [[ ${#LINKS[@]} -eq 0 ]]; then
  echo "config.json 里没有可识别的代理协议 inbound。"
  [[ -n "$SKIPPED" ]] && echo "（跳过的类型:$SKIPPED）"
  exit 0
fi

echo "============================================================"
echo " 域名: $DOMAIN    配置: $CONFIG    共 ${#LINKS[@]} 个节点"
[[ -n "$SKIPPED" ]] && echo " ⚠ 跳过不支持的协议:$SKIPPED"
echo "============================================================"

# ---- 产物 1：单条链接清单 ----
echo
echo "【1】单条节点链接（可逐条复制导入）"
echo "------------------------------------------------------------"
printf '%s\n' "${LINKS[@]}"

# ---- 产物 2：Shadowrocket 聚合订阅（多条链接 Base64 打包）----
echo
echo "【2】Shadowrocket 聚合订阅（整段 Base64，导入一次得到全部节点）"
echo "------------------------------------------------------------"
# 把所有链接每行一条拼起来，整体 base64
printf '%s\n' "${LINKS[@]}" | b64
echo
echo "（用法：复制上面这串 → Shadowrocket 也可直接当一条节点/订阅粘贴导入）"

# ---- 产物 3：Clash Verge 聚合配置（YAML）----
echo
echo "【3】Clash Verge 聚合配置（保存为 .yaml 导入 / 粘进配置）"
echo "------------------------------------------------------------"
echo "proxies:"
printf '%s\n' "${CLASH_PROXIES[@]}"
echo "proxy-groups:"
echo "  - name: PROXY"
echo "    type: select"
echo "    proxies:"
for n in "${NAMES[@]}"; do echo "      - ${n}"; done
echo "      - DIRECT"
echo "rules:"
echo "  - MATCH,PROXY"

echo
echo "[完成] 产物2给 Shadowrocket，产物3给 Clash。"
echo "⚠ 以上输出含明文密钥，切勿公开/截图外发。"
