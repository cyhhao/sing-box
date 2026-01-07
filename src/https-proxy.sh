#!/bin/bash

# HTTPS Proxy (HTTP inbound + TLS with ACME Cloudflare DNS-01) management
# Config file naming: HTTPS-PROXY-${port}.json

HTTPS_PROXY_ACME_DIR="/var/lib/sing-box/certmagic"
HTTPS_PROXY_PREFIX="HTTPS-PROXY"

# Generate random password (16 chars alphanumeric)
_gen_rand_pass() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

# Check if port is used by existing inbounds in conf dir
_is_port_in_conf() {
    local check_port=$1
    for f in "$is_conf_dir"/*.json; do
        [[ -f "$f" ]] || continue
        if jq -e ".inbounds[]?.listen_port == $check_port" "$f" &>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Validate port number
_validate_port() {
    local p=$1
    if [[ ! "$p" =~ ^[0-9]+$ ]] || [[ "$p" -lt 1 ]] || [[ "$p" -gt 65535 ]]; then
        return 1
    fi
    return 0
}

# Ensure ACME data directory exists with correct permissions
_ensure_acme_dir() {
    if [[ ! -d "$HTTPS_PROXY_ACME_DIR" ]]; then
        mkdir -p "$HTTPS_PROXY_ACME_DIR"
        chmod 700 "$HTTPS_PROXY_ACME_DIR"
        msg "已创建 ACME 数据目录: $HTTPS_PROXY_ACME_DIR"
    fi
}

# Run sing-box check to validate config
_check_config() {
    $is_core_bin check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null
    return $?
}

# Add HTTPS Proxy configuration
# Usage: https_proxy_add [port] [domain] [username] [password] [email]
https_proxy_add() {
    local use_port=$1
    local use_domain=$2
    local use_user=$3
    local use_pass=$4
    local use_email=$5

    msg "\n$(_green '=== 添加 HTTPS Proxy (标准 HTTPS 代理) ===')\n"

    # === Port ===
    if [[ -z "$use_port" ]]; then
        get_port
        use_port=$tmp_port
        msg "推荐端口: $use_port"
        ask string use_port "请输入端口 (默认 $use_port):"
        [[ -z "$use_port" ]] && use_port=$tmp_port
    fi

    if ! _validate_port "$use_port"; then
        err "端口 ($use_port) 无效, 必须是 1-65535"
    fi

    if _is_port_in_conf "$use_port"; then
        err "端口 ($use_port) 已被其他 inbound 使用"
    fi

    if [[ $(is_test port_used "$use_port") ]]; then
        err "端口 ($use_port) 已被系统其他服务占用"
    fi

    # === Domain ===
    if [[ -z "$use_domain" ]]; then
        msg "\n$(_yellow '提示: 域名必须在 Cloudflare 解析, 且设置为 DNS only (灰云, 非代理模式)')"
        ask string use_domain "请输入域名 (例如 proxy.example.com):"
    fi

    if [[ -z "$use_domain" ]]; then
        err "域名不能为空"
    fi

    # === Username ===
    if [[ -z "$use_user" ]]; then
        local default_user="proxy$(shuf -i 1000-9999 -n1)"
        ask string use_user "请输入用户名 (默认 $default_user):"
        [[ -z "$use_user" ]] && use_user=$default_user
    fi

    # === Password ===
    if [[ -z "$use_pass" ]]; then
        local default_pass=$(_gen_rand_pass)
        ask string use_pass "请输入密码 (默认随机生成):"
        [[ -z "$use_pass" ]] && use_pass=$default_pass
    fi

    # === Email (optional) ===
    if [[ -z "$use_email" ]]; then
        msg "\n$(_yellow '提示: Email 用于 ACME/Let'\''s Encrypt 注册, 建议填写')"
        echo -ne "请输入 Email (可选, 直接回车跳过):"
        read use_email
    fi

    # === Cloudflare API Token ===
    msg "\n$(_green '=== Cloudflare DNS-01 配置 ===')"
    msg "$(_yellow '需要 Cloudflare API Token 用于自动申请 TLS 证书')"
    msg "$(_yellow '权限要求: Zone.DNS:Edit (必须), Zone:Read (可选)')"
    msg "$(_yellow '创建 Token: https://dash.cloudflare.com/profile/api-tokens')\n"

    local cf_api_token=""
    local cf_zone_token=""

    ask string cf_api_token "请输入 Cloudflare API Token (Zone.DNS:Edit):"
    if [[ -z "$cf_api_token" ]]; then
        err "Cloudflare API Token 不能为空"
    fi

    # Zone Token is optional, use read directly to allow empty input
    echo -ne "请输入 Zone Token (可选, 直接回车跳过):"
    read cf_zone_token

    # Ensure ACME directory
    _ensure_acme_dir

    # Build config JSON
    local config_file="$is_conf_dir/${HTTPS_PROXY_PREFIX}-${use_port}.json"
    local tag="${HTTPS_PROXY_PREFIX}-${use_port}"

    # Build dns01_challenge object
    local dns01_json
    if [[ -n "$cf_zone_token" ]]; then
        dns01_json=$(jq -n \
            --arg provider "cloudflare" \
            --arg api_token "$cf_api_token" \
            --arg zone_token "$cf_zone_token" \
            '{provider: $provider, api_token: $api_token, zone_token: $zone_token}')
    else
        dns01_json=$(jq -n \
            --arg provider "cloudflare" \
            --arg api_token "$cf_api_token" \
            '{provider: $provider, api_token: $api_token}')
    fi

    # Build acme object
    local acme_json
    if [[ -n "$use_email" ]]; then
        acme_json=$(jq -n \
            --arg domain "$use_domain" \
            --arg email "$use_email" \
            --arg data_dir "$HTTPS_PROXY_ACME_DIR" \
            --argjson dns01 "$dns01_json" \
            '{domain: [$domain], email: $email, provider: "letsencrypt", data_directory: $data_dir, dns01_challenge: $dns01}')
    else
        acme_json=$(jq -n \
            --arg domain "$use_domain" \
            --arg data_dir "$HTTPS_PROXY_ACME_DIR" \
            --argjson dns01 "$dns01_json" \
            '{domain: [$domain], provider: "letsencrypt", data_directory: $data_dir, dns01_challenge: $dns01}')
    fi

    # Build full config
    local full_json
    full_json=$(jq -n \
        --arg tag "$tag" \
        --argjson port "$use_port" \
        --arg username "$use_user" \
        --arg password "$use_pass" \
        --argjson acme "$acme_json" \
        '{
            inbounds: [{
                type: "http",
                tag: $tag,
                listen: "0.0.0.0",
                listen_port: $port,
                users: [{username: $username, password: $password}],
                tls: {
                    enabled: true,
                    min_version: "1.2",
                    max_version: "1.3",
                    acme: $acme
                }
            }]
        }')

    # Backup existing config if any
    local backup_file=""
    if [[ -f "$config_file" ]]; then
        backup_file="${config_file}.bak.$$"
        cp "$config_file" "$backup_file"
    fi

    # Write config file with secure permissions
    echo "$full_json" > "$config_file"
    chmod 600 "$config_file"

    # Validate merged config
    msg "\n验证配置..."
    if ! _check_config; then
        # Rollback on failure
        if [[ -n "$backup_file" ]]; then
            mv "$backup_file" "$config_file"
        else
            rm -f "$config_file"
        fi
        err "配置验证失败, 请检查参数是否正确"
    fi

    # Remove backup if exists
    [[ -n "$backup_file" ]] && rm -f "$backup_file"

    msg "$(_green '配置验证通过!')\n"

    # Restart sing-box
    manage restart &

    # Show result
    msg "\n$(_green '=== HTTPS Proxy 添加成功 ===')"
    msg "配置文件: $config_file"
    msg "Tag: $tag"
    msg "端口: $use_port"
    msg "域名: $use_domain"
    msg "用户名: $use_user"
    msg "密码: $use_pass"
    msg "\n$(_cyan '=== 客户端使用方法 ===')"
    msg "代理地址: https://${use_user}:${use_pass}@${use_domain}:${use_port}"
    msg "\n$(_cyan '=== curl 测试命令 ===')"
    msg "curl -v --proxy \"https://${use_user}:${use_pass}@${use_domain}:${use_port}\" https://api.ipify.org"
    msg "\n$(_yellow '注意: 首次启动需要等待 ACME 申请证书, 可能需要 1-2 分钟')\n"
}

# Delete HTTPS Proxy configuration
# Usage: https_proxy_del <port|tag>
https_proxy_del() {
    local target=$1

    if [[ -z "$target" ]]; then
        # List available configs and ask user to select
        local configs=()
        for f in "$is_conf_dir"/${HTTPS_PROXY_PREFIX}-*.json; do
            [[ -f "$f" ]] && configs+=("$(basename "$f")")
        done

        if [[ ${#configs[@]} -eq 0 ]]; then
            err "没有找到 HTTPS Proxy 配置"
        fi

        msg "\n可用的 HTTPS Proxy 配置:"
        local i=1
        for c in "${configs[@]}"; do
            msg "  $i) $c"
            ((i++))
        done
        msg ""

        ask string target "请输入要删除的配置 (端口号或文件名):"
    fi

    # Find config file
    local config_file=""

    # Try exact match first
    if [[ -f "$is_conf_dir/${HTTPS_PROXY_PREFIX}-${target}.json" ]]; then
        config_file="$is_conf_dir/${HTTPS_PROXY_PREFIX}-${target}.json"
    elif [[ -f "$is_conf_dir/${target}" ]]; then
        config_file="$is_conf_dir/${target}"
    elif [[ -f "$is_conf_dir/${target}.json" ]]; then
        config_file="$is_conf_dir/${target}.json"
    fi

    if [[ -z "$config_file" ]] || [[ ! -f "$config_file" ]]; then
        err "找不到配置: $target"
    fi

    # Confirm deletion
    msg "\n即将删除: $(basename "$config_file")"
    ask string confirm_del "确认删除? [y/N]:"
    if [[ "${confirm_del,,}" != "y" ]]; then
        msg "已取消删除"
        return
    fi

    rm -f "$config_file"
    _green "\n已删除: $(basename "$config_file")"

    # Restart sing-box
    manage restart &
    msg ""
}

# Show HTTPS Proxy configuration info
# Usage: https_proxy_info <port|tag>
https_proxy_info() {
    local target=$1

    if [[ -z "$target" ]]; then
        # List available configs and ask user to select
        local configs=()
        for f in "$is_conf_dir"/${HTTPS_PROXY_PREFIX}-*.json; do
            [[ -f "$f" ]] && configs+=("$(basename "$f")")
        done

        if [[ ${#configs[@]} -eq 0 ]]; then
            err "没有找到 HTTPS Proxy 配置"
        fi

        if [[ ${#configs[@]} -eq 1 ]]; then
            target="${configs[0]}"
        else
            msg "\n可用的 HTTPS Proxy 配置:"
            local i=1
            for c in "${configs[@]}"; do
                msg "  $i) $c"
                ((i++))
            done
            msg ""

            ask string target "请选择要查看的配置 (端口号或文件名):"
        fi
    fi

    # Find config file
    local config_file=""

    if [[ -f "$is_conf_dir/${HTTPS_PROXY_PREFIX}-${target}.json" ]]; then
        config_file="$is_conf_dir/${HTTPS_PROXY_PREFIX}-${target}.json"
    elif [[ -f "$is_conf_dir/${target}" ]]; then
        config_file="$is_conf_dir/${target}"
    elif [[ -f "$is_conf_dir/${target}.json" ]]; then
        config_file="$is_conf_dir/${target}.json"
    fi

    if [[ -z "$config_file" ]] || [[ ! -f "$config_file" ]]; then
        err "找不到配置: $target"
    fi

    # Parse config
    local json_data
    json_data=$(cat "$config_file")

    local tag port username password domain
    tag=$(jq -r '.inbounds[0].tag' <<< "$json_data")
    port=$(jq -r '.inbounds[0].listen_port' <<< "$json_data")
    username=$(jq -r '.inbounds[0].users[0].username' <<< "$json_data")
    password=$(jq -r '.inbounds[0].users[0].password' <<< "$json_data")
    domain=$(jq -r '.inbounds[0].tls.acme.domain[0]' <<< "$json_data")

    msg "\n$(_green "=== HTTPS Proxy 配置信息 ===")"
    msg "配置文件: $(basename "$config_file")"
    msg "Tag: $tag"
    msg "端口: $port"
    msg "域名: $domain"
    msg "用户名: $username"
    msg "密码: $password"
    msg "\n$(_cyan '=== 客户端使用方法 ===')"
    msg "代理地址: https://${username}:${password}@${domain}:${port}"
    msg "\n$(_cyan '=== curl 测试命令 ===')"
    msg "curl -v --proxy \"https://${username}:${password}@${domain}:${port}\" https://api.ipify.org"
    msg ""
}

# List all HTTPS Proxy configurations
https_proxy_list() {
    local found=0

    msg "\n$(_green '=== HTTPS Proxy 配置列表 ===')\n"
    msg "$(printf '%-30s %-8s %-30s' 'Tag' 'Port' 'Domain')"
    msg "$(printf '%s' '----------------------------------------------------------------------')"

    for f in "$is_conf_dir"/${HTTPS_PROXY_PREFIX}-*.json; do
        [[ -f "$f" ]] || continue
        found=1

        local json_data tag port domain
        json_data=$(cat "$f")
        tag=$(jq -r '.inbounds[0].tag // "N/A"' <<< "$json_data")
        port=$(jq -r '.inbounds[0].listen_port // "N/A"' <<< "$json_data")
        domain=$(jq -r '.inbounds[0].tls.acme.domain[0] // "N/A"' <<< "$json_data")

        msg "$(printf '%-30s %-8s %-30s' "$tag" "$port" "$domain")"
    done

    if [[ $found -eq 0 ]]; then
        msg "没有找到 HTTPS Proxy 配置"
    fi
    msg ""
}

# Change HTTPS Proxy configuration
# Usage: https_proxy_change <port|tag|filename>
https_proxy_change() {
    local target=$1

    # Find config file (reuse logic from https_proxy_info)
    if [[ -z "$target" ]]; then
        local configs=()
        for f in "$is_conf_dir"/${HTTPS_PROXY_PREFIX}-*.json; do
            [[ -f "$f" ]] && configs+=("$(basename "$f")")
        done

        if [[ ${#configs[@]} -eq 0 ]]; then
            err "没有找到 HTTPS Proxy 配置"
        fi

        if [[ ${#configs[@]} -eq 1 ]]; then
            target="${configs[0]}"
        else
            msg "\n可用的 HTTPS Proxy 配置:"
            local i=1
            for c in "${configs[@]}"; do
                msg "  $i) $c"
                ((i++))
            done
            msg ""
            ask string target "请选择要更改的配置 (端口号或文件名):"
        fi
    fi

    # Find config file
    local config_file=""
    if [[ -f "$is_conf_dir/${HTTPS_PROXY_PREFIX}-${target}.json" ]]; then
        config_file="$is_conf_dir/${HTTPS_PROXY_PREFIX}-${target}.json"
    elif [[ -f "$is_conf_dir/${target}" ]]; then
        config_file="$is_conf_dir/${target}"
    elif [[ -f "$is_conf_dir/${target}.json" ]]; then
        config_file="$is_conf_dir/${target}.json"
    fi

    if [[ -z "$config_file" ]] || [[ ! -f "$config_file" ]]; then
        err "找不到配置: $target"
    fi

    # Parse current config
    local json_data
    json_data=$(cat "$config_file")

    local cur_port cur_domain cur_user cur_pass cur_email cur_api_token cur_zone_token
    cur_port=$(jq -r '.inbounds[0].listen_port' <<< "$json_data")
    cur_domain=$(jq -r '.inbounds[0].tls.acme.domain[0]' <<< "$json_data")
    cur_user=$(jq -r '.inbounds[0].users[0].username' <<< "$json_data")
    cur_pass=$(jq -r '.inbounds[0].users[0].password' <<< "$json_data")
    cur_email=$(jq -r '.inbounds[0].tls.acme.email // ""' <<< "$json_data")
    cur_api_token=$(jq -r '.inbounds[0].tls.acme.dns01_challenge.api_token' <<< "$json_data")
    cur_zone_token=$(jq -r '.inbounds[0].tls.acme.dns01_challenge.zone_token // ""' <<< "$json_data")

    # Show current config
    msg "\n$(_green '=== 当前 HTTPS Proxy 配置 ===')"
    msg "配置文件: $(basename "$config_file")"
    msg "端口: $cur_port"
    msg "域名: $cur_domain"
    msg "用户名: $cur_user"
    msg "密码: $cur_pass"
    [[ -n "$cur_email" && "$cur_email" != "null" ]] && msg "Email: $cur_email"

    # Show change options
    local change_options=(
        "更改端口"
        "更改域名"
        "更改用户名"
        "更改密码"
        "更改 Email"
        "更改 Cloudflare API Token"
    )

    msg "\n$(_cyan '请选择要更改的项目:')\n"
    local i=1
    for opt in "${change_options[@]}"; do
        msg "  $i) $opt"
        ((i++))
    done
    msg ""

    local choice
    ask string choice "请选择 [1-${#change_options[@]}]:"

    local new_port=$cur_port
    local new_domain=$cur_domain
    local new_user=$cur_user
    local new_pass=$cur_pass
    local new_email=$cur_email
    local new_api_token=$cur_api_token
    local new_zone_token=$cur_zone_token

    case $choice in
        1) # Change port
            ask string new_port "请输入新端口 (当前: $cur_port):"
            if ! _validate_port "$new_port"; then
                err "端口 ($new_port) 无效, 必须是 1-65535"
            fi
            if [[ "$new_port" != "$cur_port" ]]; then
                if _is_port_in_conf "$new_port"; then
                    err "端口 ($new_port) 已被其他 inbound 使用"
                fi
                if [[ $(is_test port_used "$new_port") ]]; then
                    err "端口 ($new_port) 已被系统其他服务占用"
                fi
            fi
            ;;
        2) # Change domain
            msg "$(_yellow '提示: 域名必须在 Cloudflare 解析, 且设置为 DNS only (灰云)')"
            ask string new_domain "请输入新域名 (当前: $cur_domain):"
            [[ -z "$new_domain" ]] && err "域名不能为空"
            ;;
        3) # Change username
            ask string new_user "请输入新用户名 (当前: $cur_user):"
            [[ -z "$new_user" ]] && err "用户名不能为空"
            ;;
        4) # Change password
            ask string new_pass "请输入新密码 (当前: $cur_pass):"
            [[ -z "$new_pass" ]] && err "密码不能为空"
            ;;
        5) # Change email
            echo -ne "请输入新 Email (当前: ${cur_email:-无}, 直接回车清空):"
            read new_email
            ;;
        6) # Change Cloudflare API Token
            ask string new_api_token "请输入新 Cloudflare API Token:"
            [[ -z "$new_api_token" ]] && err "API Token 不能为空"
            echo -ne "请输入新 Zone Token (可选, 直接回车跳过):"
            read new_zone_token
            ;;
        *)
            err "无效的选择"
            ;;
    esac

    # Build new config
    local new_tag="${HTTPS_PROXY_PREFIX}-${new_port}"
    local new_config_file="$is_conf_dir/${new_tag}.json"

    # Build dns01_challenge object
    local dns01_json
    if [[ -n "$new_zone_token" && "$new_zone_token" != "null" ]]; then
        dns01_json=$(jq -n \
            --arg provider "cloudflare" \
            --arg api_token "$new_api_token" \
            --arg zone_token "$new_zone_token" \
            '{provider: $provider, api_token: $api_token, zone_token: $zone_token}')
    else
        dns01_json=$(jq -n \
            --arg provider "cloudflare" \
            --arg api_token "$new_api_token" \
            '{provider: $provider, api_token: $api_token}')
    fi

    # Build acme object
    local acme_json
    if [[ -n "$new_email" && "$new_email" != "null" ]]; then
        acme_json=$(jq -n \
            --arg domain "$new_domain" \
            --arg email "$new_email" \
            --arg data_dir "$HTTPS_PROXY_ACME_DIR" \
            --argjson dns01 "$dns01_json" \
            '{domain: [$domain], email: $email, provider: "letsencrypt", data_directory: $data_dir, dns01_challenge: $dns01}')
    else
        acme_json=$(jq -n \
            --arg domain "$new_domain" \
            --arg data_dir "$HTTPS_PROXY_ACME_DIR" \
            --argjson dns01 "$dns01_json" \
            '{domain: [$domain], provider: "letsencrypt", data_directory: $data_dir, dns01_challenge: $dns01}')
    fi

    # Build full config
    local full_json
    full_json=$(jq -n \
        --arg tag "$new_tag" \
        --argjson port "$new_port" \
        --arg username "$new_user" \
        --arg password "$new_pass" \
        --argjson acme "$acme_json" \
        '{
            inbounds: [{
                type: "http",
                tag: $tag,
                listen: "0.0.0.0",
                listen_port: $port,
                users: [{username: $username, password: $password}],
                tls: {
                    enabled: true,
                    min_version: "1.2",
                    max_version: "1.3",
                    acme: $acme
                }
            }]
        }')

    # Backup old config
    local backup_file="${config_file}.bak.$$"
    cp "$config_file" "$backup_file"

    # If port changed, we need to create new file and delete old one
    if [[ "$new_port" != "$cur_port" ]]; then
        echo "$full_json" > "$new_config_file"
        chmod 600 "$new_config_file"
    else
        echo "$full_json" > "$config_file"
        chmod 600 "$config_file"
    fi

    # Validate config
    msg "\n验证配置..."
    if ! _check_config; then
        # Rollback
        if [[ "$new_port" != "$cur_port" ]]; then
            rm -f "$new_config_file"
        else
            mv "$backup_file" "$config_file"
        fi
        err "配置验证失败, 已回滚更改"
    fi

    # Remove backup and old config if port changed
    rm -f "$backup_file"
    if [[ "$new_port" != "$cur_port" ]]; then
        rm -f "$config_file"
    fi

    msg "$(_green '配置更新成功!')"

    # Restart sing-box
    manage restart &

    # Show new config
    msg "\n$(_green '=== 更新后的配置 ===')"
    msg "端口: $new_port"
    msg "域名: $new_domain"
    msg "用户名: $new_user"
    msg "密码: $new_pass"
    msg "\n$(_cyan '=== 客户端使用方法 ===')"
    msg "代理地址: https://${new_user}:${new_pass}@${new_domain}:${new_port}"
    msg "\n$(_cyan '=== curl 测试命令 ===')"
    msg "curl -v --proxy 'https://${new_user}:${new_pass}@${new_domain}:${new_port}' https://api.ipify.org"
    msg ""
}

# Main entry point
https_proxy_main() {
    local action=$1
    shift

    case $action in
        add)
            https_proxy_add "$@"
            ;;
        change | c)
            https_proxy_change "$@"
            ;;
        del | rm | delete)
            https_proxy_del "$@"
            ;;
        info | show)
            https_proxy_info "$@"
            ;;
        list | ls)
            https_proxy_list
            ;;
        *)
            msg "\nHTTPS Proxy 命令用法:"
            msg "  $is_core https-proxy add [port] [domain] [user] [pass] [email]"
            msg "  $is_core https-proxy change [port|tag]"
            msg "  $is_core https-proxy del <port|tag>"
            msg "  $is_core https-proxy info [port|tag]"
            msg "  $is_core https-proxy list"
            msg ""
            ;;
    esac
}

