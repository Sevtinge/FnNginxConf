#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FnNginxConf - 规则存取、校验与哈希。"""

import hashlib
import json
import os
import tempfile
import time
import uuid

from nginx_cfg import (
    validate_location,
    validate_http_target,
    validate_socket_target,
    check_location_conflict,
    normalize_location,
)

RULES_FILE = os.environ.get("RULES_FILE", "/var/apps/FnNginxConf/var/rules.json")


def log(msg):
    line = "[%s] [rules] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    lf = os.environ.get("LOG_FILE", "")
    if lf:
        try:
            with open(lf, "a", encoding="utf-8", errors="replace") as f:
                f.write(line)
        except Exception:
            pass
    else:
        print(line, end="")


def new_rule_id():
    return uuid.uuid4().hex


def load_rules():
    """加载规则列表；文件缺失/损坏返回 []（不崩溃）。"""
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        log("读取规则文件失败: %s" % e)
        return []


def save_rules(rules):
    """原子写规则文件（tmp + os.replace）。"""
    rules = list(rules)
    d = os.path.dirname(RULES_FILE)
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".rules-", dir=d)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, RULES_FILE)
        return True
    except OSError as e:
        log("保存规则文件失败: %s" % e)
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False


def rules_hash(rules):
    """规则列表的 sha256（用于"是否已应用"指示）。"""
    canonical = json.dumps(rules, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_rule(rule, existing=None, exclude_id=None):
    """校验并规范化一条规则。

    existing: 当前全部规则（用于规则间重复 location 检查），exclude_id: 编辑时排除自身。
    返回 (normalized_rule_or_None, error_or_None, warning_or_None)。
    """
    if not isinstance(rule, dict):
        return None, "规则必须是对象", None

    name = rule.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, "名称不能为空", None
    name = name.strip()
    if len(name) > 100:
        return None, "名称过长（最多 100 字符）", None

    location, err = validate_location(rule.get("location"))
    if err:
        return None, err, None

    rtype = rule.get("type")
    if rtype not in ("http", "socket"):
        return None, "类型必须是 http 或 socket", None
    if rtype == "http":
        target, err = validate_http_target(rule.get("target"))
        if err:
            return None, err, None
        socket = None
    else:
        socket, err = validate_socket_target(rule.get("socket"))
        if err:
            return None, err, None
        target = None

    # 冲突检测：不占用官方/系统已有路径（reject 阻塞，warn 非阻塞）
    status, msg, _ = check_location_conflict(location)
    if status == "reject":
        return None, msg, None

    # 规则间重复 location
    if existing:
        norm = normalize_location(location)
        for r in existing:
            if exclude_id and r.get("id") == exclude_id:
                continue
            if normalize_location(r.get("location", "")) == norm:
                return None, "已有规则使用相同路径 %s" % r.get("location"), None

    normalized = {
        "id": rule.get("id") or new_rule_id(),
        "name": name,
        "location": location,
        "type": rtype,
        "target": target,
        "socket": socket,
        "stripPrefix": bool(rule.get("stripPrefix", True)),
        "enabled": bool(rule.get("enabled", True)),
    }
    warning = msg if status == "warn" else None
    return normalized, None, warning
