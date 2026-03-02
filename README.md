# 基于 C 语言的简易网络安全日志分析工具

这是一个轻量级的命令行工具，用于从文本日志中识别常见安全事件特征，并输出汇总报告。

## 功能

- 统计总日志行数与无法提取 IP 的异常行数
- 识别失败登录（Failed password / authentication failure / login failed）
- 识别 SQL 注入特征（`UNION SELECT`、`OR 1=1`、`sleep(` 等）
- 识别 XSS 特征（`<script`、`javascript:`、`onerror=`）
- 识别端口扫描特征（`nmap`、`masscan`、`SYN scan` 等）
- 识别可疑扫描器 User-Agent（如 `sqlmap`、`nikto`）
- 按来源 IP 输出事件统计

## 编译

```bash
gcc -O2 -Wall -Wextra -std=c11 log_analyzer.c -o log_analyzer
```

## 使用

```bash
./log_analyzer <日志文件路径>
```

示例：

```bash
./log_analyzer sample_security.log
```

## 输出示例

```text
=== Security Log Analysis Report ===
Total lines:              6
Malformed lines:          0
Failed login events:      2
SQL injection indicators: 1
XSS indicators:           1
Port scan indicators:     1
Suspicious scanners:      1

--- Top suspicious IPs ---
IP                   Tot   Fail  SQLi  XSS   Scan  UA
192.168.1.10         2     2     0     0     0     0
10.0.0.8             2     0     1     1     0     0
172.16.0.77          2     0     0     0     1     1
```

## 说明

- 当前实现为规则匹配（关键词检出），适合作为课程设计或小型实验项目的基础版本。
- 可扩展方向：
  - 支持 JSON/CSV 输出
  - 引入正则表达式与更精细的日志格式解析
  - 增加黑名单与告警阈值
