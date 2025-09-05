[![unittests](https://github.com/robertdavidgraham/masscan/actions/workflows/unittests.yml/badge.svg?branch=master)](https://github.com/robertdavidgraham/masscan/actions/workflows/unittests.yml/?branch=master)

# 🚀 MASSCAN 优化整理版

## 1. 核心特点

* **极致性能**：单机每秒可发送 **1000 万个数据包**，5 分钟扫描整个 IPv4。
* **异步架构**：独立发送/接收线程，最大限度利用硬件性能。
* **独立 TCP/IP 协议栈**：避免依赖本地内核网络栈，可直接处理横幅（banner）。
* **随机化扫描**：通过加密索引随机化目标顺序，避免集中打击目标网络。
* **多输出格式**：XML、JSON、Nmap grepable、二进制、列表。

---

## 2. 安装方式

原文地址:https://github.com/robertdavidgraham/masscan

编译过程:https://blog.csdn.net/weixin_73850291/article/details/150557247?spm=1001.2014.3001.5501

### Linux (推荐)

```bash
sudo apt-get update && sudo apt-get install -y git make gcc
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make -j   # 多线程编译
sudo make install
```

### Windows

* Visual Studio：打开 `vs10` 项目。
* MinGW：直接 `make`。
* 不支持 Cygwin。

### macOS

* XCode：打开 `XCode4` 项目。
* 命令行：直接 `make`。

---

## 3. 基本用法

### 扫描子网端口

```bash
masscan -p80,8000-8100 10.0.0.0/8
```

### 使用配置文件

```bash
masscan -p80 192.168.0.0/16 --echo > my.conf
masscan -c my.conf --rate 1000
```

### 保存结果

```bash
masscan 192.168.1.0/24 -p80 -oX result.xml
masscan 192.168.1.0/24 -p80 -oJ result.json
```

---

## 4. 横幅抓取 (服务识别)

```bash
masscan 10.0.0.0/8 -p80 --banners --source-ip 192.168.1.200
```

> ⚠️ 必须隔离 TCP/IP 协议栈（设置源 IP 或 iptables/pf 规则）。

---

## 5. 高速全网扫描

### 全 IPv4 空间 + 全端口

```bash
masscan 0.0.0.0/0 -p0-65535 --rate 100000 --excludefile exclude.txt -oX fullscan.xml
```

* `--rate`：调节速率（默认 100 pps，安全；百万级会压垮网卡/目标）。
* `--excludefile`：排除敏感网段（军队、政府、研究网络）。

---

## 6. 输出格式

* `-oX file.xml` → XML
* `-oJ file.json` → JSON
* `-oG file.grep` → Nmap grep 格式
* `-oL file.txt` → 简单列表
* `--readscan`   → 解析二进制结果文件

---

## 7. 防止 RST 干扰 (横幅模式必要)

Linux 示例：

```bash
iptables -A INPUT -p tcp --dport 61000 -j DROP
masscan 10.0.0.0/8 -p80 --banners --source-port 61000
```

macOS / BSD 示例：

```bash
sudo ipfw add 1 deny tcp from any to any 40000 in
masscan 10.0.0.0/8 -p80 --banners --source-port 40000
```

---

## 8. 性能优化

* **PF\_RING ZC 驱动**：Intel 10Gbps 网卡，配合 PF\_RING，可达 1 亿 PPS。
* **分片扫描**：多机/多网卡分工 `--shard`
* **离线模式**：性能基准测试

  ```bash
  masscan 0.0.0.0/4 -p80 --rate 100000000 --offline
  ```

---

## 9. 使用建议（安全 & 合法）

* ⚠️ 扫描公网要小心：很多 ISP、IDC 会拉黑扫描源 IP。
* 推荐 **实验环境/授权目标** 使用。
* 建议配合 `--excludefile exclude.txt`，避免误扫敏感地址。
* 如用于研究，可先低速小范围扫描验证。

---

## 10. 适用场景

✅ 适合：

* 互联网资产测绘
* 红队快速摸清目标暴露面
* 大规模漏洞探测前的资产发现

❌ 不适合：

* 单机深度扫描（请用 nmap）
* 内网靶场需要服务识别时（masscan 较弱）
