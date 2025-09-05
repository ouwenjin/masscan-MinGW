[![unittests](https://github.com/robertdavidgraham/masscan/actions/workflows/unittests.yml/badge.svg?branch=master)](https://github.com/robertdavidgraham/masscan/actions/workflows/unittests.yml/?branch=master)

MASSCAN：海量 IP 端口扫描器
这是一款互联网规模的端口扫描器。它可以在 5 分钟内扫描整个互联网，每秒从一台机器传输 1000 万个数据包。

它的用法（参数、输出）与最著名的端口扫描器类似nmap。如有疑问，请尝试以下功能之一——支持对多台机器进行广泛扫描的功能已支持，但不支持对单台机器进行深度扫描的功能。

它在内部使用异步传输，类似于 scanrand、unicornscan和 等端口扫描器ZMap。它更加灵活，允许任意端口和地址范围。

注意：masscan 使用其自己的专用 TCP/IP 协议栈。除简单端口扫描之外的任何操作都可能与本地 TCP/IP 协议栈发生冲突。这意味着您需要使用 选项--src-ip从其他 IP 地址运行，或者使用--src-port选项配置 masscan 使用的源端口，然后配置内部防火墙（例如pf或iptables），以将这些端口与操作系统的其他部分隔离开来。

此工具是免费的，但请考虑为其开发捐款：比特币钱包地址：1MASSCANaHUiyTtR3bJ2sLGuMw5kDBaj4T

建筑
gcc 在 Debian/Ubuntu 上，它类似于以下内容。除了 C 编译器（例如或clang）之外，它实际上没有任何依赖项。

sudo apt-get --assume-yes install git make gcc
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
这会将程序放入masscan/bin子目录中。要在 Linux 上安装它，请运行：

make install
源代码包含大量小文件，因此使用多线程构建可以加快构建速度。这在 Raspberry Pi 上需要超过 2GB 的内存（而且容易崩溃），因此您可以使用较小的线程数，而-j4不是使用所有可能的线程。

make -j
虽然 Linux 是主要目标平台，但该代码在许多其他系统（Windows、macOS 等）上也能良好运行。以下是一些额外的构建信息：

Windows 系统（Visual Studio 版本）：使用 VS10 项目
Windows 系统（带有 MinGW）：只需输入make
Windows 系统无法运行 cygwin
Mac OS X /w XCode：使用 XCode4 项目
Mac OS X /w cmdline：只需输入make
FreeBSD：类型gmake
其他：尝试将所有文​​件编译在一起，cc src/*.c -o bin/masscan
在 macOS 上，x86 二进制文件在 ARM 仿真下似乎运行得一样快。

用法
使用方法与类似nmap。扫描指定网段的某些端口：

# masscan -p80,8000-8100 10.0.0.0/8 2603:3001:2d00:da00::/112
这将：

扫描10.x.x.x子网和2603:3001:2d00:da00::x子网
扫描两个子网上的 80 端口以及 8000 至 8100 范围（共 102 个端口）
打印输出到<stdout>可以重定向到文件
要查看完整的选项列表，请使用该--echo功能。这将转储当前配置并退出。此输出可用作程序的输入：

# masscan -p80,8000-8100 10.0.0.0/8 2603:3001:2d00:da00::/112 --echo > xxx.conf
# masscan -c xxx.conf --rate 1000
横幅检查
Masscan 的功能远不止检测端口是否开放。它还可以与该端口上的应用程序建立 TCP 连接并进行交互，从而获取简单的“横幅”信息。

Masscan 支持以下协议的横幅检查：

FTP
HTTP
IMAP4
memcached
POP3
SMTP
SSH
SSL
SMBv1
SMBv2
远程登录
RDP
VNC
问题在于，masscan 拥有独立的 TCP/IP 协议栈，与运行它的系统无关。当本地系统收到被探测目标的 SYN-ACK 数据包时，它会响应一个 RST 数据包，从而在 masscan 获取到 Banner 之前终止连接。

防止这种情况的最简单方法是为masscan分配一个单独的IP地址。这看起来像以下示例之一：

# masscan 10.0.0.0/8 -p80 --banners --source-ip 192.168.1.200
  # masscan 2a00:1450:4007:810::/112 -p80 --banners --source-ip 2603:3001:2d00:da00:91d7:b54:b498:859d
您选择的地址必须位于本地子网内，并且不能被其他系统使用。Masscan 会警告您输入错误，但您可能已经干扰了其他机器的通信几分钟，所以请务必小心。

在某些情况下，例如 WiFi，这是不可能的。在这种情况下，您可以对 masscan 使用的端口设置防火墙。这样可以防止本地 TCP/IP 协议栈检测到数据包，但 masscan 仍然可以看到它，因为它绕过了本地协议栈。对于 Linux，如下所示：

# iptables -A INPUT -p tcp --dport 61000 -j DROP
# masscan 10.0.0.0/8 -p80 --banners --source-port 61000
您可能希望选择与 Linux 可能选择的源端口不冲突的端口。您可以通过查看该文件来查看 Linux 使用的端口范围，并重新配置该范围：

/proc/sys/net/ipv4/ip_local_port_range
在最新版本的 Kali Linux（2018 年 8 月）中，该范围是 32768 到 60999，因此您应该选择低于 32768 或高于 61000 的端口。

设置的iptables规则仅持续到下次重启。您需要根据发行版查找如何保存配置，例如使用iptables-save 和/或iptables-persistent。

在 Mac OS X 和 BSD 上，步骤类似。要找出需要避开的范围，请使用以下命令：

# sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last
在 FreeBSD 和较旧的 MacOS 上，使用以下ipfw命令：

# sudo ipfw add 1 deny tcp from any to any 40000 in
# masscan 10.0.0.0/8 -p80 --banners --source-port 40000
在较新的 MacOS 和 OpenBSD 上，使用pf数据包过滤实用程序。编辑文件/etc/pf.conf并添加如下行：

block in proto tcp from any to any port 40000:40015
然后启用防火墙，运行以下命令：

# pfctl -E    
如果防火墙已在运行，则使用以下命令重新启动或重新加载规则：

# pfctl -f /etc/pf.conf
Windows 不会响应 RST 数据包，因此这两种技术都不是必需的。然而，masscan 的设计仍然使其自身 IP 地址能够发挥最佳性能，因此即使并非绝对必要，也应该尽可能以这种方式运行。

其他检查也需要同样的事情，比如该--heartbleed检查，它只是横幅检查的一种形式。

如何扫描整个互联网
虽然该程序适用于较小的内部网络，但它实际上是为整个互联网设计的。它可能看起来像这样：

# masscan 0.0.0.0/0 -p0-65535
扫描整个互联网是不对的。首先，部分互联网对扫描的反应很差。其次，有些网站会跟踪扫描并将你添加到黑名单，这会导致你被防火墙阻隔，无法访问互联网上有用的部分。因此，你需要排除大量的范围。要将范围列入黑名单或排除，你需要使用以下语法：

# masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt
这只是将结果打印到命令行。您可能希望将它们保存到文件中。因此，您需要类似以下内容：

# masscan 0.0.0.0/0 -p0-65535 -oX scan.xml
这会将结果保存在 XML 文件中，使您可以轻松地将结果转储到数据库或其他地方。

但是，默认速率只有每秒 100 个数据包，扫描互联网需要很长时间。你需要这样加快速度：

# masscan 0.0.0.0/0 -p0-65535 --max-rate 100000
这会将速率提高到每秒 100,000 个数据包，这将在每个端口大约 10 小时内扫描整个互联网（减去排除项）（如果扫描所有端口则需要 655,360 小时）。

关于此命令行，需要注意的是，这些都是nmap 兼容的选项。此外，nmap 还为您设置了与 兼容的“不可见”选项：-sS -Pn -n --randomize-hosts --send-eth。同样，XML 文件的格式也受 启发。当然，由于程序的异步nmap特性，它们之间存在很多差异，因此解决问题的方法也截然不同。

上面的命令行有点繁琐。与其把所有东西都写在命令行上，不如把它们保存在一个文件中。上面的设置看起来如下：

# My Scan
rate =  100000.00
output-format = xml
output-status = all
output-filename = scan.xml
ports = 0-65535
range = 0.0.0.0-255.255.255.255
excludefile = exclude.txt
要使用此配置文件，请使用-c：

# masscan -c myscan.conf
当您重复扫描时，这也会使事情变得更容易。

默认情况下，masscan 首先加载配置文件 /etc/masscan/masscan.conf。任何后续配置参数都会覆盖此默认配置文件中的配置。我将“excludefile”参数放在这里，这样就永远不会忘记了。它会自动运行。

获取输出
默认情况下，masscan 会生成相当大的文本文件，但很容易将其转换为其他格式。支持五种输出格式：

xml: 只需使用参数-oX <filename>。或者，使用参数--output-format xml和--output-filename <filename>。

二进制：这是 masscan 内置格式。它生成的文件更小，这样当我扫描互联网时，我的磁盘就不会被占满。不过，它们需要被解析。命令行选项--readscan将读取二进制扫描文件。使用--readscan该-oX选项将生成 XML 版本的结果文件。

grepable：这是 Nmap -oG 输出的实现，可以通过命令行工具轻松解析。只需使用参数-oG <filename>。或者，使用参数--output-format grepable和 --output-filename <filename>。

json：这将以 JSON 格式保存结果。只需使用参数-oJ <filename>。或者，使用参数--output-format json和 --output-filename <filename>。

列表：这是一个简单的列表，每行包含一个主机名和端口号。只需使用参数 即可-oL <filename>。或者，使用参数 --output-format list和--output-filename <filename>。格式如下：

<port state> <protocol> <port number> <IP address> <POSIX timestamp>  
open tcp 80 XXX.XXX.XXX.XXX 1390380064
与 Nmap 的比较
尽管 Masscan 与 nmap 存在本质上的不同，但我们在合理之处尽一切努力使nmap用户能够轻松上手。Masscan 适用于对大量机器进行大范围扫描，而 nmap 则适用于对单台机器或小范围进行密集扫描。

两个重要的区别是：

没有默认端口可供扫描，您必须指定-p <ports>
目标主机是 IP 地址或简单范围，而不是 DNS 名称，也不是可以使用的奇怪子网范围nmap（如10.0.0-255.0-255）。
您可以认为masscan以下设置已永久启用：

-sS：这仅执行 SYN 扫描（目前，将来会改变）
-Pn：不首先 ping 主机，这是异步操作的基础
-n：没有发生 DNS 解析
--randomize-hosts：扫描完全随机，始终，您无法更改此设置
--send-eth：使用原始发送libpcap
如果您需要其他兼容设置的列表nmap，请使用以下命令：

# masscan --nmap
传输速率（重要！！）
这个程序输出数据包的速度非常快。在 Windows 或虚拟机上，它每秒可以处理 30 万个数据包。在 Linux（无虚拟化）上，它每秒可以处理 160 万个数据包。这样的速度足以让大多数网络瘫痪。

请注意，它只会破坏你自己的网络。它会随机化目标 IP 地址，这样就不会破坏任何远程网络。

默认情况下，速率设置为每秒 100 个数据包。要将速率提高到一百万，请使用类似 的命令--rate 1000000。

扫描 IPv4 互联网时，您将扫描许多子网，因此即使数据包的传出速率很高，每个目标子网也会接收到少量传入数据包。

然而，使用 IPv6 扫描时，您往往会专注于包含数十亿个地址的单个目标子网。因此，您的默认行为将导致目标网络不堪重负。网络经常会在 Masscan 产生的负载下崩溃。

设计
本节描述该计划的主要设计问题。

代码布局
正如您所料，该文件main.c包含main()函数。它还包含transmit_thread()和receive_thread()函数。这些函数被刻意扁平化，并添加了大量注释，以便您只需逐行执行每个函数即可了解程序的设计。

异步
这是一种异步设计。换句话说，它与Web 服务器的关系就像nmap一样。它有独立的发送和接收线程，彼此之间基本独立。这与、和 中的设计相同。nginxApachescanrandunicornscanZMap

因为它是异步的，所以它的运行速度与底层数据包传输允许的速度一样快。

随机化
Masscan 与其他扫描仪之间的一个主要区别在于其随机化目标的方式。

其基本原理是设置一个索引变量，该变量从零开始，每探测一次就加一。在 C 代码中，其表示如下：

for (i = 0; i < range; i++) {
    scan(i);
}
我们必须将索引转换为 IP 地址。假设您要扫描所有“私有” IP 地址。那么范围表如下：

192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
在此示例中，前 64k 个索引附加到 192.168.xx 以形成目标地址。然后，接下来的 1600 万个索引附加到 10.xxx。范围内的其余索引应用于 172.16.xx。

在这个例子中，我们只有三个范围。扫描整个互联网时，我们实际上有超过 100 个范围。这是因为你必须将许多子范围列入黑名单或排除在外。这会将所需的范围分割成数百个较小的范围。

这导致了代码中最慢的部分之一。我们每秒传输1000万个数据包，并且必须将每个探测的索引变量转换为IP地址。我们通过在少量内存中进行“二分查找”来解决这个问题。在这种数据包速率下，缓存效率开始超过算法效率。理论上有很多更高效的技术，但它们都需要大量的内存，因此在实践中速度会更慢。

我们将索引转换为 IP 地址的函数称为pick()函数。实际使用时，它如下所示：

for (i = 0; i < range; i++) {
    ip = pick(addresses, i);
    scan(ip);
}
Masscan不仅支持IP地址范围，还支持端口范围。这意味着我们需要从索引变量中选择一个IP地址和一个端口。这相当简单：

range = ip_count * port_count;
for (i = 0; i < range; i++) {
    ip   = pick(addresses, i / port_count);
    port = pick(ports,     i % port_count);
    scan(ip, port);
}
这导致了代码中另一个开销更大的部分。在 x86 CPU 上，除法/模运算指令大约需要 90 个时钟周期，也就是 30 纳秒。当以每秒 1000 万个数据包的速度传输时，每个数据包只有 100 纳秒的时间。我看不出有什么更好的优化方法。不过幸运的是，两个这样的操作可以同时执行，因此执行两个这样的操作（如上所示）并不比执行一个更昂贵。

实际上，针对上述性能问题有一些简单的优化方法，但它们都依赖于i++索引变量在扫描过程中逐个增加的事实。实际上，我们需要将这个变量随机化。我们需要随机化扫描的 IP 地址顺序，否则我们将对那些并非为这种速度构建的目标网络造成严重影响。我们需要将流量均匀地分布到目标网络。

我们随机化的方法很简单，就是加密索引变量。顾名思义，加密是随机的，并在原始索引变量和输出之间建立一对一的映射。这意味着，虽然我们线性遍历范围，但输出 IP 地址是完全随机的。代码如下：

range = ip_count * port_count;
for (i = 0; i < range; i++) {
    x = encrypt(i);
    ip   = pick(addresses, x / port_count);
    port = pick(ports,     x % port_count);
    scan(ip, port);
}
这也会带来很大的开销。由于范围大小不可预测，而不是 2 的偶数次方，我们无法使用像与 (&) 和异或 (^) 这样简单的二进制技术。相反，我们不得不使用像模 (%) 这样昂贵的运算。在我目前的基准测试中，加密变量需要 40 纳秒。

这种架构支持许多很酷的功能。例如，它支持“分片”。您可以设置 5 台机器，每台机器负责五分之一的扫描工作 range / shard_count。分片可以是多台机器，也可以是同一台机器上的多个网络适配器，甚至（如果您愿意）是同一网络适配器上的多个 IP 源地址。

或者，您可以对加密函数使用“种子”或“密钥”，这样每次扫描时您都会得到不同的顺序，例如x = encrypt(seed, i)。

我们也可以通过退出程序来暂停扫描，只需记住当前的 值i，稍后再重新启动即可。我在开发过程中经常这样做。我发现我的互联网扫描出了问题，所以我点击了 停止扫描，然后在修复错误后重新启动它。

另一个功能是重传/重试。互联网上有时会丢失数据包，因此您可以连续发送两个数据包。但是，丢失一个数据包的程序可能会丢失紧接着的数据包。因此，您需要每隔约 1 秒发送一次副本。这很简单。我们已经有一个“速率”变量，它表示每秒传输的数据包数，因此重传函数只是用作i + rate 索引。有一天，我打算研究一下互联网，并区分“连续”、“1 秒”、“10 秒”和“1 分钟”的重传方式，看看丢失的数据是否存在差异。

C10 可扩展性
异步技术被称为“c10k问题”的解决方案。Masscan的设计目标是解决更高级别的可扩展性，即“C10M问题”。

C10M 的解决方案是绕过内核。Masscan 中主要有三种内核绕过方法：

自定义网络驱动程序
用户模式 ​​TCP 堆栈
用户模式同步
Masscan 可以使用 PF_RING DNA 驱动程序。该驱动程序将数据包直接从用户模式内存 DMA 到网络驱动程序，无需内核参与。这使得软件即使 CPU 速度较慢，也能以硬件允许的最大速率传输数据包。如果您在一台计算机上安装 8 张 10Gbps 网卡，这意味着它可以以每秒 1 亿个数据包的速度传输数据包。

Masscan 拥有内置的 TCP 协议栈，用于从 TCP 连接中抓取横幅广告。这意味着它可以轻松支持 1000 万个并发 TCP 连接，当然前提是计算机拥有足够的内存。

Masscan 没有“互斥锁”。现代的互斥锁（又称 futexes）大多是用户模式的，但它们有两个问题。第一个问题是它们会导致缓存行在 CPU 之间快速来回跳转。第二个问题是，当发生争用时，它们会执行内核的系统调用，这会降低性能。程序快速路径上的互斥锁会严重限制可扩展性。相反，Masscan 使用“环”来同步，例如，当接收线程中的用户模式 ​​TCP 堆栈需要在不干扰发送线程的情况下发送数据包时。

可移植性
该代码在 Linux、Windows 和 Mac OS X 上都能良好运行。所有重要代码均采用标准 C (C90) 语言编写。因此，它可以在 Visual Studio 上使用微软的编译器进行编译，在 Mac OS X 上使用 Clang/LLVM 编译器进行编译，在 Linux 上使用 GCC 进行编译。

Windows 和 Mac 系统并未针对数据包传输进行优化，每秒只能传输大约 30 万个数据包，而 Linux 系统每秒可以传输 150 万个数据包。这可能比你预期的要快。

安全代码
漏洞将获得赏金，请参阅 VULNINFO.md 文件了解更多信息。

该项目使用像这样的安全函数，safe_strcpy()而不是像这样的不安全函数strcpy()。

该项目已实现自动化单元回归测试（make regress）。

兼容性
我们付出了很多努力来使输入/输出看起来像这样nmap，每个进行端口扫描的人都（或应该）熟悉它。

IPv6 与 IPv4 共存
Masscan 支持 IPv6，但没有特殊模式，两者同时支持。（没有-6选项——始终可用）。

在您看到的任何 Masscan 使用示例中，只需在 IPv4 地址的位置放置一个 IPv6 地址即可。您可以在同一次扫描中同时包含 IPv4 和 IPv6 地址。输出结果会在同一位置显示相应的地址，无需特殊标记。

请记住，IPv6 地址空间非常大。您可能不想扫描大范围的地址，除非是通过 DHCPv6 分配的子网的前 64k 个地址。

相反，您可能希望扫描存储在--include-file filename.txt从其他来源获取的文件 () 中的大量地址列表。与其他地方一样，此文件可以包含 IPv4 和 IPv6 地址列表。我使用的测试文件包含 800 万个地址。如此大小的文件在启动时需要额外几秒钟来读取（masscan 会在扫描前对地址进行排序并删除重复项）。

请记住，masscan 包含自己的网络堆栈。因此，运行 masscan 的本地计算机无需启用 IPv6——尽管本地网络需要能够路由 IPv6 数据包。

PF_RING
为了达到每秒超​​过 200 万个数据包的速度，您需要一个 Intel 10 gbps 以太网适配器和一个来自 ntop 的特殊驱动程序“PF_RING ZC”。Masscan 无需重新构建即可使用 PF_RING。要使用 PF_RING，您需要构建以下组件：

libpfring.so（安装在/usr/lib/libpfring.so）
pf_ring.ko（他们的内核驱动程序）
ixgbe.ko（他们的英特尔 10-gbps 以太网驱动程序版本）
您不需要构建他们的版本libpcap.so。

当 Masscan 检测到适配器的名称类似于zc:enp1s0而不是 时enp1s0，它将自动切换到 PF_RING ZC 模式。

更详细的讨论可以在PoC||GTFO 0x15中找到。

回归测试
该项目包含一个内置单元测试：

$ make test
bin/masscan --selftest
selftest: success!
这会测试代码中很多棘手的部分。你应该在构建之后执行此操作。

性能测试
要测试性能，请对一次性地址运行以下命令，以避免本地路由器过载：

$ bin/masscan 0.0.0.0/4 -p80 --rate 100000000 --router-mac 66-55-44-33-22-11
攻击者--router-mac将数据包保留在本地网络段上，这样它们就不会传到互联网上。

您还可以在“离线”模式下进行测试，这是在没有传输开销的情况下程序运行的速度：

$ bin/masscan 0.0.0.0/4 -p80 --rate 100000000 --offline
第二个基准测试大致显示了如果使用 PF_RING 程序的运行速度，其开销接近于零。

顺便说一下，随机化算法大量使用了“整数运算”，而这在CPU上是一项长期运行缓慢的操作。现代CPU执行此类计算的速度已经翻倍，速度也因此masscan大幅提升。

作者
该工具由 Robert Graham 创建：电子邮件：robert_david_graham@yahoo.com twitter：@ErrataRob

执照
版权所有 (c) 2013 Robert David Graham

该程序是免费软件：您可以根据自由软件基金会发布的 GNU Affero 通用公共许可证第 3 版的条款重新分发和/或修改它。

本程序发布时，希望其能够发挥作用，但不提供任何担保；甚至不提供任何关于适销性或特定用途适用性的默示担保。更多详情，请参阅 GNU Affero 通用公共许可证。

您应该已随本程序收到一份 GNU Affero 通用公共许可证的副本。如果没有，请参阅https://www.gnu.org/licenses/。
