- [Overview](#intro)
- [Application Scenario](#scene)
- [Hardware Specification](#spec)
- [Operating System](#os)

<a id="intro"></a>
# Overview
The Asterfusion ET2500 is an open intelligent gateway designed to address the intricate networking requirements of modern enterprises. 
In recent years, businesses have embraced technologies like cloud computing, big data, video conferencing, live streaming, and notably, the application of AI and IoT technologies has facilitated business transformation through machine empowerment. 
The widespread adoption of these innovations has substantially reshaped the composition and direction of enterprise network traffic. 
Traditional network devices, constrained by their closed and inflexible nature, face challenges in adapting to these emerging business trends.
Traditional enterprise networks typically employ various dedicated devices to handle different functions:
- Dedicated routers: Responsible for routing network traffic, NAT, traffic control, QoS, and other functionalities.
- Dedicated firewalls: Control inbound and outbound network traffic through security rules.
- Dedicated VPN gateways: Authenticate remote users and facilitate encrypted communication.
- Dedicated IDS/IPS: Deeply analyze network traffic to prevent network attacks.
- Dedicated load balancers: Distribute network traffic among multiple enterprise servers.
- Dedicated Network Traffic Analyzer (NTA): Real-time monitoring and analysis of network traffic.
- Dedicated Network Behavior Analyzer (NBA): Utilizes AI and big data behavior analysis techniques to provide advanced threat detection.

These devices each utilize dedicated hardware and software, making enterprise networks complex, expensive, and difficult to operation & maintain. To address this issue, the ET2500 adopts a Computing-Networking fusion chip architecture and a decoupled open design, allowing enterprises to use a single intelligent device to perform all of the aforementioned functions.

The ET2500 uses Marvell OCTEON 10 CN102XX chip. This Computing-Networking fusion chip integrates an 8-core ARM 64-bit Neoverse N2 processor, programmable Ethernet switch ports with total throughput of 60 Gbps, and an embedded encryption/decryption engine with a processing capacity of 60 Gbps. Combined with optimized DPDK toolkits bound to these hardware components and an optional AI hardware accelerator capable of up to 26 TOPS, it enables full-stack analysis and intelligent processing of network traffic from the network layer to the application layer. 

Additionally, the ET2500 supports installation of various Linux distributions, including Ubuntu, Debian, OpenWRT  and CentOS, fostering an open software ecosystem that includes VPP, UFW, OpenVPN, Snort, HAProxy, Nginx, ntopng, and others. Users can run multiple software applications concurrently on the same device according to their needs.

As a compact high-performance box only the size of a laptop and 1U in height, the ET2500 is ideal for deployment at enterprise exits as an intelligent gateway. For small businesses, a single ET2500 can handle all functions from routing and firewalling to network traffic analysis, and can even serve as a small server running various enterprise applications. For medium to large enterprises, multiple ET2500 units can be deployed as a resource pool, enabling horizontal load balancing or vertical task specialization akin to cloud computing, facilitating on-demand and elastic scheduling.

The ET2500 fundamentally simplifies enterprise campus networks, reducing CapEX and OpEX. Its openness and intelligent design excel in meeting future network demands, whether coping with escalating network traffic or swiftly responding to emerging technologies. This allows enterprises to focus more on innovating and developing core business activities, alleviating concerns about complex network management. The introduction of the ET2500 marks another significant stride in the transformation of enterprise IT towards digitization, intelligence, and modernization.

<a id="scene"></a>
# Application Scenario
Based on the open hardware-software decoupled architecture, the ET2500 combines a rich array of open-source software for control plane with hardware-optimized data plane, and can connect to SSDs, 5G/LTE, WiFi6E/7, GNSS, TPM, and other devices via M.2 and USB interfaces, thereby addressing diverse application scenarios. Here are some typical scenarios that can be used individually or in combination:

- Router: Ubuntu + VPP
  - Hardware-optimized vector packet technology and DPDK accelerate data plane forwarding, delivering up to 60Gbps forwarding performance.
  - Multi-WAN load balancing across Ethernet and 5G/LTE links.
  - Comprehensive QoS policies for precise management of traffic from different users and applications.
  - Firewall: Ubuntu + iptables + BPFILTER
  - Flexible and efficient iptables configuration suitable for a wide range of scenarios.
  - GUFW provides a simple and user-friendly GUI.
  - BPFILTER leverages eBPF for advanced packet filtering and processing.

- VPN Gateway: Ubuntu + OpenVPN/WireGuard
  - Hardware-accelerated OpenVPN with encryption/decryption engine supports up to 60Gbps throughput.
  - WireGuard benefits from an 8-core CPU for accelerated performance.
  - Installation of the latest VPN software on demand to adapt to changing network environments.

- IDS/IPS: Ubuntu + Snort
  - Leading open-source IDS/IPS with continuously updated rule sets from its active open community.
  - Hardware DPDK enhances packet processing performance and reduces latency.
  - Optimized regular expression engine boosts IDS/IPS performance.

- Load Balancer: Ubuntu + HAProxy + Nginx
  - Hardware DPDK improves processing speed and throughput.
  - Optimized regular expression engine boosts  load balancing performance based on domain and URL.
  - Hardware SSL engine speeds up HTTPS connections.

- Network Traffic Analyzer (NTA): Ubuntu + ntopng
  - Real-time traffic monitoring, protocol recognition, application analysis, historical data logging, and visual reporting capabilities.
  - Intuitive GUI for visualizing and analyzing network traffic and performance metrics.
  - Hardware SSL engine accelerates HTTPS traffic analysis.

Additionally, users have the flexibility to install new software or develop their own software using the built-in toolchain as needed to address additional use cases.

<a id="spec"></a>
# Hardware Specification
| Product Model | Sub Model | ET2500 |
| --- | -- | --  |
| Computing | CPU | 8xARM64 N2 @2.7GHz |
|  | Cache | L2 8MB, L3 16MB |
|  | RAM | 16GB DDR5 SODIMM, up to 48GB |
|  | Flash | 64GB eMMC 5.1 |
|  | NVME SSD (Option) | up to 4TB, M.2 M key, share slot with AI accelerator |
|  | SATA SSD  (Option) | up to 4TB, M.2 M key, dedicated slot |
|  | SPECint (2017) | 37 |
| Network Interface | 10GE(SFP+) | 4 |
| | 2.5GE (RJ45) | 4 |
| | 1GE (RJ45) | 8 |
| | PoE | 4 of 2.5GE or 8 of 1GE ports |
| | WiFi (Option) | WiFi6E/7, M.2 E key |
| | 5G/LTE (Option) | 2 SIM cards, M.2 B key |
| | Antenna | 6 (2 on front, 4 on rear) |
| Network Performance | L2/L3 switching capacity | 60Gbps |
| | Routing capacity | 60Gbps |
| | Firewall capacity | 60Gbps |
| | Encryption and Decryption capacity | 60Gbps |
| PTP(Option) | SyncE accuracy | 20ns |
| | SyncE holdover time | > 8hours |
| AI accelerator  | Inference performance | 26TOPS@INT8 |
| Misc. interface | USB | 1 x USB3.1 |
| | OOB | 1 x RS232 RJ45 |
| Electrical characteristics | Fan | 2 |
| | Power Module | 1 x 150W (w/o PoE) or 1 x 270W (PoE) |
| | Input voltage | 100~240VAC |
| | Maximum power consumption | 60W (FULL configuration and workload) |
| | PoE budget | 150W |
| Dimensions | Height | 1RU |
| | Dimensions (W x H x D, mm)  | 220 x 44 x 310 |
| Operating conditions | Operating temperature | 0 – 45℃ |
| | Relative humidity | 5% - 95% (non-condensing) |


## HighLight
- 8 x 2.7GHz ARM64 Neoverse N2 Core
- 16GB pluggable DDR5 SO-DIMM, up to 64G
- 4 x 10GE, 4 x 2.5GE  and 8 x 1GE, optional 4xPoE @150W budget
- True inline crypto engine
- Optional AI hardware accelerator with 26TOPS INT8 inference performance
- Optional M.2 SSD up to 4TB
- 2 pluggable modules with M.2 form, extending support 5G/LTE, WiFi6E/7, BlueTooth5.3, GNSS, TPM(Trusted Platform Module), etc.
- Optional PTP module with 20ns accuracy and BC support, featuring holdover > 8 hours
- 60Gbps intelligent data processing for routing, firewall, IPSec and SSL/TLS
- <60 Watt with FULL configuration and workload (w/o PoE)

<a id="os"></a>
# Operating System
- Ubuntu 24.04 LTS
- Debian 12.6
- OpenWRT 23.05


