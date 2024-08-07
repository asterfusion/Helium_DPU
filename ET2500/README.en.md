- [Overview](#intro)
- [Application Scenario](#scene)
- [Hardware Specification](#spec)
- [Operating System](#os)

<a id="intro"></a>
# Overview
The Asterfusion ET2500 is an open intelligent gateway designed to address the intricate networking requirements of modern enterprises. In recent years, businesses have embraced technologies like cloud computing, big data, video conferencing, live streaming, and notably, the application of AI and IoT technologies has facilitated business transformation through machine empowerment. The widespread adoption of these innovations has substantially reshaped the composition and direction of enterprise network traffic. Traditional network devices, constrained by their closed and inflexible nature, face challenges in adapting to these emerging business trends.
Traditional enterprise networks typically employ various dedicated devices to handle different functions:
- Dedicated routers: Responsible for routing network traffic, NAT, traffic control, QoS, and other functionalities.
- Dedicated firewalls: Control inbound and outbound network traffic through security rules.
- Dedicated VPN gateways: Authenticate remote users and facilitate encrypted communication.
- Dedicated IDS/IPS: Deeply analyze network traffic to prevent network attacks.
- Dedicated load balancers: Distribute network traffic among multiple enterprise servers.
- Dedicated Network Traffic Analyzer (NTA): Real-time monitoring and analysis of network traffic.
- Dedicated Network Behavior Analyzer (NBA): Utilizes AI and big data behavior analysis techniques to provide advanced threat detection.
These devices each utilize dedicated hardware and software, making enterprise networks complex, expensive, and difficult to operation & maintain. To address this issue, the ET2500 adopts a Computing-Networking fusion chip architecture and a decoupled open design, allowing enterprises to use a single intelligent device to perform all of the aforementioned functions.
The ET2500 uses Marvell OCTEON 10 CN102XX chip. This Computing-Networking fusion chip integrates an 8-core ARM 64-bit Neoverse N2 processor, programmable Ethernet switch ports with total throughput of 60 Gbps, and an embedded encryption/decryption engine with a processing capacity of 60 Gbps. Combined with optimized DPDK toolkits bound to these hardware components and an optional AI hardware accelerator capable of up to 26 TOPS, it enables full-stack analysis and intelligent processing of network traffic from the network layer to the application layer. Additionally, the ET2500 supports installation of various Linux distributions, including Ubuntu, Debian, OpenWRT  and CentOS, fostering an open software ecosystem that includes VPP, UFW, OpenVPN, Snort, HAProxy, Nginx, ntopng, and others. Users can run multiple software applications concurrently on the same device according to their needs.
As a compact high-performance box only the size of a laptop and 1U in height, the ET2500 is ideal for deployment at enterprise exits as an intelligent gateway. For small businesses, a single ET2500 can handle all functions from routing and firewalling to network traffic analysis, and can even serve as a small server running various enterprise applications. For medium to large enterprises, multiple ET2500 units can be deployed as a resource pool, enabling horizontal load balancing or vertical task specialization akin to cloud computing, facilitating on-demand and elastic scheduling.
The ET2500 fundamentally simplifies enterprise campus networks, reducing CapEX and OpEX. Its openness and intelligent design excel in meeting future network demands, whether coping with escalating network traffic or swiftly responding to emerging technologies. This allows enterprises to focus more on innovating and developing core business activities, alleviating concerns about complex network management. The introduction of the ET2500 marks another significant stride in the transformation of enterprise IT towards digitization, intelligence, and modernization.

