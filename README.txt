KakaVoicePro v34.3 源码包
=========================
版本：v34.3（2026-11-23 构建）
基线：v33（智能噪声门 + 慢启动压缩 + 参数回调）

文件清单
--------
KakaVoicePro.m          主源码（全部逻辑都在这一个文件里）
tweetnacl.c / .h        Ed25519 验签（授权用）
fishhook.c / .h         fishhook（符号重绑定）
kp_aes.h                AES/白盒授权辅助
kp_rsa.h                RSA 授权校验
build.sh                Linux 交叉编译脚本
KakaVoicePro_v29.8.dylib  旧产物（v29.8，仅作对照）

编译
----
    chmod +x build.sh
    ./build.sh

需要 iOS SDK，默认路径 /workspace/work/sdks/iPhoneOS15.6.sdk，可用环境变量覆盖：

    SDK=/path/to/iPhoneOS15.6.sdk OUT=KakaVoicePro_v34.3.dylib ./build.sh

本版新增（v34）：PK 网关探测
---------------------------
依据 deliver/PK网关越权发布逆向与验证.md，把“越权发布”的三条判据做成
纯观测探针，结果直接写进本地日志，不改动官方 PK 行为：

1. SDP 方向：hook RTCPeerConnection 的 setLocalDescription /
   setRemoteDescription，解析 m=audio 段是 a=recvonly 还是 a=sendrecv。
   首轮 recvonly 只记“订阅态”，不再据此判 PK（房间 PC 首轮同样是 recvonly）。
2. SSRC：统计 answer 里 a=ssrc 行数（有 SSRC 不等于媒体真的通了）。
3. 本地音轨：hook addTrack:completionHandler:，PK 连接上出现 addTrack
   时告警——这是“越权发布”的第一步动作。

另外在已有 WebSocket 钩子里补了一层信令探针：捕获原生 WS 的
{"op":"join","ticket":"..."}，记录 gateway 地址和 ticket 前 12 位；
若打开“PK configure 主动探测”，会在这条连接上补发
{"op":"configure","muted":false,"request_id":"..."}，并把回包原样写日志。

日志位置
--------
Documents/KakaAudio/rack.log（和现有 kp_log 同一份）
关键前缀：[PK-PROBE]

典型判读
--------
- 本地 offer audio=recvonly            → 官方 PK 接收端，只收不发
- 远端 answer audio=recvonly           → 结论A：服务端按 ticket 角色拦截
- 远端 answer audio=sendrecv           → 结论B：网开放行上行，还要 B 房听众验收
- PK 连接上出现 addTrack               → 有人往 PK 连接挂本地音轨（越权动作）
- 捕获 PK join → gateway=... ticket=... → 信令层可用，可继续做 configure 探测
- 信令出现 configured / error          → configure 探测的直接回包

开关
----
面板“PK 网关探测（SDP/信令写日志）”：默认开，纯观测，不改变任何行为。
面板“PK configure 主动探测（默认关）”：打开后向 PK 网关补发
configure muted:false。注意：如果 ticket 是一次性的，这条探测可能抢占
官方 PK 连接，建议只在自己房间、自己参与的 PK 上验证。

注意
----
APM 的 AGC/NS/瞬态抑制是全局硬锁，不受开关控制，底噪会明显变大，属预期。
`g_priorityLoud` 是霸麦开关，`g_shieldRemote` 是全屏蔽，
`g_shieldLowOnly` 是 20% 档 —— 二次开发请沿用这三个名字。
PK 探测新增：`g_pkProbeEnabled`（总开关）、`g_pkProbeActive`（主动探测）。

v34.3 新增两个实验开关（默认都关）
--------------------------------
1. 只播 BGM/MP3（麦克风置零）
   在 kp_process_pcm 里把 vL/vR 直接置 0，只保留 mus（BGM/SFX/片段）。
   效果：整条上行只剩伴奏，但仍走同一个 PCM、同一个 Opus、同一个 SSRC，
   服务端分不出这是 MP3——就是官方 BGM 那条路径。
   用法：Documents/KakaAudio/BGM/ 放 MP3 → 面板开“伴奏 BGM” → 开本开关；
   音量用“伴奏音量”调到输出 RMS -12～-10dB（别到 -2dB，会炸 limiter）。

2. 第二 SSRC 实验（仅测试房）
   不再在 addTransceiver hook 里建第二条。只在两个时机构建：
   a) 第一条 RTCRtpSender 真正 setTrack: 拿到 audio track（主路径）
   b) 第一次 answer=sendrecv/sendonly，且 answer 已应用（备路径）
   建完立刻把第二条 direction 从 2(recvonly) 强制改成 0(sendrecv)，
   再把第一条的同一个 track 用 setTrack: 挂到第二条 sender。
   每条 PC 只建一次；重进房间就是新 PC，天然重置。

   判读（都写在 rack.log，前缀 [2SSRC]）：
   - hook install: ... setTrack=1 setDirection=1 → 两个钩子确实装上了
   - 第二条 transceiver 已建 ... 初始direction=2 触发=setTrack
   - 第二条 transceiver direction 2→0(sendrecv) 已确认 after=0
   - 第二条 sender setTrack 完成 ... track=已挂（触发=setTrack）
   - 本地 offer m=audio 数量=2 | mid=0 dir=sendrecv ssrc行=1 | mid=1 dir=sendrecv ssrc行=1
   缺任何一行，先修客户端，不要下“服务端拒绝”的结论。

v34.3 结论门槛
-------------
必须同时满足：
   1) 第二条 transceiver 已建，且日志确认 direction 0(sendrecv)
   2) 第二条 sender 已挂同一条 track（track=已挂）
   3) offer 里 m=audio 数量=2，且两条都是 sendrecv/sendonly
在此之后，answer 仍然是 inactive 或只有 1 个 m=audio，
才能判定“单 PC 双 SSRC 被服务端拒”，再转多账号同房或单 SSRC 增益路线。