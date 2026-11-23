KakaVoicePro v34.1 源码包
=========================
版本：v34.1（2026-11-23 构建）
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

    SDK=/path/to/iPhoneOS15.6.sdk OUT=KakaVoicePro_v34.1.dylib ./build.sh

本版新增（v34）：PK 网关探测
---------------------------
依据 deliver/PK网关越权发布逆向与验证.md，把“越权发布”的三条判据做成
纯观测探针，结果直接写进本地日志，不改动官方 PK 行为：

1. SDP 方向：hook RTCPeerConnection 的 setLocalDescription /
   setRemoteDescription，解析 m=audio 段是 a=recvonly 还是 a=sendrecv。
   本地 offer 出现 recvonly 时自动判定为 PK 接收端并打星标。
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

v34.1 新增两个实验开关（默认都关）
--------------------------------
1. 只播 BGM/MP3（麦克风置零）
   在 kp_process_pcm 里把 vL/vR 直接置 0，只保留 mus（BGM/SFX/片段）。
   效果：整条上行只剩伴奏，但仍走同一个 PCM、同一个 Opus、同一个 SSRC，
   服务端分不出这是 MP3——就是官方 BGM 那条路径。
   用法：Documents/KakaAudio/BGM/ 放 MP3 → 面板开“伴奏 BGM” → 开本开关；
   音量用“伴奏音量”调到输出 RMS -12～-10dB（别到 -2dB，会炸 limiter）。

2. 第二 SSRC 实验（仅测试房）
   在 RTCPeerConnection addTrack:completionHandler: 上做文章：
   房间 PC 第一次 addTrack 音频轨时，用同一个 RTCPeerConnectionFactory、
   同一个 source 再建一条 RTCAudioTrack（新 trackId），在原轨之后立刻追加，
   争取让同一轮 offer 出现 2 个 m=audio、2 个独立 SSRC。
   只在非 PK 的 PC 上加，且全局只加一次；关掉开关会重置标记，重进房间生效。

   判读（都写在 rack.log）：
   - [2SSRC] 同一轮协商追加第二条音频轨 → 说明钩子生效
   - answer 出现 2 个 m=audio 且第二条 sendrecv/sendonly → 服务端可能按 SSRC 收
   - answer 只有 1 个 m=audio，或第二条 recvonly → 服务端按 participant 去重，白加
   - 如果 PK/Janus 网关一个 participant 只允许一条 audio m-line，第二条会直接进房失败

   风险：先在测试房开，不要在主房试；双音验证用 1kHz/2kHz 分别喂两条轨，
   让 B 房录音，两个音都在才说明按 SSRC 混，只听到一个说明被去重。
   本实现两条轨共享同一个 source，信号内容相同，双音验证需要另配源。
v34.1 修正（2SSRC 挂点重做）
--------------------------
问题：原实现挂在 RTCPeerConnection addTrack:，但 KAKA 房间是
addTransceiver（先 recvonly）+ replaceTrack/改 direction，addTrack 根本不会触发；
同时用“首个 offer 是 recvonly”判 PK，把房间 PC 也误判成 PK 直接跳过。

现在：
1. 新增 hook：addTransceiverOfType:init:（记录 transceiver/sender -> PC 映射、
   记录 App 实际用的 mediaType）、RTCRtpSender replaceTrack:completionHandler:
   （拿到真实音频轨时触发）、RTCRtpTransceiver setDirection:（只记录方向变化）。
2. 第二条轨在 replaceTrack 首次拿到音频轨时追加：同一个 PC 上
   addTransceiverOfType:init:（默认 sendrecv）+ 把同一 track replaceTrack 到新 sender，
   保证落在同一轮协商里。mediaType 复用 App 传过的值，兜底再试 soun。
3. PK 判定不再用 offer 方向，也不再用 isPK 挡 2SSRC；PK 接收端从不 replaceTrack，
   天然不会进到这个分支。房间 PC 每进一次房间就是新 PC，天然重置“只加一次”。
4. 日志判据：出现 `[2SSRC] 触发点=replaceTrack → 已追加第二条 audio transceiver`
   才说明客户端真的加了；只有这时 answer 里 1 个 m=audio 才叫“服务端不受理”。