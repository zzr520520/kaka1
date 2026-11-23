#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <math.h>
#import <string.h>
#import <stdio.h>
#import <mach-o/dyld.h>
#include "tweetnacl.h"
#include "kp_aes.h"

// TweetNaCl 随机源桥接（dylib 侧仅验签，密钥生成不使用）
void randombytes(unsigned char *buf, unsigned long long len) {
    arc4random_buf(buf, (size_t)len);
}

// ==========================================
// 1. 全局配置与状态（v31.0 全新重构版：已移除变声，精简链路 + 统一同步）
// ==========================================
#define KP_VERSION      @"v34.1"
#define EQ10_BANDS      10
#define MAX_CHANNELS    8
#define REVERB_CH       2
#define KP_PROC_CHUNK   1024
#define KP_LOOK         192
#define SFX_SLOT        4
#define CLIP_SLOT       4
#define CLIP_SECONDS    60
#define CLIP_MAX_SAMPLES (48000 * CLIP_SECONDS)
#define AUDIO_MAX_FRAMES (48000 * 600)
#define BGM_RETIRE      3
#define REC_RETIRE      2

static _Atomic BOOL  g_dspEnabled        = YES;
static _Atomic BOOL  g_losslessPriority  = YES;
static _Atomic BOOL  g_deepBypassVP      = NO;
static _Atomic BOOL  g_priorityLoud      = YES;
static _Atomic BOOL  g_oneTapMasterLock  = NO;
static _Atomic double g_lastLockTap      = 0.0;
static _Atomic float g_sampleRate        = 48000.0f;

static _Atomic BOOL  g_lowCutEnabled     = YES;
static _Atomic BOOL  g_throatEnabled     = YES;

static _Atomic BOOL  g_compEnabled       = YES;
static _Atomic float g_compThresh        = 0.15f;   // v33：压缩阈值（约 -16.5dBFS），保留字头瞬态爆发力
static _Atomic float g_compRatio         = 3.2f;    // v33：3.2:1 紧致压缩，字句连贯又不成方波
static _Atomic float g_preGain           = 1.40f;   // v33：适度前级驱动（告别 1.80f 过载死砖墙）
static _Atomic BOOL  g_forceDefaultMode  = YES;     // 强制将 VoiceChat 改为 Default，甩掉苹果通话模式压制
static _Atomic BOOL  g_disableDucking    = YES;     // 关闭系统/WebRTC 自动闪避
static _Atomic BOOL  g_understageEnabled = NO;      // 台下开麦：强开采集投递 + 强解本地静音（默认关，防热麦）
static _Atomic BOOL  g_pkProbeEnabled    = YES;     // v34 PK 网关探测：SDP 方向 / 信令 configure 全量写日志（纯观测，默认开）
static _Atomic BOOL  g_pkProbeActive     = NO;      // v34 主动探测：向 PK 网关补发 configure muted:false（默认关）

static _Atomic BOOL  g_eq10Enabled       = YES;
static const float kEq10Freqs[EQ10_BANDS] = {
    60.0f, 125.0f, 250.0f, 500.0f, 1000.0f, 2000.0f, 3500.0f, 6000.0f, 10000.0f, 14000.0f
};
static _Atomic float g_eq10Gains[EQ10_BANDS] = {
    -5.0f, -3.0f, -1.0f, 0.5f, 1.5f, 3.5f, 4.5f, 3.0f, 1.5f, 1.0f
};

static _Atomic BOOL  g_reverbEnabled     = NO;
static _Atomic float g_reverbRoom        = 0.85f;
static _Atomic float g_reverbWet         = 0.25f;

static _Atomic BOOL  g_limiterEnabled    = YES;
static _Atomic float g_makeupGain        = 1.55f;   // v33：补偿增益，目标说话 RMS 稳在 -10.5dB 左右
static _Atomic float g_limiterCeiling    = 29800.0f; // 留出余量，避免混音阶段硬顶 100% 变方波

static _Atomic BOOL  g_mixDspEnabled     = YES;
static _Atomic float g_bgmVolume         = 0.45f;
static _Atomic BOOL  g_bgmOnly           = NO;    // v34.1 只播 BGM/SFX：麦克风路径置零，只留 mus
static _Atomic BOOL  g_secondSSRC        = NO;    // v34.1 第二 SSRC 实验：房间 PC 在同一轮协商追加一条音频轨
static __weak id      g_rtcFactory       = nil;  // 最近一次 RTCPeerConnectionFactory，用于建第二条轨
static BOOL           g_secondSSRCApplied = NO;  // 第二 SSRC 只加一次（房间 PC）
static _Atomic float g_sfxVolume         = 1.0f;
static _Atomic BOOL  g_duckEnabled       = NO;
static _Atomic float g_bgmDuckFloor      = 0.22f;
static float         g_duckGain          = 1.0f;
static _Atomic BOOL  g_clipLoop          = NO;
static NSString     *g_bgmName           = nil;

// 本地远端屏蔽护盾（仅作用于本地远端播放轨）
static _Atomic BOOL    g_shieldRemote    = NO;
static _Atomic BOOL    g_shieldLowOnly   = YES;
static NSMutableArray *g_shieldTracks    = nil;
static void kp_shield_apply(void);

// 实时仪表与计数
static _Atomic int  g_vuMic     = 0;
static _Atomic int  g_vuMix     = 0;
static _Atomic int  g_vuIn      = 0;
static _Atomic int  g_vuGr      = 0;
static _Atomic int  g_vuOut     = 0;
static _Atomic long g_pcmCalls  = 0;
static _Atomic long g_mixCalls  = 0;
static _Atomic long g_frames    = 0;
static _Atomic int  g_hookState = 0;

// 持久化 Keys
#define KEY_DSP_ON          @"kaka_v31_dsp_on"
#define KEY_LOSSLESS_ON     @"kaka_v31_lossless_on"
#define KEY_DEEP_VP_ON      @"kaka_v31_deep_vp_on"
#define KEY_LOWCUT_ON       @"kaka_v31_lowcut_on"
#define KEY_GAIN_VAL        @"kaka_v31_gain_val"
#define KEY_CEIL_VAL        @"kaka_v31_ceil_val"
#define KEY_MIXDSP_ON       @"kaka_v31_mixdsp_on"
#define KEY_THROAT_ON       @"kaka_v31_throat_on"
#define KEY_COMP_ON         @"kaka_v31_comp_on"
#define KEY_COMP_THR        @"kaka_v31_comp_thr"
#define KEY_COMP_RATIO      @"kaka_v31_comp_ratio"
#define KEY_EQ10_ON         @"kaka_v31_eq10_on"
#define KEY_EQ10_GAINS      @"kaka_v31_eq10_gains"
#define KEY_LIMITER_ON      @"kaka_v31_limiter_on"
#define KEY_REVERB_ON       @"kaka_v31_reverb_on"
#define KEY_REVERB_ROOM     @"kaka_v31_reverb_room"
#define KEY_REVERB_WET      @"kaka_v31_reverb_wet"
#define KEY_BGM_VOL         @"kaka_v31_bgm_vol"
#define KEY_SFX_VOL         @"kaka_v31_sfx_vol"
#define KEY_BGM_NAME        @"kaka_v31_bgm_name"
#define KEY_DUCK_ON         @"kaka_v31_duck_on"
#define KEY_DUCK_FLOOR      @"kaka_v31_duck_floor"
#define KEY_MASTER_LOCK     @"kaka_v31_master_lock"
#define KEY_SHIELD_ON       @"kaka_v31_shield_on"
#define KEY_SHIELD_LOW      @"kaka_v31_shield_low"
#define KEY_PRIORITY_LOUD   @"kaka_v31_priority_loud"
#define KEY_CLIP_LOOP       @"kaka_v31_clip_loop"
#define KEY_UNDERSTAGE_ON   @"kaka_v31_understage_on"
#define KEY_NOISE_GATE_ON   @"kaka_v33_gate_on"
#define KEY_PK_PROBE_ON     @"kaka_v34_pk_probe_on"
#define KEY_PK_PROBE_ACTIVE @"kaka_v34_pk_probe_active"
#define KEY_BGM_ONLY        @"kaka_v34_bgm_only"
#define KEY_SECOND_SSRC     @"kaka_v34_second_ssrc"

static float g_dc_x1[MAX_CHANNELS] = {0};
static float g_dc_y1[MAX_CHANNELS] = {0};
static float g_hpfAlpha            = 0.9870f;
// v33：智能平滑噪声门（2ms 快开不吃字头 / 120ms 平滑关保留尾音，静音衰减至 2%）
static float g_gateEnv[MAX_CHANNELS] = {0};
static float g_gateAtkCoef          = 0.5f;
static float g_gateRelCoef          = 0.05f;
static _Atomic float g_gateThresh   = 0.015f;   // 噪声门阈值（约 -36.5dBFS）
static _Atomic BOOL  g_noiseGateEnabled = YES;  // 噪声门总开关
static float g_compAtkCoef         = 0.0025f;
static float g_compRelCoef         = 0.085f;
static float g_compEnv[MAX_CHANNELS] = {0};
static float g_grCompPeak          = 0.0f;
static float g_grLimPeak           = 0.0f;
static float g_kvEnv        = 0.0f;  // KVDSP 浮点出口压缩包络（KPCustomAudioProcessor 专用）
static float g_kvGainSmooth = 1.0f;  // KVDSP 浮点出口平滑增益

static void kp_log(NSString *fmt, ...);
static void kp_pk_ws_tx_probe(id task, NSString *s);
static void kp_pk_ws_rx_probe(id task, NSString *s);
static void kp_rebuild_filter_bank(void);
static void kp_update_ball(void);
static void kp_sync_all_ui(void);
static void kp_toggle_master_lock(BOOL lock);

static void load_saved_settings(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if ([ud objectForKey:KEY_DSP_ON])        g_dspEnabled       = [ud boolForKey:KEY_DSP_ON];
    if ([ud objectForKey:KEY_LOSSLESS_ON])   g_losslessPriority = [ud boolForKey:KEY_LOSSLESS_ON];
    if ([ud objectForKey:KEY_DEEP_VP_ON])    g_deepBypassVP     = [ud boolForKey:KEY_DEEP_VP_ON];
    if ([ud objectForKey:KEY_LOWCUT_ON])     g_lowCutEnabled    = [ud boolForKey:KEY_LOWCUT_ON];
    if ([ud objectForKey:KEY_GAIN_VAL])      g_makeupGain       = [ud floatForKey:KEY_GAIN_VAL];
    if ([ud objectForKey:KEY_CEIL_VAL])      g_limiterCeiling   = [ud floatForKey:KEY_CEIL_VAL];
    if ([ud objectForKey:KEY_MIXDSP_ON])     g_mixDspEnabled    = [ud boolForKey:KEY_MIXDSP_ON];
    if ([ud objectForKey:KEY_THROAT_ON])     g_throatEnabled    = [ud boolForKey:KEY_THROAT_ON];
    if ([ud objectForKey:KEY_COMP_ON])       g_compEnabled      = [ud boolForKey:KEY_COMP_ON];
    if ([ud objectForKey:KEY_COMP_THR])      g_compThresh       = [ud floatForKey:KEY_COMP_THR];
    if ([ud objectForKey:KEY_COMP_RATIO])    g_compRatio        = [ud floatForKey:KEY_COMP_RATIO];
    if ([ud objectForKey:KEY_EQ10_ON])       g_eq10Enabled      = [ud boolForKey:KEY_EQ10_ON];
    if ([ud objectForKey:KEY_LIMITER_ON])    g_limiterEnabled   = [ud boolForKey:KEY_LIMITER_ON];
    if ([ud objectForKey:KEY_REVERB_ON])     g_reverbEnabled    = [ud boolForKey:KEY_REVERB_ON];
    if ([ud objectForKey:KEY_REVERB_ROOM])   g_reverbRoom       = [ud floatForKey:KEY_REVERB_ROOM];
    if ([ud objectForKey:KEY_REVERB_WET])    g_reverbWet        = [ud floatForKey:KEY_REVERB_WET];
    if ([ud objectForKey:KEY_BGM_VOL])       g_bgmVolume        = [ud floatForKey:KEY_BGM_VOL];
    if ([ud objectForKey:KEY_SFX_VOL])       g_sfxVolume        = [ud floatForKey:KEY_SFX_VOL];
    if ([ud objectForKey:KEY_BGM_NAME])      g_bgmName          = [ud stringForKey:KEY_BGM_NAME];
    if ([ud objectForKey:KEY_DUCK_ON])       g_duckEnabled      = [ud boolForKey:KEY_DUCK_ON];
    if ([ud objectForKey:KEY_DUCK_FLOOR])    g_bgmDuckFloor     = [ud floatForKey:KEY_DUCK_FLOOR];
    if ([ud objectForKey:KEY_MASTER_LOCK])   g_oneTapMasterLock = [ud boolForKey:KEY_MASTER_LOCK];
    if ([ud objectForKey:KEY_SHIELD_ON])     g_shieldRemote     = [ud boolForKey:KEY_SHIELD_ON];
    if ([ud objectForKey:KEY_SHIELD_LOW])    g_shieldLowOnly    = [ud boolForKey:KEY_SHIELD_LOW];
    if ([ud objectForKey:KEY_PRIORITY_LOUD]) g_priorityLoud     = [ud boolForKey:KEY_PRIORITY_LOUD];
    if ([ud objectForKey:KEY_CLIP_LOOP])     g_clipLoop         = [ud boolForKey:KEY_CLIP_LOOP];
    if ([ud objectForKey:KEY_UNDERSTAGE_ON]) g_understageEnabled = [ud boolForKey:KEY_UNDERSTAGE_ON];
    if ([ud objectForKey:KEY_PK_PROBE_ON])     g_pkProbeEnabled = [ud boolForKey:KEY_PK_PROBE_ON];
    if ([ud objectForKey:KEY_PK_PROBE_ACTIVE]) g_pkProbeActive  = [ud boolForKey:KEY_PK_PROBE_ACTIVE];
    if ([ud objectForKey:KEY_BGM_ONLY])        g_bgmOnly        = [ud boolForKey:KEY_BGM_ONLY];
    if ([ud objectForKey:KEY_SECOND_SSRC])     g_secondSSRC     = [ud boolForKey:KEY_SECOND_SSRC];
    if ([ud objectForKey:KEY_NOISE_GATE_ON]) g_noiseGateEnabled = [ud boolForKey:KEY_NOISE_GATE_ON];

    NSArray *eqArr = [ud arrayForKey:KEY_EQ10_GAINS];
    if (eqArr.count == EQ10_BANDS) {
        for (int i = 0; i < EQ10_BANDS; i++) {
            float g = [eqArr[i] floatValue];
            if (g < -12.0f) g = -12.0f;
            if (g > 12.0f)  g = 12.0f;
            g_eq10Gains[i] = g;
        }
    }

    if (g_makeupGain < 1.0f || g_makeupGain > 10.0f)                g_makeupGain = 1.55f;  // v33：-10.5dB 黄金区默认
    if (g_limiterCeiling < 20000.0f || g_limiterCeiling > 32700.0f) g_limiterCeiling = 29800.0f;
    if (g_compThresh < 0.05f || g_compThresh > 0.80f)               g_compThresh = 0.15f;  // v33 默认门限
    if (g_compRatio < 1.2f || g_compRatio > 10.0f)                  g_compRatio = 3.2f;    // v33 默认压缩比
    if (g_bgmVolume < 0.0f || g_bgmVolume > 2.0f)                   g_bgmVolume = 0.45f;   // v31.1：上限放宽到 200%
    if (g_reverbRoom < 0.0f || g_reverbRoom > 0.95f)                g_reverbRoom = 0.85f;
    if (g_reverbWet < 0.0f || g_reverbWet > 0.80f)                  g_reverbWet = 0.25f;
    if (g_sfxVolume < 0.0f || g_sfxVolume > 1.0f)                   g_sfxVolume = 1.0f;
    if (g_bgmDuckFloor < 0.05f || g_bgmDuckFloor > 0.70f)           g_bgmDuckFloor = 0.22f;

    kp_rebuild_filter_bank();
}

static void save_current_settings(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setBool:g_dspEnabled       forKey:KEY_DSP_ON];
    [ud setBool:g_losslessPriority forKey:KEY_LOSSLESS_ON];
    [ud setBool:g_deepBypassVP     forKey:KEY_DEEP_VP_ON];
    [ud setBool:g_lowCutEnabled    forKey:KEY_LOWCUT_ON];
    [ud setFloat:g_makeupGain      forKey:KEY_GAIN_VAL];
    [ud setFloat:g_limiterCeiling  forKey:KEY_CEIL_VAL];
    [ud setBool:g_mixDspEnabled    forKey:KEY_MIXDSP_ON];
    [ud setBool:g_throatEnabled    forKey:KEY_THROAT_ON];
    [ud setBool:g_compEnabled      forKey:KEY_COMP_ON];
    [ud setFloat:g_compThresh      forKey:KEY_COMP_THR];
    [ud setFloat:g_compRatio       forKey:KEY_COMP_RATIO];
    [ud setBool:g_eq10Enabled      forKey:KEY_EQ10_ON];
    [ud setBool:g_limiterEnabled   forKey:KEY_LIMITER_ON];
    [ud setBool:g_reverbEnabled    forKey:KEY_REVERB_ON];
    [ud setFloat:g_reverbRoom      forKey:KEY_REVERB_ROOM];
    [ud setFloat:g_reverbWet       forKey:KEY_REVERB_WET];
    [ud setFloat:g_bgmVolume       forKey:KEY_BGM_VOL];
    [ud setFloat:g_sfxVolume       forKey:KEY_SFX_VOL];
    [ud setBool:g_duckEnabled      forKey:KEY_DUCK_ON];
    [ud setFloat:g_bgmDuckFloor    forKey:KEY_DUCK_FLOOR];
    [ud setBool:g_oneTapMasterLock forKey:KEY_MASTER_LOCK];
    [ud setBool:g_shieldRemote     forKey:KEY_SHIELD_ON];
    [ud setBool:g_shieldLowOnly    forKey:KEY_SHIELD_LOW];
    [ud setBool:g_priorityLoud     forKey:KEY_PRIORITY_LOUD];
    [ud setBool:g_clipLoop         forKey:KEY_CLIP_LOOP];
    [ud setBool:g_understageEnabled forKey:KEY_UNDERSTAGE_ON];
    [ud setBool:g_noiseGateEnabled forKey:KEY_NOISE_GATE_ON];
    [ud setBool:g_pkProbeEnabled   forKey:KEY_PK_PROBE_ON];
    [ud setBool:g_pkProbeActive    forKey:KEY_PK_PROBE_ACTIVE];
    [ud setBool:g_bgmOnly          forKey:KEY_BGM_ONLY];
    [ud setBool:g_secondSSRC       forKey:KEY_SECOND_SSRC];

    NSMutableArray *eqArr = [NSMutableArray arrayWithCapacity:EQ10_BANDS];
    for (int i = 0; i < EQ10_BANDS; i++) {
        [eqArr addObject:@((float)g_eq10Gains[i])];
    }
    [ud setObject:eqArr forKey:KEY_EQ10_GAINS];
}

// ==========================================
// 2. Freeverb 混响（可选效果）
// ==========================================
#define COMB_N   8
#define AP_N     4
#define COMB_BUF 2048
#define AP_BUF   1024

static const int kCombTune[COMB_N] = {1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617};
static const int kApTune[AP_N]     = {556, 441, 341, 225};

typedef struct {
    float buf[COMB_BUF];
    int   size;
    int   idx;
    float store;
} KPComb;

typedef struct {
    float buf[AP_BUF];
    int   size;
    int   idx;
} KPAllpass;

typedef struct {
    KPComb    comb[COMB_N];
    KPAllpass ap[AP_N];
} KPReverb;

static KPReverb g_reverb[REVERB_CH];

static void kp_reverb_reset(void) {
    memset(g_reverb, 0, sizeof(g_reverb));
    for (int c = 0; c < REVERB_CH; c++) {
        for (int i = 0; i < COMB_N; i++) {
            g_reverb[c].comb[i].size = kCombTune[i];
        }
        for (int i = 0; i < AP_N; i++) {
            g_reverb[c].ap[i].size = kApTune[i];
        }
    }
}

static inline float kp_reverb_tick(float in, UInt32 ch) {
    KPReverb *rv = &g_reverb[ch < REVERB_CH ? ch : 0];
    float room = g_reverbRoom;
    const float damp = 0.28f;
    float sum = 0.0f;

    for (int i = 0; i < COMB_N; i++) {
        KPComb *cf = &rv->comb[i];
        float out = cf->buf[cf->idx];
        cf->store = out * (1.0f - damp) + cf->store * damp;
        cf->buf[cf->idx] = in + cf->store * room;
        if (++cf->idx >= cf->size) cf->idx = 0;
        sum += out;
    }
    sum *= 0.125f;

    for (int i = 0; i < AP_N; i++) {
        KPAllpass *af = &rv->ap[i];
        float bufOut = af->buf[af->idx];
        float out = bufOut - sum;
        af->buf[af->idx] = sum + bufOut * 0.5f;
        if (++af->idx >= af->size) af->idx = 0;
        sum = out;
    }
    return sum;
}

// ==========================================
// 3. 精简人声 DSP（双缓冲无锁系数 + 高穿透提亮 + 10段 EQ + 稳健压缩 + 前瞻限幅）
// ==========================================
typedef struct {
    float b0, b1, b2, a1, a2;
} KPBiquadCoef;

typedef struct {
    float z1, z2;
} KPBiquadState;

typedef struct {
    KPBiquadCoef throat[2];
    KPBiquadCoef eq10[EQ10_BANDS];
} KPFilterBank;

static KPFilterBank  g_filterBanks[2];
static _Atomic int   g_activeBank = 0;
static KPBiquadState g_throatSt[MAX_CHANNELS][2];
static KPBiquadState g_eq10St[MAX_CHANNELS][EQ10_BANDS];

static inline float kp_biquad_run(float x, const KPBiquadCoef *c, KPBiquadState *s) {
    float y = c->b0 * x + s->z1;
    s->z1 = c->b1 * x - c->a1 * y + s->z2;
    s->z2 = c->b2 * x - c->a2 * y;
    return y;
}

static void kp_rbj_peaking(KPBiquadCoef *c, float fs, float f0, float Q, float dB) {
    if (fabsf(dB) < 0.05f || f0 >= fs * 0.48f) {
        c->b0 = 1.0f; c->b1 = 0.0f; c->b2 = 0.0f; c->a1 = 0.0f; c->a2 = 0.0f;
        return;
    }
    float A = powf(10.0f, dB / 40.0f);
    float w0 = 2.0f * (float)M_PI * f0 / fs;
    float cosw = cosf(w0);
    float alpha = sinf(w0) / (2.0f * Q);
    float a0 = 1.0f + alpha / A;
    c->b0 = (1.0f + alpha * A) / a0;
    c->b1 = (-2.0f * cosw) / a0;
    c->b2 = (1.0f - alpha * A) / a0;
    c->a1 = (-2.0f * cosw) / a0;
    c->a2 = (1.0f - alpha / A) / a0;
}

static void kp_rebuild_filter_bank(void) {
    float fs = g_sampleRate;
    if (fs < 8000.0f || fs > 96000.0f) fs = 48000.0f;
    int next = 1 - g_activeBank;
    KPFilterBank *B = &g_filterBanks[next];

    // v31.8：中高频频段区隔——2850Hz 存在感 + 4200Hz 字头锐度，多人混音里把每个字“切”出来
    if (g_priorityLoud) {
        // 120Hz 以下彻底切干净（不跟男声低频泥潭抢能量）
        // 2850Hz (+5.5dB) 提升人声存在感，4200Hz (+3.5dB) 提升辅音字头锐度
        kp_rbj_peaking(&B->throat[0], fs, 2850.0f, 1.25f, 5.5f);
        kp_rbj_peaking(&B->throat[1], fs, 4200.0f, 1.40f, 3.5f);
    } else {
        kp_rbj_peaking(&B->throat[0], fs, 2800.0f, 1.20f, 3.0f);
        kp_rbj_peaking(&B->throat[1], fs, 220.0f,  1.20f, 1.0f);
    }

    for (int i = 0; i < EQ10_BANDS; i++) {
        float q = (i == 0 || i == EQ10_BANDS - 1) ? 0.9f : 1.35f;
        kp_rbj_peaking(&B->eq10[i], fs, kEq10Freqs[i], q, g_eq10Gains[i]);
    }

    // 120Hz 高通：去掉糊成一团的低频，把动态余量全留给中频
    float fc = g_priorityLoud ? 120.0f : 90.0f;
    g_hpfAlpha = expf(-2.0f * (float)M_PI * fc / fs);

    // 报告 10 节压缩时间常数：Attack 5ms / Release 150ms
    g_compAtkCoef = 1.0f - expf(-1.0f / (fs * 0.016f)); // v33 慢启动：放过字头 16ms 瞬态爆发力
    g_compRelCoef = 1.0f - expf(-1.0f / (fs * 0.140f)); // v33：Release 140ms 托住句尾
    g_gateAtkCoef = 1.0f - expf(-1.0f / (fs * 0.002f)); // v33 噪声门：2ms 快开
    g_gateRelCoef = 1.0f - expf(-1.0f / (fs * 0.120f)); // v33 噪声门：120ms 平滑关

    g_activeBank = next;
}

static void kp_eq_init(void) {
    memset(g_throatSt, 0, sizeof(g_throatSt));
    memset(g_gateEnv, 0, sizeof(g_gateEnv));
    memset(g_eq10St, 0, sizeof(g_eq10St));
    kp_rebuild_filter_bank();
    kp_rebuild_filter_bank();
}

// 稳健双向压缩：放过微弱底噪不发糊，适度提拉中段人声，超阈值平稳压限
static inline float kp_comp_sample(float xn, UInt32 ch) {
    float absx = fabsf(xn);
    float coef = (absx > g_compEnv[ch]) ? g_compAtkCoef : g_compRelCoef;
    g_compEnv[ch] += (absx - g_compEnv[ch]) * coef;
    float env = g_compEnv[ch];

    float upGain = 1.0f;
    float thr = g_compThresh;
    if (absx < 0.55f && env > 0.045f && env < thr && thr > 0.001f) {
        float maxUp = g_priorityLoud ? 1.85f : 1.50f;
        float base = powf(thr / env, 0.45f);
        if (base > maxUp) base = maxUp;
        float ramp = (env - 0.045f) / 0.035f;
        if (ramp < 0.0f) ramp = 0.0f;
        if (ramp > 1.0f) ramp = 1.0f;
        upGain = 1.0f + (base - 1.0f) * ramp;
    }

    float downGain = 1.0f;
    if (env > thr && thr > 0.001f) {
        float overDb = 20.0f * log10f(env / thr);
        float redDb  = overDb * (1.0f - 1.0f / g_compRatio);
        downGain = powf(10.0f, -redDb / 20.0f);
        float grPct = (1.0f - downGain) * 140.0f;
        if (grPct > g_grCompPeak) g_grCompPeak = grPct;
    }
    return xn * upGain * downGain;
}

// 前瞻限幅器：防爆音与硬削波方波
typedef struct {
    float buf[KP_LOOK];
    int   idx;
    float gr;
    float hold;
} KPLim;
static KPLim g_lim[MAX_CHANNELS];

static void kp_lim_reset(void) {
    memset(g_lim, 0, sizeof(g_lim));
    for (int i = 0; i < MAX_CHANNELS; i++) g_lim[i].gr = 1.0f;
}

static inline float kp_limiter_tick(float x, UInt32 ch, float ceilNorm) {
    KPLim *L = &g_lim[ch];
    float delayed = L->buf[L->idx];
    L->buf[L->idx] = x;
    L->idx = (L->idx + 1) % KP_LOOK;

    float ax = fabsf(x);
    if (ax > L->hold) L->hold = ax;
    else              L->hold += (ax - L->hold) * 0.0008f;

    float targetGr = (L->hold > ceilNorm && L->hold > 1e-6f) ? (ceilNorm / L->hold) : 1.0f;
    if (targetGr < L->gr) L->gr += (targetGr - L->gr) * 0.35f;
    else                  L->gr += (targetGr - L->gr) * 0.001f;

    float grPct = (1.0f - L->gr) * 140.0f;
    if (grPct > g_grLimPeak) g_grLimPeak = grPct;

    float out = delayed * L->gr;
    if (out > ceilNorm)  out = ceilNorm;
    if (out < -ceilNorm) out = -ceilNorm;
    return out;
}

static inline float kp_voice_pre_sample(float inSample, UInt32 ch, const KPFilterBank *bank) {
    float y = inSample;
    if (g_lowCutEnabled) {
        float fy = y - g_dc_x1[ch] + g_hpfAlpha * g_dc_y1[ch];
        g_dc_x1[ch] = y;
        g_dc_y1[ch] = fy;
        y = fy;
    }

    float xn = y * (1.0f / 32768.0f);
    // v33 智能平滑噪声门：不说话时衰减至 2%（-34dB），把码率和动态全留给开口瞬间
    if (g_noiseGateEnabled) {
        float absX = fabsf(xn);
        float tgt  = (absX >= g_gateThresh) ? 1.0f : 0.02f;
        float gc   = (tgt > g_gateEnv[ch]) ? g_gateAtkCoef : g_gateRelCoef;
        g_gateEnv[ch] += (tgt - g_gateEnv[ch]) * gc;
        xn *= g_gateEnv[ch];
    }
    if (g_throatEnabled) {
        xn = kp_biquad_run(xn, &bank->throat[0], &g_throatSt[ch][0]);
        xn = kp_biquad_run(xn, &bank->throat[1], &g_throatSt[ch][1]);
    }
    if (g_eq10Enabled) {
        for (int b = 0; b < EQ10_BANDS; b++) {
            xn = kp_biquad_run(xn, &bank->eq10[b], &g_eq10St[ch][b]);
        }
    }
    if (g_compEnabled) {
        xn = kp_comp_sample(xn, ch);
    }
    return xn * 32768.0f;
}

// ==========================================
// 4. 音效 / BGM / 话术播放器（无锁读取 + 缓冲延迟回收）
// ==========================================
typedef struct {
    int16_t *pcm;
    UInt32   len;
} KPAudioClip;

static KPAudioClip g_sfxClip[SFX_SLOT];
static _Atomic int g_sfxPos[SFX_SLOT];
static _Atomic int g_sfxOn[SFX_SLOT];

static int16_t    *g_bgmPcm = NULL;
static _Atomic int g_bgmLen = 0;
static _Atomic int g_bgmPos = 0;
static _Atomic int g_bgmOn  = 0;

static int16_t *g_bgmRetired[BGM_RETIRE];
static int      g_bgmRetiredSlot = 0;

static void kp_bgm_retire(int16_t *old) {
    if (!old) return;
    if (g_bgmRetired[g_bgmRetiredSlot]) free(g_bgmRetired[g_bgmRetiredSlot]);
    g_bgmRetired[g_bgmRetiredSlot] = old;
    g_bgmRetiredSlot = (g_bgmRetiredSlot + 1) % BGM_RETIRE;
}

static void kp_play_sfx(int index) {
    if (index < 0 || index >= SFX_SLOT) return;
    if (!g_sfxClip[index].pcm) return;
    g_sfxPos[index] = 0;
    g_sfxOn[index]  = 1;
}

static int16_t *kp_load_audio(NSString *path, UInt32 *outCount) {
    if (!path || ![path length]) return NULL;
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return NULL;

    ExtAudioFileRef f = NULL;
    if (ExtAudioFileOpenURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], &f) != noErr || !f) return NULL;

    AudioStreamBasicDescription fileFmt;
    UInt32 sz = sizeof(fileFmt);
    if (ExtAudioFileGetProperty(f, kExtAudioFileProperty_FileDataFormat, &sz, &fileFmt) != noErr || fileFmt.mSampleRate <= 0) {
        ExtAudioFileDispose(f);
        return NULL;
    }

    SInt64 fileFrames = 0;
    sz = sizeof(fileFrames);
    ExtAudioFileGetProperty(f, kExtAudioFileProperty_FileLengthFrames, &sz, &fileFrames);

    double ratio = 48000.0 / fileFmt.mSampleRate;
    SInt64 destFrames = (SInt64)((double)fileFrames * ratio) + 48000;
    if (destFrames < 48000) destFrames = 48000;
    if (destFrames > AUDIO_MAX_FRAMES) destFrames = AUDIO_MAX_FRAMES;

    AudioStreamBasicDescription client;
    memset(&client, 0, sizeof(client));
    client.mFormatID         = kAudioFormatLinearPCM;
    client.mSampleRate       = 48000.0;
    client.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    client.mBitsPerChannel   = 16;
    client.mChannelsPerFrame = 1;
    client.mFramesPerPacket  = 1;
    client.mBytesPerFrame    = 2;
    client.mBytesPerPacket   = 2;

    if (ExtAudioFileSetProperty(f, kExtAudioFileProperty_ClientDataFormat, sizeof(client), &client) != noErr) {
        ExtAudioFileDispose(f);
        return NULL;
    }

    int16_t *buf = (int16_t *)calloc((size_t)destFrames, sizeof(int16_t));
    if (!buf) { ExtAudioFileDispose(f); return NULL; }

    UInt32 written = 0;
    while (written < (UInt32)destFrames) {
        UInt32 want = 2048;
        if (want > (UInt32)destFrames - written) want = (UInt32)destFrames - written;

        AudioBufferList abl;
        abl.mNumberBuffers = 1;
        abl.mBuffers[0].mNumberChannels = 1;
        abl.mBuffers[0].mDataByteSize   = want * 2;
        abl.mBuffers[0].mData           = buf + written;

        UInt32 got = want;
        if (ExtAudioFileRead(f, &got, &abl) != noErr || got == 0) break;
        written += got;
    }
    ExtAudioFileDispose(f);

    if (written == 0) { free(buf); return NULL; }
    if (outCount) *outCount = written;
    return buf;
}

static int16_t *kp_synth_sfx(int type, UInt32 *outCount) {
    UInt32 n = 48000;
    int16_t *buf = (int16_t *)calloc(n, sizeof(int16_t));
    if (!buf) return NULL;

    unsigned int seed = (unsigned int)(type * 7919 + 12345);
    for (UInt32 i = 0; i < n; i++) {
        float t = (float)i / 48000.0f;
        float s = 0.0f;
        if (type == 0) {
            seed = seed * 1103515245u + 12345u;
            float nz = ((float)((seed >> 16) & 0x7FFF) / 16384.0f) - 1.0f;
            float burst = 0.55f + 0.45f * sinf(2.0f * (float)M_PI * 11.0f * t);
            s = nz * burst * expf(-t * 2.6f) * 0.55f;
        } else if (type == 1) {
            float freq = 320.0f + 120.0f * sinf(2.0f * (float)M_PI * 5.5f * t);
            s = sinf(2.0f * (float)M_PI * freq * t) * (0.5f + 0.5f * sinf(2.0f * (float)M_PI * 2.2f * t)) * expf(-t * 1.6f) * 0.6f;
        } else if (type == 2) {
            float a = sinf(2.0f * (float)M_PI * 523.25f * t);
            float b = sinf(2.0f * (float)M_PI * 659.25f * t);
            float c = sinf(2.0f * (float)M_PI * 783.99f * t);
            s = (a + b + c) / 3.0f * (0.6f + 0.4f * sinf(2.0f * (float)M_PI * 3.0f * t)) * expf(-t * 1.2f) * 0.65f;
        } else {
            float f0 = 1800.0f - 1100.0f * t;
            s = sinf(2.0f * (float)M_PI * f0 * t) * expf(-t * 3.5f) * 0.5f;
        }
        if (s > 1.0f) s = 1.0f;
        if (s < -1.0f) s = -1.0f;
        buf[i] = (int16_t)(s * 26000.0f);
    }
    if (outCount) *outCount = n;
    return buf;
}

static NSString *kp_documents_path(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static NSString *kp_sfx_dir(void) {
    return [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/SFX"];
}

static void kp_load_sfx_library(void) {
    NSString *dir = kp_sfx_dir();
    for (int i = 0; i < SFX_SLOT; i++) {
        UInt32 n = 0;
        int16_t *buf = NULL;
        NSString *base = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"sfx_%d", i]];
        for (NSString *ext in @[@"mp3", @"m4a", @"wav", @"caf"]) {
            NSString *p = [base stringByAppendingPathExtension:ext];
            if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
                buf = kp_load_audio(p, &n);
                if (buf) break;
            }
        }
        if (!buf) buf = kp_synth_sfx(i, &n);
        g_sfxClip[i].pcm = buf;
        g_sfxClip[i].len = n;
        g_sfxPos[i] = 0;
        g_sfxOn[i] = 0;
    }
}

static BOOL kp_reset_sfx_slot(int idx) {
    if (idx < 0 || idx >= SFX_SLOT) return NO;
    g_sfxOn[idx] = 0;
    g_sfxPos[idx] = 0;

    BOOL removed = NO;
    NSString *base = [kp_sfx_dir() stringByAppendingPathComponent:[NSString stringWithFormat:@"sfx_%d", idx]];
    for (NSString *ext in @[@"mp3", @"m4a", @"wav", @"caf"]) {
        NSString *p = [base stringByAppendingPathExtension:ext];
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            if ([[NSFileManager defaultManager] removeItemAtPath:p error:nil]) removed = YES;
        }
    }

    UInt32 n = 0;
    int16_t *fresh = kp_synth_sfx(idx, &n);
    int16_t *old = g_sfxClip[idx].pcm;
    g_sfxClip[idx].pcm = fresh;
    g_sfxClip[idx].len = n;

    if (old) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ free(old); });
    }
    return removed;
}

static void kp_delete_bgm(void) {
    g_bgmOn = 0;
    g_bgmPos = 0;
    int16_t *old = g_bgmPcm;
    g_bgmPcm = NULL;
    g_bgmLen = 0;
    kp_bgm_retire(old);
    g_bgmName = nil;
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:KEY_BGM_NAME];
}

// 话术板录制 / 播放 / 删除
static int16_t    *g_clipPcm = NULL;
static _Atomic int g_clipLen = 0;
static _Atomic int g_clipPos = 0;
static _Atomic int g_clipOn  = 0;
static int         g_clipPlayingSlot = -1;

static _Atomic int    g_recOn    = 0;
static _Atomic int    g_recCount = 0;
static int16_t       *g_recBuf   = NULL;
static int            g_recSlot  = 0;
static int16_t       *g_recRetired[REC_RETIRE];
static int            g_recRetiredSlot = 0;

static NSString *kp_clip_dir(void) {
    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/VoiceBank"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSString *kp_clip_path(int slot) {
    return [kp_clip_dir() stringByAppendingPathComponent:[NSString stringWithFormat:@"clip_%d.wav", slot]];
}

static BOOL kp_clip_exists(int slot) {
    return [[NSFileManager defaultManager] fileExistsAtPath:kp_clip_path(slot)];
}

static BOOL kp_write_wav(NSString *path, const int16_t *pcm, UInt32 count) {
    if (!path.length || !pcm || count == 0) return NO;
    FILE *f = fopen(path.UTF8String, "wb");
    if (!f) return NO;

    uint32_t dataSize = count * 2;
    uint32_t riffSize = 36 + dataSize;
    uint32_t rate     = 48000;
    uint32_t byteRate = rate * 2;
    uint16_t align    = 2;
    uint16_t bits     = 16;
    uint16_t chans    = 1;
    uint16_t fmt      = 1;
    uint32_t fmtSize  = 16;

    fwrite("RIFF", 1, 4, f);
    fwrite(&riffSize, 4, 1, f);
    fwrite("WAVEfmt ", 1, 8, f);
    fwrite(&fmtSize, 4, 1, f);
    fwrite(&fmt, 2, 1, f);
    fwrite(&chans, 2, 1, f);
    fwrite(&rate, 4, 1, f);
    fwrite(&byteRate, 4, 1, f);
    fwrite(&align, 2, 1, f);
    fwrite(&bits, 2, 1, f);
    fwrite("data", 1, 4, f);
    fwrite(&dataSize, 4, 1, f);
    size_t w = fwrite(pcm, 2, count, f);
    fclose(f);
    return w == (size_t)count;
}

static void kp_rec_start(int slot) {
    if (g_recOn) return;
    if (slot < 0 || slot >= CLIP_SLOT) slot = 0;
    int16_t *buf = (int16_t *)calloc((size_t)CLIP_MAX_SAMPLES, sizeof(int16_t));
    if (!buf) return;
    g_recBuf = buf;
    g_recCount = 0;
    g_recSlot = slot;
    g_recOn = 1;
}

static void kp_normalize_clip(int16_t *buf, int cnt) {
    if (!buf || cnt <= 0) return;
    float peak = 0.0f;
    for (int i = 0; i < cnt; i++) {
        float v = fabsf((float)buf[i]);
        if (v > peak) peak = v;
    }
    if (peak < 300.0f) return;
    float gain = 30500.0f / peak;
    if (gain > 6.0f) gain = 6.0f;
    for (int i = 0; i < cnt; i++) {
        float v = (float)buf[i] * gain;
        if (v > 32767.0f) v = 32767.0f;
        if (v < -32768.0f) v = -32768.0f;
        buf[i] = (int16_t)v;
    }
}

static BOOL kp_rec_stop(void) {
    if (!g_recOn) return NO;
    g_recOn = 0;
    int cnt = g_recCount;
    int16_t *buf = g_recBuf;
    g_recBuf = NULL;
    g_recCount = 0;

    BOOL ok = NO;
    if (buf && cnt > 4800) {
        kp_normalize_clip(buf, cnt);
        ok = kp_write_wav(kp_clip_path(g_recSlot), buf, (UInt32)cnt);
    }
    if (buf) {
        if (g_recRetired[g_recRetiredSlot]) free(g_recRetired[g_recRetiredSlot]);
        g_recRetired[g_recRetiredSlot] = buf;
        g_recRetiredSlot = (g_recRetiredSlot + 1) % REC_RETIRE;
    }
    return ok;
}

static void kp_clip_stop(void) {
    g_clipOn = 0;
    g_clipPos = 0;
    g_clipPlayingSlot = -1;
}

static void kp_clip_play(int slot) {
    if (slot < 0 || slot >= CLIP_SLOT) return;
    if (g_clipOn && g_clipPlayingSlot == slot) {
        kp_clip_stop();
        return;
    }
    if (!kp_clip_exists(slot)) return;

    NSString *path = kp_clip_path(slot);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        UInt32 n = 0;
        int16_t *buf = kp_load_audio(path, &n);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!buf || n == 0) return;
            g_clipOn = 0;
            int16_t *old = g_clipPcm;
            g_clipPcm = buf;
            g_clipLen = (int)n;
            g_clipPos = 0;
            g_clipPlayingSlot = slot;
            kp_bgm_retire(old);
            g_clipOn = 1;
        });
    });
}

static void kp_clip_delete(int slot) {
    if (g_clipPlayingSlot == slot) kp_clip_stop();
    [[NSFileManager defaultManager] removeItemAtPath:kp_clip_path(slot) error:nil];
}

// ==========================================
// 5. 诊断探针
// ==========================================
static double g_probeLast    = 0;
static long   g_probeCalls   = 0;
static long   g_probeFrames  = 0;
static int    g_probeInPeak  = 0;
static int    g_probeOutPeak = 0;
static double g_probeSumSq   = 0;
static long   g_probeSamples = 0;
static int    g_probeCh      = 0;

static void kp_probe_flush(void) {
    double now = CACurrentMediaTime();
    if (g_probeLast == 0.0) { g_probeLast = now; return; }
    if (now - g_probeLast < 5.0) return;
    double rms = (g_probeSamples > 0) ? sqrt(g_probeSumSq / (double)g_probeSamples) : 0.0;
    double db  = 20.0 * log10(rms > 1e-9 ? rms : 1e-9);
    kp_log(@"probe: calls=%ld frames=%ld ch=%d inPeak=%d%% outPeak=%d%% outRMS=%.1fdB",
           g_probeCalls, g_probeFrames, g_probeCh, g_probeInPeak, g_probeOutPeak, db);
    g_probeLast = now;
    g_probeCalls = 0; g_probeFrames = 0; g_probeCh = 0;
    g_probeInPeak = 0; g_probeOutPeak = 0;
    g_probeSumSq = 0; g_probeSamples = 0;
}

static void kp_probe_tick(const int16_t *pcm, UInt32 frames, UInt32 chs, BOOL primary) {
    kp_probe_flush();
    if (!primary) return;
    g_probeCalls++;
    g_probeFrames += frames;
    g_probeCh = (int)chs;
    UInt32 n = frames * chs;
    for (UInt32 i = 0; i < n; i++) {
        int a = pcm[i] < 0 ? -(int)pcm[i] : (int)pcm[i];
        int pct = a * 100 / 32768;
        if (pct > g_probeInPeak) g_probeInPeak = pct;
    }
}

static void kp_probe_out(const int16_t *pcm, UInt32 frames, UInt32 chs, BOOL primary) {
    if (!primary) return;
    UInt32 n = frames * chs;
    for (UInt32 i = 0; i < n; i++) {
        int a = pcm[i] < 0 ? -(int)pcm[i] : (int)pcm[i];
        int pct = a * 100 / 32768;
        if (pct > g_probeOutPeak) g_probeOutPeak = pct;
        double v = (double)pcm[i] * (1.0 / 32768.0);
        g_probeSumSq += v * v;
    }
    g_probeSamples += n;
}

// ==========================================
// 6. 授权与设备标识模块（保留原校验体系）
// ==========================================
static NSString *const KP_PRODUCT_ID = @"KAKA_VOICE";
static const uint8_t KP_PUBKEY_OBF[32] = {
    0x19, 0x23, 0x01, 0xCD, 0xBA, 0xDB, 0xA3, 0x02,
    0x4A, 0xC8, 0x08, 0x6E, 0x78, 0x2E, 0xF3, 0x7F,
    0x35, 0xBC, 0x7A, 0xF1, 0x8A, 0xD7, 0x0E, 0xD3,
    0x09, 0xDA, 0xED, 0x82, 0xF5, 0x75, 0x78, 0xF2
};
static const uint8_t KP_PUBKEY_XOR = 0x5A;
#define KP_DSP_TOKEN 0x5A5AA5A5u

#pragma pack(push, 1)
typedef struct {
    float    preamp;
    float    drive;
    float    ceiling;
    float    mix;
    uint32_t clientId;
    uint32_t token;
    uint32_t check;
    uint32_t reserved;
} KPDspParams;
#pragma pack(pop)

static KPDspParams g_dspParams = { 0 };
static _Atomic BOOL g_licOk = NO;
static NSString *g_licExpireStr = @"未授权";
static NSString *g_licReason   = @"未激活";

#define KP_LIC_CODE_NAME @"lic.code"
#define KP_LIC_TS_NAME   @"lic.ts"
static NSString *const KP_KC_SERVICE = @"com.kaka.voice.lic.v28";
static NSString *const KP_KC_SEED    = @"dev_seed";
static NSString *const KP_KC_TIME    = @"time_wm";
static NSString *const KP_KC_NET     = @"net_sync";

static uint32_t kp_fnv1a(const uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static NSData *kp_kc_get(NSString *acct) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KP_KC_SERVICE,
        (__bridge id)kSecAttrAccount: acct,
        (__bridge id)kSecReturnData:  @YES
    };
    CFTypeRef out = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) == errSecSuccess) {
        return (__bridge_transfer NSData *)out;
    }
    return nil;
}

static BOOL kp_kc_set(NSString *acct, NSData *data) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KP_KC_SERVICE,
        (__bridge id)kSecAttrAccount: acct
    };
    SecItemDelete((__bridge CFDictionaryRef)q);
    NSMutableDictionary *add = [q mutableCopy];
    add[(__bridge id)kSecValueData]     = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    return SecItemAdd((__bridge CFDictionaryRef)add, NULL) == errSecSuccess;
}

static long long kp_kc_get_ll(NSString *acct) {
    NSData *d = kp_kc_get(acct);
    long long v = 0;
    if (d.length == sizeof(v)) [d getBytes:&v length:sizeof(v)];
    return v;
}

static void kp_kc_set_ll(NSString *acct, long long v) {
    kp_kc_set(acct, [NSData dataWithBytes:&v length:sizeof(v)]);
}

static NSString *kp_lic_dir(void) {
    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSString *kp_lic_idfv_raw(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
    NSString *s = [[[idfv stringByReplacingOccurrencesOfString:@"-" withString:@""]
                    stringByReplacingOccurrencesOfString:@" " withString:@""] uppercaseString];
    if (s.length < 16) return @"0000000000000000";
    return [s substringToIndex:16];
}

static NSString *kp_lic_dev_raw(void) {
    static NSString *cached = nil;
    if (cached) return cached;

    NSData *seed = kp_kc_get(KP_KC_SEED);
    if (seed.length != 32) {
        uint8_t r[32];
        if (SecRandomCopyBytes(kSecRandomDefault, 32, r) == errSecSuccess) {
            NSData *d = [NSData dataWithBytes:r length:32];
            if (kp_kc_set(KP_KC_SEED, d)) seed = d;
        }
    }
    if (seed.length == 32) {
        uint8_t dg[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(seed.bytes, (CC_LONG)seed.length, dg);
        char hex[17];
        for (int i = 0; i < 8; i++) sprintf(hex + i * 2, "%02X", dg[i]);
        hex[16] = '\0';
        cached = [NSString stringWithUTF8String:hex];
    } else {
        cached = kp_lic_idfv_raw();
    }
    return cached;
}

static NSString *kp_lic_dev_disp(void) {
    NSString *r = kp_lic_dev_raw();
    return [NSString stringWithFormat:@"%@-%@-%@-%@",
            [r substringWithRange:NSMakeRange(0, 4)],
            [r substringWithRange:NSMakeRange(4, 4)],
            [r substringWithRange:NSMakeRange(8, 4)],
            [r substringWithRange:NSMakeRange(12, 4)]];
}

static NSString *kp_lic_norm(NSString *s) {
    if (!s) return @"";
    NSString *t = [s stringByReplacingOccurrencesOfString:@"-" withString:@""];
    t = [t stringByReplacingOccurrencesOfString:@" " withString:@""];
    t = [t stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    return [t uppercaseString];
}

static long long kp_lic_last_ts(void) {
    long long a = kp_kc_get_ll(KP_KC_TIME);
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_TS_NAME];
    long long b = [[NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil] longLongValue];
    long long c = (long long)[[NSUserDefaults standardUserDefaults] doubleForKey:@"kaka_lic_ts"];
    long long m = (a > b) ? a : b;
    return (m > c) ? m : c;
}

static void kp_lic_force_ts(long long ts) {
    if (ts <= 0) return;
    kp_kc_set_ll(KP_KC_TIME, ts);
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_TS_NAME];
    [[NSString stringWithFormat:@"%lld", ts] writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[NSUserDefaults standardUserDefaults] setDouble:(double)ts forKey:@"kaka_lic_ts"];
}

static void kp_lic_save_ts(long long ts, BOOL trusted) {
    if (ts <= 0) return;
    if (trusted) { kp_lic_force_ts(ts); return; }
    long long last = kp_lic_last_ts();
    long long v = ts;
    if (last > 0 && ts > last + 86400LL) v = last + 86400LL;
    if (v <= last) return;
    kp_lic_force_ts(v);
}

static long long kp_lic_fetch_net_time(void) {
    NSArray *urls = @[@"https://captive.apple.com/hotspot-detect.html",
                      @"https://www.apple.com/library/test/success.html"];
    for (NSString *u in urls) {
        __block long long got = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:u]
                                                         cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                     timeoutInterval:2.5];
        req.HTTPMethod = @"HEAD";
        [[[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *resp, NSError *err) {
                if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                    NSString *ds = ((NSHTTPURLResponse *)resp).allHeaderFields[@"Date"];
                    if (ds) {
                        NSDateFormatter *df = [[NSDateFormatter alloc] init];
                        df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
                        df.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss zzz";
                        NSDate *nd = [df dateFromString:ds];
                        if (nd) got = (long long)[nd timeIntervalSince1970];
                    }
                }
                dispatch_semaphore_signal(sem);
        }] resume];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
        if (got > 1704067200LL) return got;
    }
    return 0;
}

static void kp_lic_net_sync(void) {
    long long lastSync = kp_kc_get_ll(KP_KC_NET);
    long long now = (long long)[[NSDate date] timeIntervalSince1970];
    if (lastSync > 0 && now >= lastSync && now - lastSync < 6 * 3600LL) return;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://captive.apple.com/hotspot-detect.html"]
                                                     cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                 timeoutInterval:4.0];
    req.HTTPMethod = @"HEAD";
    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *resp, NSError *err) {
            if (![resp isKindOfClass:[NSHTTPURLResponse class]]) return;
            NSString *ds = ((NSHTTPURLResponse *)resp).allHeaderFields[@"Date"];
            if (!ds) return;
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
            df.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss zzz";
            NSDate *nd = [df dateFromString:ds];
            if (!nd) return;
            long long netTS = (long long)[nd timeIntervalSince1970];
            if (netTS < 1704067200LL) return;
            kp_lic_save_ts(netTS, YES);
            kp_kc_set_ll(KP_KC_NET, netTS);
    }] resume];
}

static BOOL kp_lic_env_safe(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && (strstr(nm, "FridaGadget") || strstr(nm, "frida-agent"))) return NO;
    }
    return YES;
}

static NSString *kp_lic_stored_code(void) {
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_CODE_NAME];
    NSString *s = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    return s.length ? s : [[NSUserDefaults standardUserDefaults] stringForKey:@"kaka_lic_code"];
}

static void kp_lic_store_code(NSString *code) {
    NSString *p = [kp_lic_dir() stringByAppendingPathComponent:KP_LIC_CODE_NAME];
    [code writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[NSUserDefaults standardUserDefaults] setObject:code forKey:@"kaka_lic_code"];
}

static void kp_dsp_inject(NSString *entropyHex, NSString *encB64) {
    memset(&g_dspParams, 0, sizeof(g_dspParams));
    if (entropyHex.length != 16) return;
    NSData *enc = [[NSData alloc] initWithBase64EncodedString:encB64 options:0];
    if (enc.length != sizeof(KPDspParams)) return;

    uint8_t key[16];
    memcpy(key, entropyHex.UTF8String, 16);
    uint8_t plain[32];
    kpa_decrypt_ecb(key, enc.bytes, plain, 32);

    KPDspParams tmp;
    memcpy(&tmp, plain, sizeof(KPDspParams));
    if (tmp.token != KP_DSP_TOKEN || tmp.check != kp_fnv1a(plain, 24)) return;
    g_dspParams = tmp;
}

static NSString *kp_lic_clean(NSString *code) {
    if (!code) return @"";
    NSMutableString *m = [NSMutableString stringWithCapacity:code.length];
    for (NSUInteger i = 0; i < code.length; i++) {
        unichar ch = [code characterAtIndex:i];
        if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == 0x3000) continue;
        [m appendFormat:@"%C", ch];
    }
    return m;
}

static BOOL kp_lic_verify(NSString *code) {
    g_licOk = NO;
    g_licReason = @"未激活";
    memset(&g_dspParams, 0, sizeof(g_dspParams));

    if (!kp_lic_env_safe()) { g_licReason = @"运行环境异常"; return NO; }
    kp_lic_net_sync();

    NSString *c = kp_lic_clean(code);
    NSArray *parts = [c componentsSeparatedByString:@"."];
    if (c.length < 40 || parts.count != 2) { g_licReason = @"授权码格式错误"; return NO; }

    NSData *sigData = [[NSData alloc] initWithBase64EncodedString:parts[1] options:0];
    NSData *msgData = [parts[0] dataUsingEncoding:NSUTF8StringEncoding];
    if (sigData.length != 64 || msgData.length == 0) { g_licReason = @"签名或载荷异常"; return NO; }

    uint8_t pk[32];
    for (int i = 0; i < 32; i++) pk[i] = KP_PUBKEY_OBF[i] ^ KP_PUBKEY_XOR;

    size_t smLen = 64 + msgData.length;
    uint8_t *sm = (uint8_t *)malloc(smLen);
    uint8_t *mo = (uint8_t *)malloc(smLen);
    if (!sm || !mo) { free(sm); free(mo); g_licReason = @"内存不足"; return NO; }

    memcpy(sm, sigData.bytes, 64);
    memcpy(sm + 64, msgData.bytes, msgData.length);
    unsigned long long moLen = 0;
    int vret = crypto_sign_open(mo, &moLen, sm, smLen, pk);
    free(sm); free(mo);
    if (vret != 0) { g_licReason = @"签名校验失败"; return NO; }

    NSArray *fields = [parts[0] componentsSeparatedByString:@"#"];
    if (fields.count != 5) { g_licReason = @"授权码字段异常"; return NO; }
    if (![fields[0] isEqualToString:KP_PRODUCT_ID]) { g_licReason = @"产品不匹配"; return NO; }
    if (![kp_lic_norm(fields[1]) isEqualToString:kp_lic_dev_raw()]) { g_licReason = @"设备码不匹配"; return NO; }

    NSString *entropy = fields[3];
    NSString *encB64  = fields[4];
    BOOL hexOk = (entropy.length == 16);
    for (NSUInteger i = 0; hexOk && i < entropy.length; i++) {
        unichar ch = [entropy characterAtIndex:i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F'))) hexOk = NO;
    }
    if (!hexOk || encB64.length < 40) { g_licReason = @"授权码内容异常"; return NO; }

    NSString *expStr = fields[2];
    if (expStr.length != 10) { g_licReason = @"到期时间异常"; return NO; }
    for (NSUInteger i = 0; i < 10; i++) {
        unichar ch = [expStr characterAtIndex:i];
        if (ch < '0' || ch > '9') { g_licReason = @"到期时间异常"; return NO; }
    }
    long long exp = [expStr longLongValue];
    if (exp < 1704067200LL || exp > 2147483647LL) { g_licReason = @"到期时间越界"; return NO; }

    long long now = (long long)[[NSDate date] timeIntervalSince1970];
    long long wm  = kp_lic_last_ts();
    long long eff = (wm > now) ? wm : now;

    if (wm > 0 && now + 300 < wm) {
        long long netTS = kp_lic_fetch_net_time();
        if (netTS > 0) {
            kp_lic_force_ts(netTS);
            kp_kc_set_ll(KP_KC_NET, netTS);
            wm = netTS;
            eff = (wm > now) ? wm : now;
        }
        if (now + 300 < wm) { g_licReason = @"系统时间异常"; return NO; }
    }

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"yyyy-MM-dd HH:mm"];
    g_licExpireStr = [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)exp]];

    if (eff > exp) {
        g_licReason = [NSString stringWithFormat:@"已过期（%@）", g_licExpireStr];
        return NO;
    }

    kp_lic_save_ts(now, NO);
    kp_dsp_inject(entropy, encB64);
    if (g_dspParams.token != KP_DSP_TOKEN) { g_licReason = @"参数激活失败"; return NO; }

    g_licOk = YES;
    g_licReason = @"已授权";
    return YES;
}

static BOOL kp_lic_activate(NSString *code) {
    BOOL ok = kp_lic_verify(code);
    if (ok) kp_lic_store_code([code stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]);
    return ok;
}

static void kp_lic_load(void) {
    NSString *saved = kp_lic_stored_code();
    if (saved.length) kp_lic_verify(saved);
}

static UIButton *g_licBar = nil;
static UIWindow *g_licWin = nil;
static UIView *(*g_licSuperHitTest)(id, SEL, CGPoint, UIEvent *) = NULL;

static void kp_lic_refresh_bar(void) {
    if (!g_licBar) return;
    if (g_licOk) {
        [g_licBar setTitle:[NSString stringWithFormat:@"%@ · 已授权 · 到期 %@", KP_VERSION, g_licExpireStr]
                  forState:UIControlStateNormal];
        [g_licBar setTitleColor:[UIColor colorWithWhite:0.45 alpha:1.0] forState:UIControlStateNormal];
        g_licBar.backgroundColor = [UIColor clearColor];
    } else {
        [g_licBar setTitle:[NSString stringWithFormat:@"未授权 · 点此激活 · 设备码 %@", kp_lic_dev_disp()]
                  forState:UIControlStateNormal];
        [g_licBar setTitleColor:[UIColor colorWithRed:1.0 green:0.65 blue:0.55 alpha:1.0]
                       forState:UIControlStateNormal];
        g_licBar.backgroundColor = [UIColor colorWithRed:0.52 green:0.12 blue:0.10 alpha:0.95];
    }
}

static void kp_lic_window_class_once(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        SEL htSel = @selector(hitTest:withEvent:);
        Method superM = class_getInstanceMethod([UIWindow class], htSel);
        if (!superM) return;
        g_licSuperHitTest = (UIView *(*)(id, SEL, CGPoint, UIEvent *))method_getImplementation(superM);

        Class cls = objc_allocateClassPair([UIWindow class], "KPLicWindowV31", 0);
        if (!cls) return;
        class_addMethod(cls, htSel, imp_implementationWithBlock(^(id _s, CGPoint point, UIEvent *event) {
            UIViewController *host = [(UIWindow *)_s rootViewController];
            if (host.presentedViewController) {
                return g_licSuperHitTest(_s, htSel, point, event);
            }
            return (UIView *)nil;
        }), nil);
        objc_registerClassPair(cls);
    });
}

static UIViewController *kp_lic_top_vc(UIViewController *base) {
    UIViewController *top = base;
    while (top.presentedViewController && !top.presentedViewController.isBeingDismissed) {
        top = top.presentedViewController;
    }
    return top;
}

static void kp_lic_dismiss_win(void) {
    if (g_licWin) {
        g_licWin.hidden = YES;
        g_licWin = nil;
    }
    kp_lic_refresh_bar();
}

static UIAlertController *kp_lic_build_alert(void) {
    NSString *state = g_licOk
        ? [NSString stringWithFormat:@"已授权，到期 %@", g_licExpireStr]
        : [NSString stringWithFormat:@"未授权（%@）", g_licReason];

    NSString *msg = [NSString stringWithFormat:
                     @"本机设备码：\n%@\n\n当前状态：%@\n\n复制设备码获取授权码后粘贴激活。",
                     kp_lic_dev_disp(), state];

    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"授权激活"
                                                                message:msg
                                                         preferredStyle:UIAlertControllerStyleAlert];
    [al addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"粘贴授权码";
        tf.font = [UIFont systemFontOfSize:10];
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    __weak UIAlertController *weakAl = al;
    [al addAction:[UIAlertAction actionWithTitle:@"复制设备码" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) {
        [UIPasteboard generalPasteboard].string = kp_lic_dev_disp();
        UIAlertController *tip = [UIAlertController alertControllerWithTitle:@"已复制"
                                                                    message:kp_lic_dev_disp()
                                                             preferredStyle:UIAlertControllerStyleAlert];
        [tip addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *b) {
            if (!g_licWin) return;
            [kp_lic_top_vc(g_licWin.rootViewController) presentViewController:kp_lic_build_alert() animated:YES completion:nil];
        }]];
        [kp_lic_top_vc(g_licWin.rootViewController) presentViewController:tip animated:YES completion:nil];
    }]];

    [al addAction:[UIAlertAction actionWithTitle:@"立即激活" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) {
        NSString *input = weakAl.textFields.firstObject.text;
        BOOL ok = kp_lic_activate(input);
        NSString *t = ok ? @"激活成功" : @"激活失败";
        NSString *m = ok ? [NSString stringWithFormat:@"已授权，到期 %@", g_licExpireStr] : g_licReason;
        UIAlertController *r = [UIAlertController alertControllerWithTitle:t message:m
                                                           preferredStyle:UIAlertControllerStyleAlert];
        [r addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *b) {
            if (ok) kp_lic_dismiss_win();
            else if (g_licWin) [kp_lic_top_vc(g_licWin.rootViewController) presentViewController:kp_lic_build_alert() animated:YES completion:nil];
        }]];
        [kp_lic_top_vc(g_licWin.rootViewController) presentViewController:r animated:YES completion:nil];
    }]];

    [al addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel
                                        handler:^(UIAlertAction *a) {
        kp_lic_dismiss_win();
    }]];
    return al;
}

static void kp_lic_show_alert(void) {
    kp_lic_window_class_once();
    if (g_licWin) {
        if (!g_licWin.rootViewController.presentedViewController) {
            kp_lic_dismiss_win();
        } else {
            return;
        }
    }

    Class wcls = NSClassFromString(@"KPLicWindowV31") ?: [UIWindow class];
    g_licWin = [[wcls alloc] initWithFrame:[UIScreen mainScreen].bounds];
    g_licWin.windowLevel = UIWindowLevelAlert + 200;
    g_licWin.backgroundColor = [UIColor clearColor];

    UIViewController *host = [[UIViewController alloc] init];
    host.view.backgroundColor = [UIColor clearColor];
    g_licWin.rootViewController = host;

    if (@available(iOS 13.0, *)) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.windowScene) { g_licWin.windowScene = w.windowScene; break; }
        }
    }

    [g_licWin makeKeyAndVisible];
    [host presentViewController:kp_lic_build_alert() animated:YES completion:nil];
}

// ==========================================
// 7. 核心音频处理总线（人声 + BGM/音效/话术 统一限幅与避让）
// ==========================================
static inline void kp_process_pcm(int16_t *pcm, UInt32 frames, UInt32 chs, BOOL isPrimary) {
    if (!g_licOk || !pcm || frames == 0) return;
    if (chs < 1) chs = 1;
    if (chs > 2) chs = 2;
    if (g_dspParams.token != KP_DSP_TOKEN) {
        memset(pcm, 0, (size_t)frames * chs * sizeof(int16_t));
        return;
    }

    kp_probe_tick(pcm, frames, chs, isPrimary);
    UInt32 chOff = isPrimary ? 0 : 4;
    const KPFilterBank *bank = &g_filterBanks[g_activeBank];
    g_grCompPeak = 0.0f;
    g_grLimPeak  = 0.0f;

    UInt32 total = frames * chs;
    float rawPeak = 0.0f;
    for (UInt32 i = 0; i < total; i++) {
        float r = fabsf((float)pcm[i]) * (1.0f / 32768.0f);
        if (r > rawPeak) rawPeak = r;
    }

    float gain = g_makeupGain;
    float ceilNorm = g_limiterCeiling * (1.0f / 32768.0f);
    if (ceilNorm > 0.98f) ceilNorm = 0.98f;

    float outPeak = 0.0f;
    float fs = g_sampleRate > 8000.0f ? g_sampleRate : 48000.0f;
    float sumSq = 0.0f;
    int   rmsCnt = 0;

    float fbuf[2 * KP_PROC_CHUNK];
    for (UInt32 f0 = 0; f0 < frames; f0 += KP_PROC_CHUNK) {
        UInt32 curFrames = frames - f0;
        if (curFrames > KP_PROC_CHUNK) curFrames = KP_PROC_CHUNK;
        int16_t *subPcm = pcm + f0 * chs;

        for (UInt32 f = 0; f < curFrames; f++) {
            for (UInt32 c = 0; c < chs; c++) {
                float s = (float)subPcm[f * chs + c];
                if (isPrimary) {
                    s = kp_voice_pre_sample(s, chOff + c, bank);
                } else if (g_compEnabled) {
                    s = kp_comp_sample(s * (1.0f / 32768.0f), chOff + c) * 32768.0f;
                }
                fbuf[f * chs + c] = s;
            }
        }

        if (isPrimary && g_recOn) {
            int16_t *rb = g_recBuf;
            if (rb) {
                int cnt = g_recCount;
                for (UInt32 f = 0; f < curFrames && cnt < CLIP_MAX_SAMPLES; f++) {
                    float rv = fbuf[f * chs];
                    if (rv > 32767.0f) rv = 32767.0f;
                    if (rv < -32768.0f) rv = -32768.0f;
                    rb[cnt++] = (int16_t)rv;
                }
                g_recCount = cnt;
            }
        }

        if (isPrimary) {
            BOOL clipOn = (g_clipOn != 0);
            float floorV = (g_bgmDuckFloor >= 0.05f && g_bgmDuckFloor <= 0.70f) ? g_bgmDuckFloor : 0.22f;
            float target = (g_duckEnabled && (rawPeak > 0.03f || clipOn)) ? floorV : 1.0f;
            float dt  = (float)curFrames / fs;
            float tau = (target < g_duckGain) ? 0.030f : 0.280f;
            float a   = 1.0f - expf(-dt / tau);
            if (a > 1.0f) a = 1.0f;
            g_duckGain += (target - g_duckGain) * a;
        }

        for (UInt32 f = 0; f < curFrames; f++) {
            float vL = fbuf[f * chs] * (1.0f / 32768.0f);
            float vR = (chs >= 2) ? (fbuf[f * chs + 1] * (1.0f / 32768.0f)) : vL;

            if (isPrimary && g_reverbEnabled) {
                float wL = kp_reverb_tick(vL * 32768.0f, 0) * (1.0f / 32768.0f);
                float wR = (chs >= 2) ? (kp_reverb_tick(vR * 32768.0f, 1) * (1.0f / 32768.0f)) : wL;
                vL = vL * (1.0f - g_reverbWet) + wL * g_reverbWet;
                vR = vR * (1.0f - g_reverbWet) + wR * g_reverbWet;
            }

            vL *= gain;
            vR *= gain;

            // v34.1 BGMOnly：麦克风路径彻底置零，只留 mus（BGM/SFX/片段）走同一个 SSRC
            if (isPrimary && g_bgmOnly) {
                vL = 0.0f;
                vR = 0.0f;
            }

            float mus = 0.0f;
            if (isPrimary) {
                for (int s = 0; s < SFX_SLOT; s++) {
                    if (!g_sfxOn[s]) continue;
                    int pos = g_sfxPos[s];
                    if (pos >= (int)g_sfxClip[s].len) { g_sfxOn[s] = 0; continue; }
                    mus += (float)g_sfxClip[s].pcm[pos] * g_sfxVolume;
                    g_sfxPos[s] = pos + 1;
                }
                if (g_bgmOn && g_bgmPcm && g_bgmLen > 0) {
                    int pos = g_bgmPos;
                    if (pos >= g_bgmLen) pos = 0;
                    float duckFactor = g_duckEnabled ? g_duckGain : 1.0f;
                    mus += (float)g_bgmPcm[pos] * g_bgmVolume * duckFactor;
                    g_bgmPos = pos + 1;
                }
                if (g_clipOn && g_clipPcm && g_clipLen > 0) {
                    int pos = g_clipPos;
                    if (pos >= g_clipLen && g_clipLoop) pos = 0;
                    if (pos < g_clipLen) {
                        mus += (float)g_clipPcm[pos];
                        g_clipPos = pos + 1;
                    } else {
                        g_clipOn = 0;
                        g_clipPlayingSlot = -1;
                    }
                }
            }

            float mNorm = mus * (1.0f / 32768.0f);
            if (mNorm > 0.65f)  mNorm = 0.65f + 0.15f * tanhf((mNorm - 0.65f) * 4.0f);
            if (mNorm < -0.65f) mNorm = -0.65f + 0.15f * tanhf((mNorm + 0.65f) * 4.0f);

            float L = vL + mNorm;
            float R = vR + mNorm;

            if (g_limiterEnabled) {
                L = kp_limiter_tick(L, chOff + 0, ceilNorm);
                if (chs >= 2) R = kp_limiter_tick(R, chOff + 1, ceilNorm);
            } else {
                L = tanhf(L) * ceilNorm;
                if (chs >= 2) R = tanhf(R) * ceilNorm;
            }

            float pL = fabsf(L), pR = (chs >= 2) ? fabsf(R) : 0.0f;
            if (pL > outPeak) outPeak = pL;
            if (pR > outPeak) outPeak = pR;
            if (isPrimary) { sumSq += L * L; rmsCnt++; }

            int32_t iL = (int32_t)(L * 32767.0f);
            if (iL > 32767) iL = 32767;
            if (iL < -32768) iL = -32768;
            subPcm[f * chs] = (int16_t)iL;

            if (chs >= 2) {
                int32_t iR = (int32_t)(R * 32767.0f);
                if (iR > 32767) iR = 32767;
                if (iR < -32768) iR = -32768;
                subPcm[f * chs + 1] = (int16_t)iR;
            }
        }

        // v31.1：g_rmsTrim 自压总增益机制已彻底移除——响度全部交给 KVDSP 浮点出口把控
        sumSq = 0.0f;
        rmsCnt = 0;
    }

    kp_probe_out(pcm, frames, chs, isPrimary);
    int vuIn  = (int)(rawPeak * 100.0f); if (vuIn > 100)  vuIn = 100;
    int vuOut = (int)(outPeak * 100.0f); if (vuOut > 100) vuOut = 100;
    float maxGr = (g_grCompPeak > g_grLimPeak) ? g_grCompPeak : g_grLimPeak;
    int vuGr  = (int)maxGr;              if (vuGr > 100)  vuGr = 100;

    if (isPrimary) {
        if (vuIn > g_vuIn)   g_vuIn = vuIn;
        if (vuOut > g_vuOut) g_vuOut = vuOut;
        if (vuGr > g_vuGr)   g_vuGr = vuGr;
        if (vuOut > g_vuMic) g_vuMic = vuOut;
    } else {
        if (vuOut > g_vuMix) g_vuMix = vuOut;
    }
    g_frames++;
}

// ==========================================
// 8a. 自定义浮点后处理：完全接管 WebRTC capturePostProcessingDelegate，跳过官方 KakaAudioMixer
//     KVDSP 人声处理 + 独立音量 BGM/音效/话术混音 + tanhf 软限幅，恒在 ±1.0 内响而不炸
// ==========================================
@interface KPCustomAudioProcessor : NSObject
- (void)audioProcessingInitializeWithSampleRate:(size_t)sampleRate channels:(size_t)channels;
- (void)audioProcessingProcess:(id)audioBuffer;
- (void)audioProcessingRelease;
@end

static KPCustomAudioProcessor *g_customProc = nil;

@implementation KPCustomAudioProcessor

- (void)audioProcessingInitializeWithSampleRate:(size_t)sampleRate channels:(size_t)channels {
    if (sampleRate >= 8000 && sampleRate <= 96000) {
        g_sampleRate = (float)sampleRate;
        kp_rebuild_filter_bank();
    }
    g_kvEnv = 0.0f;
    g_kvGainSmooth = 1.0f;
    kp_log(@"[KV-TAKEOVER] 浮点出口已接管（跳过官方混音器）sr=%zu ch=%zu", sampleRate, channels);
}

- (void)audioProcessingProcess:(id)audioBuffer {
    // v31.10：kp_hook_mixProc（KakaAudioMixer 出口）已全链接管上行处理，
    // APM 浮点出口不再二次处理——防止同一份音频增益叠加两遍变成 -2.3dB 死砖墙方波。
    //（下方旧处理体保留但不可达，直接 return）
    (void)audioBuffer;
    return;

    if (!g_dspEnabled || !audioBuffer) return;

    // 通过 runtime 读取 RTCAudioBuffer 的 channels / frames / rawBufferForChannel:
    NSUInteger chans  = ((NSUInteger (*)(id, SEL))objc_msgSend)(audioBuffer, NSSelectorFromString(@"channels"));
    NSUInteger frames = ((NSUInteger (*)(id, SEL))objc_msgSend)(audioBuffer, NSSelectorFromString(@"frames"));
    if (chans == 0 || frames == 0) return;
    if (chans > 2) chans = 2;

    float *bufs[2] = {NULL, NULL};
    SEL rawSel = NSSelectorFromString(@"rawBufferForChannel:");
    for (NSUInteger c = 0; c < chans; c++) {
        bufs[c] = ((float *(*)(id, SEL, NSUInteger))objc_msgSend)(audioBuffer, rawSel, c);
        if (!bufs[c]) return;
    }

    const KPFilterBank *bank = &g_filterBanks[g_activeBank];
    float fs = g_sampleRate > 8000.0f ? g_sampleRate : 48000.0f;

    // 1. 计算本帧原始峰值，用于 BGM 说话闪避检测
    float rawPeak = 0.0f;
    for (NSUInteger i = 0; i < frames; i++) {
        float a = fabsf(bufs[0][i]);
        if (a > rawPeak) rawPeak = a;
    }

    // 2. 平滑更新 BGM 闪避系数（关掉闪避则恒为 1.0，绝不压小）
    BOOL clipOn = (g_clipOn != 0);
    float floorV = (g_bgmDuckFloor >= 0.05f && g_bgmDuckFloor <= 0.70f) ? g_bgmDuckFloor : 0.22f;
    float duckTarget = (g_duckEnabled && (rawPeak > 0.025f || clipOn)) ? floorV : 1.0f;
    float dt  = (float)frames / fs;
    float tau = (duckTarget < g_duckGain) ? 0.030f : 0.280f;
    float aDuck = 1.0f - expf(-dt / tau);
    if (aDuck > 1.0f) aDuck = 1.0f;
    g_duckGain += (duckTarget - g_duckGain) * aDuck;

    float outPeak = 0.0f;
    float thr = g_compThresh;
    float ratio = g_compRatio;
    float preG = g_preGain;
    float makeup = g_makeupGain;

    for (NSUInteger f = 0; f < frames; f++) {
        float tmp[2] = {0.0f, 0.0f};
        float peak = 0.0f;

        // 3. 人声链：120Hz 高通 -> 2.8kHz 存在感提亮 -> 10段 EQ -> 前级增益
        for (NSUInteger c = 0; c < chans; c++) {
            float x = bufs[c][f];
            if (g_lowCutEnabled) {
                float fy = x - g_dc_x1[c] + g_hpfAlpha * g_dc_y1[c];
                g_dc_x1[c] = x;
                g_dc_y1[c] = fy;
                x = fy;
            }
            if (g_throatEnabled) {
                x = kp_biquad_run(x, &bank->throat[0], &g_throatSt[c][0]);
                x = kp_biquad_run(x, &bank->throat[1], &g_throatSt[c][1]);
            }
            if (g_eq10Enabled) {
                for (int b = 0; b < EQ10_BANDS; b++) {
                    x = kp_biquad_run(x, &bank->eq10[b], &g_eq10St[c][b]);
                }
            }
            x *= preG;
            tmp[c] = x;
            float ax = fabsf(x);
            if (ax > peak) peak = ax;
        }

        // 4. 紧致压缩器（报告附录 C.1 逻辑：4:1~6:1 压密人声）
        float coef = (peak > g_kvEnv) ? g_compAtkCoef : g_compRelCoef;
        g_kvEnv += (peak - g_kvEnv) * coef;
        float targetGr = 1.0f;
        if (g_compEnabled && g_kvEnv > thr && thr > 0.001f) {
            float overDb = 20.0f * log10f(g_kvEnv / thr);
            float redDb  = overDb * (1.0f - 1.0f / ratio);
            targetGr = powf(10.0f, -redDb / 20.0f);
        }
        g_kvGainSmooth += (targetGr - g_kvGainSmooth) * 0.35f;

        // 5. 提取 BGM / 音效 / 话术（独立推子，不再被 0.65f 砍一刀）
        float mus = 0.0f;
        for (int s = 0; s < SFX_SLOT; s++) {
            if (!g_sfxOn[s]) continue;
            int pos = g_sfxPos[s];
            if (pos >= (int)g_sfxClip[s].len) { g_sfxOn[s] = 0; continue; }
            mus += ((float)g_sfxClip[s].pcm[pos] / 32768.0f) * g_sfxVolume;
            g_sfxPos[s] = pos + 1;
        }
        if (g_bgmOn && g_bgmPcm && g_bgmLen > 0) {
            int pos = g_bgmPos;
            if (pos >= g_bgmLen) pos = 0;
            float duckF = g_duckEnabled ? g_duckGain : 1.0f;
            mus += ((float)g_bgmPcm[pos] / 32768.0f) * g_bgmVolume * duckF;
            g_bgmPos = pos + 1;
        }
        if (g_clipOn && g_clipPcm && g_clipLen > 0) {
            int pos = g_clipPos;
            if (pos >= g_clipLen && g_clipLoop) pos = 0;
            if (pos < g_clipLen) {
                mus += ((float)g_clipPcm[pos] / 32768.0f);
                g_clipPos = pos + 1;
            } else {
                g_clipOn = 0;
                g_clipPlayingSlot = -1;
            }
        }

        // 6. 人声(压缩+Makeup) + BGM 汇总，过 tanhf 软限幅（恒在 ±1.0 内，响且不炸）
        for (NSUInteger c = 0; c < chans; c++) {
            float v = tmp[c] * g_kvGainSmooth * makeup;
            if (g_reverbEnabled) {
                float w = kp_reverb_tick(v * 32768.0f, (UInt32)c) / 32768.0f;
                v = v * (1.0f - g_reverbWet) + w * g_reverbWet;
            }
            float out = tanhf(v + mus);
            bufs[c][f] = out;
            if (fabsf(out) > outPeak) outPeak = fabsf(out);
        }

        // 话术录音同步采集（录下处理后的人声）
        if (g_recOn && g_recBuf && g_recCount < CLIP_MAX_SAMPLES) {
            float rv = tanhf(tmp[0] * g_kvGainSmooth * makeup) * 32767.0f;
            g_recBuf[g_recCount++] = (int16_t)rv;
        }
    }

    int vuIn  = (int)(rawPeak * 100.0f); if (vuIn > 100)  vuIn = 100;
    int vuOut = (int)(outPeak * 100.0f); if (vuOut > 100) vuOut = 100;
    if (vuIn > g_vuIn)   g_vuIn = vuIn;
    if (vuOut > g_vuOut) g_vuOut = vuOut;
    if (vuOut > g_vuMic) g_vuMic = vuOut;
    g_pcmCalls++;
}

- (void)audioProcessingRelease {
    kp_log(@"[KV-TAKEOVER] 浮点出口已释放");
}

@end

// ==========================================
// v31.9 房间与通道监听：下行混音统计（链式透传，不影响收听）
// ==========================================
static _Atomic BOOL g_roomMonitorEnabled = YES; // 房间与通道监听日志总开关
static NSHashTable *g_allPeerConns = nil;       // v31.10：记录所有 RTCPeerConnection（KAKA 建两条：上行+下行）
static id g_origRenderDel = nil;                // 链式保留官方渲染代理，绝不影响听别人说话

@interface KPRenderMonitorProcessor : NSObject
- (void)audioProcessingInitializeWithSampleRate:(size_t)sampleRate channels:(size_t)channels;
- (void)audioProcessingProcess:(id)audioBuffer;
- (void)audioProcessingRelease;
@end

static KPRenderMonitorProcessor *g_renderMon = nil;

@implementation KPRenderMonitorProcessor

- (void)audioProcessingInitializeWithSampleRate:(size_t)sampleRate channels:(size_t)channels {
    if (g_origRenderDel && [g_origRenderDel respondsToSelector:_cmd]) {
        ((void (*)(id, SEL, size_t, size_t))objc_msgSend)(g_origRenderDel, _cmd, sampleRate, channels);
    }
    if (g_roomMonitorEnabled) {
        kp_log(@"[ROOM-RX] 下行混音初始化 sr=%zu ch=%zu", sampleRate, channels);
    }
}

- (void)audioProcessingProcess:(id)audioBuffer {
    // 1. 统计整个房间下行混音的峰值和 RMS（不改数据，只监听）
    if (g_roomMonitorEnabled && audioBuffer) {
        NSUInteger chans  = ((NSUInteger (*)(id, SEL))objc_msgSend)(audioBuffer, NSSelectorFromString(@"channels"));
        NSUInteger frames = ((NSUInteger (*)(id, SEL))objc_msgSend)(audioBuffer, NSSelectorFromString(@"frames"));
        if (chans > 0 && frames > 0) {
            float *p = ((float *(*)(id, SEL, NSUInteger))objc_msgSend)(audioBuffer, NSSelectorFromString(@"rawBufferForChannel:"), 0);
            if (p) {
                static double lastT = 0;
                static float rxPeak = 0.0f;
                static double sumSq = 0.0;
                static long totalSamples = 0;

                for (NSUInteger i = 0; i < frames; i++) {
                    float v = p[i];
                    float a = fabsf(v);
                    if (a > rxPeak) rxPeak = a;
                    sumSq += (double)v * (double)v;
                }
                totalSamples += (long)frames;

                double now = CACurrentMediaTime();
                if (lastT == 0) lastT = now;
                if (now - lastT >= 5.0) {
                    double rms = (totalSamples > 0) ? sqrt(sumSq / (double)totalSamples) : 0.0;
                    double db  = 20.0 * log10(rms > 1e-9 ? rms : 1e-9);
                    int pkPct  = (int)(rxPeak * 100.0f);
                    if (pkPct > 100) pkPct = 100;
                    kp_log(@"[ROOM-RX] 房间下行总音量 peak=%d%% rms=%.1fdB ch=%lu", pkPct, db, (unsigned long)chans);
                    lastT = now; rxPeak = 0.0f; sumSq = 0.0; totalSamples = 0;
                }
            }
        }
    }

    // 2. 原样交给官方渲染代理（确保听别人说话完全正常）
    if (g_origRenderDel && [g_origRenderDel respondsToSelector:_cmd]) {
        ((void (*)(id, SEL, id))objc_msgSend)(g_origRenderDel, _cmd, audioBuffer);
    }
}

- (void)audioProcessingRelease {
    if (g_origRenderDel && [g_origRenderDel respondsToSelector:_cmd]) {
        ((void (*)(id, SEL))objc_msgSend)(g_origRenderDel, _cmd);
    }
}

@end

// ==========================================
// 8. 音频与 WebRTC 安全 Hook 层
// ==========================================
static int  (*orig_deliverPCM)(id, SEL, int16_t *, unsigned int, unsigned long long, const AudioTimeStamp *) = NULL;
static void (*orig_mixerPCM)(id, SEL, int16_t *, unsigned long long, unsigned long long, double) = NULL;
static void (*orig_willEnableEngine)(id, SEL, id, BOOL, BOOL, BOOL, BOOL) = NULL;
static BOOL (*orig_captureGate)(id, SEL) = NULL;
static void (*orig_setCaptureGate)(id, SEL, BOOL) = NULL;
static BOOL (*orig_speakerAEC)(id, SEL) = NULL;
static void (*orig_setSpeakerAEC)(id, SEL, BOOL) = NULL;
static void (*orig_stopRecording)(id, SEL) = NULL;

static BOOL kp_hook_capture_gate(id self, SEL _cmd) {
    if (g_dspEnabled || g_priorityLoud) return NO;
    return orig_captureGate ? orig_captureGate(self, _cmd) : NO;
}

static void kp_hook_set_capture_gate(id self, SEL _cmd, BOOL en) {
    if (orig_setCaptureGate) {
        BOOL v = (g_dspEnabled || g_priorityLoud) ? NO : en;
        orig_setCaptureGate(self, _cmd, v);
    }
}

static BOOL kp_hook_speaker_aec(id self, SEL _cmd) {
    if (g_losslessPriority || g_priorityLoud || g_shieldRemote) return NO;
    return orig_speakerAEC ? orig_speakerAEC(self, _cmd) : NO;
}

static void kp_hook_set_speaker_aec(id self, SEL _cmd, BOOL en) {
    if (orig_setSpeakerAEC) {
        BOOL v = (g_losslessPriority || g_priorityLoud || g_shieldRemote) ? NO : en;
        orig_setSpeakerAEC(self, _cmd, v);
    }
}

static void kp_hook_stop_recording(id self, SEL _cmd) {
    kp_log(@"[mic-guard] stopRecording called");
    if (orig_stopRecording) orig_stopRecording(self, _cmd);
}

static void kp_hook_will_enable_engine(id self, SEL _cmd, id adm, BOOL eng, BOOL playout, BOOL rec, BOOL vp) {
    BOOL forceOff = (g_deepBypassVP || g_priorityLoud || g_shieldRemote);
    if (orig_willEnableEngine) {
        orig_willEnableEngine(self, _cmd, adm, eng, playout, rec, forceOff ? NO : vp);
    }
}

static int kp_deliver_pcm(id self, SEL _cmd, int16_t *pcm, unsigned int frames, unsigned long long channels, const AudioTimeStamp *ts) {
    g_pcmCalls++;
    // v31.1：KVDSP 浮点出口（KPCustomAudioProcessor）已完全接管，
    // int16 采集路径不再做 DSP，避免两遍增益叠加导致破音/冲突
    // if (g_dspEnabled && pcm && frames > 0) {
    //     kp_process_pcm(pcm, frames, (UInt32)channels, YES);
    // }
    return orig_deliverPCM(self, _cmd, pcm, frames, channels, ts);
}

static void kp_mixer_pcm(id self, SEL _cmd, int16_t *pcm, unsigned long long frames, unsigned long long channels, double rate) {
    g_mixCalls++;
    if (rate >= 8000.0 && rate <= 96000.0 && fabsf((float)rate - g_sampleRate) > 10.0f) {
        g_sampleRate = (float)rate;
        kp_rebuild_filter_bank();
    }
    // v31.1：int16 混音路径不再做 DSP（统一在 KPCustomAudioProcessor 浮点出口处理）
    // if (g_dspEnabled && (g_mixDspEnabled || g_losslessPriority) && pcm && frames > 0) {
    //     kp_process_pcm(pcm, (UInt32)frames, (UInt32)channels, NO);
    // }
    orig_mixerPCM(self, _cmd, pcm, frames, channels, rate);
}

static int kp_install_hooks(void) {
    int state = 0;
    Class dev = objc_getClass("KakaStereoAudioDevice");
    if (dev) {
        Method m = class_getInstanceMethod(dev, @selector(deliverPCM:frames:channels:timestamp:));
        if (m && !orig_deliverPCM) {
            orig_deliverPCM = (int (*)(id, SEL, int16_t *, unsigned int, unsigned long long, const AudioTimeStamp *))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_deliver_pcm);
        }
        if (orig_deliverPCM) state |= 1;

        Method mg = class_getInstanceMethod(dev, @selector(roomCaptureGateEnabled));
        if (mg && !orig_captureGate) {
            orig_captureGate = (BOOL (*)(id, SEL))method_getImplementation(mg);
            method_setImplementation(mg, (IMP)kp_hook_capture_gate);
        }
        Method msg = class_getInstanceMethod(dev, @selector(setRoomCaptureGateEnabled:));
        if (msg && !orig_setCaptureGate) {
            orig_setCaptureGate = (void (*)(id, SEL, BOOL))method_getImplementation(msg);
            method_setImplementation(msg, (IMP)kp_hook_set_capture_gate);
        }
        Method maeG = class_getInstanceMethod(dev, @selector(speakerphoneEchoCancellation));
        if (maeG && !orig_speakerAEC) {
            orig_speakerAEC = (BOOL (*)(id, SEL))method_getImplementation(maeG);
            method_setImplementation(maeG, (IMP)kp_hook_speaker_aec);
        }
        Method maeS = class_getInstanceMethod(dev, @selector(setSpeakerphoneEchoCancellation:));
        if (maeS && !orig_setSpeakerAEC) {
            orig_setSpeakerAEC = (void (*)(id, SEL, BOOL))method_getImplementation(maeS);
            method_setImplementation(maeS, (IMP)kp_hook_set_speaker_aec);
        }
        Method mStop = class_getInstanceMethod(dev, @selector(stopRecording));
        if (mStop && !orig_stopRecording) {
            orig_stopRecording = (void (*)(id, SEL))method_getImplementation(mStop);
            method_setImplementation(mStop, (IMP)kp_hook_stop_recording);
        }
    }

    Class mixer = objc_getClass("KakaAudioMixer");
    if (mixer) {
        Method m = class_getInstanceMethod(mixer, @selector(processPCM:frames:channels:rate:));
        if (m && !orig_mixerPCM) {
            orig_mixerPCM = (void (*)(id, SEL, int16_t *, unsigned long long, unsigned long long, double))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_mixer_pcm);
        }
        if (orig_mixerPCM) state |= 2;

        Method me = class_getInstanceMethod(mixer, @selector(audioDeviceModule:willEnableEngine:isPlayoutEnabled:isRecordingEnabled:isVoiceProcessingEnabled:));
        if (me && !orig_willEnableEngine) {
            orig_willEnableEngine = (void (*)(id, SEL, id, BOOL, BOOL, BOOL, BOOL))method_getImplementation(me);
            method_setImplementation(me, (IMP)kp_hook_will_enable_engine);
        }

        // v31.2 直接接管 KakaAudioMixer 的浮点出口，不调用原实现（彻底不要官方混音器）
        // probe-m 已证实该类自带 audioProcessingInitializeWithSampleRate:channels: 与
        // audioProcessingProcess:，原地替换即可命中真实调用链，无需依赖 APM 设代理
        if (!g_customProc) g_customProc = [[KPCustomAudioProcessor alloc] init];

        SEL initProcSel = NSSelectorFromString(@"audioProcessingInitializeWithSampleRate:channels:");
        Method mInitProc = class_getInstanceMethod(mixer, initProcSel);
        if (mInitProc) {
            static BOOL hookedInit = NO;
            if (!hookedInit) {
                hookedInit = YES;
                method_setImplementation(mInitProc, imp_implementationWithBlock(^(id _s, size_t sr, size_t ch) {
                    [g_customProc audioProcessingInitializeWithSampleRate:sr channels:ch];
                }));
            }
        }

        SEL procSel = NSSelectorFromString(@"audioProcessingProcess:");
        Method mProc = class_getInstanceMethod(mixer, procSel);
        if (mProc) {
            static BOOL hookedProc = NO;
            if (!hookedProc) {
                hookedProc = YES;
                method_setImplementation(mProc, imp_implementationWithBlock(^(id _s, id audioBuffer) {
                    // 直接跑我们自己的高密度人声 + BGM + tanhf 软限幅，不调官方 orig
                    [g_customProc audioProcessingProcess:audioBuffer];
                }));
                state |= 8;
                kp_log(@"[KV-TAKEOVER] 已强制原地接管 KakaAudioMixer audioProcessingProcess:");
            }
        }
    }
    return state;
}

static void kp_lock_bool_prop(Class cls, NSString *getterName, NSString *setterName) {
    SEL g = NSSelectorFromString(getterName);
    SEL s = NSSelectorFromString(setterName);
    Method mg = class_getInstanceMethod(cls, g);
    if (mg) {
        method_setImplementation(mg, imp_implementationWithBlock(^BOOL(id _s) {
            (void)_s;
            return NO;
        }));
    }
    Method ms = class_getInstanceMethod(cls, s);
    if (ms) {
        IMP orig = method_getImplementation(ms);
        method_setImplementation(ms, imp_implementationWithBlock(^(id _s, BOOL en) {
            (void)en;
            ((void (*)(id, SEL, BOOL))orig)(_s, s, NO);
        }));
    }
}

static BOOL (*kp_orig_av_setMode)(id, SEL, NSString *, NSError **) = NULL;
static BOOL kp_hook_av_setMode(id self, SEL _cmd, NSString *mode, NSError **err) {
    NSString *targetMode = mode;
    if (g_deepBypassVP && [mode isEqualToString:@"AVAudioSessionModeVoiceChat"]) {
        targetMode = @"AVAudioSessionModeDefault";
    }
    return kp_orig_av_setMode ? kp_orig_av_setMode(self, _cmd, targetMode, err) : YES;
}

// v31.1：强行关闭 RTCAudioDeviceModule 的 Ducking 和平台 AGC
static void kp_tune_device_module(id adm) {
    if (!adm) return;
    @try {
        if (g_disableDucking) {
            SEL sDuck = NSSelectorFromString(@"setAdvancedDuckingEnabled:");
            if ([adm respondsToSelector:sDuck]) ((void (*)(id, SEL, BOOL))objc_msgSend)(adm, sDuck, NO);
            SEL sLvl = NSSelectorFromString(@"setDuckingLevel:");
            if ([adm respondsToSelector:sLvl]) ((void (*)(id, SEL, long))objc_msgSend)(adm, sLvl, 0);
        }
        SEL sAgc = NSSelectorFromString(@"setVoiceProcessingAGCEnabled:");
        if ([adm respondsToSelector:sAgc]) ((void (*)(id, SEL, BOOL))objc_msgSend)(adm, sAgc, NO);
    } @catch (NSException *e) {}
}

// v31.1：强行关闭 APM 的 AGC1/AGC2/NS/HPF/瞬态抑制（保留 AEC 防外放啸叫）
static void kp_tune_apm_config(id cfg) {
    if (!cfg) return;
    @try {
        [cfg setValue:@NO forKey:@"isAutoGainControl1Enabled"];
        [cfg setValue:@NO forKey:@"isAutoGainControl2Enabled"];
        [cfg setValue:@NO forKey:@"isNoiseSuppressionEnabled"];
        [cfg setValue:@NO forKey:@"isTransientSuppressionEnabled"];
        [cfg setValue:@NO forKey:@"isHighPassFilterEnabled"];
        // AEC 保持 YES，避免外放啸叫
    } @catch (NSException *e) {}
}

// v31.1：Hook AVAudioSession / RTCAudioSession 的 setCategory:mode:options:error:
//        把 VoiceChat / VideoChat 全部改写为 Default，甩掉苹果通话模式压制
static BOOL (*orig_av_setCatModeOpt)(id, SEL, NSString *, NSString *, NSUInteger, NSError **) = NULL;
static BOOL kp_hook_av_setCatModeOpt(id self, SEL _cmd, NSString *cat, NSString *mode, NSUInteger opt, NSError **err) {
    NSString *m = mode;
    if (g_forceDefaultMode && ([m isEqualToString:@"AVAudioSessionModeVoiceChat"] || [m isEqualToString:@"AVAudioSessionModeVideoChat"])) {
        m = @"AVAudioSessionModeDefault";
    }
    BOOL ok = orig_av_setCatModeOpt ? orig_av_setCatModeOpt(self, _cmd, cat, m, opt, err) : YES;

    // v31.8：强制锁定 48000Hz 宽带采样率 + 10ms 低延迟缓冲，防止退化为 16kHz 窄带通话音质
    // （用 runtime 消息发送，AVAudioSession 仅前向声明，避免引入 AVFoundation 依赖）
    static Class clsAVS = NULL;
    if (!clsAVS) clsAVS = objc_getClass("AVAudioSession");
    if (clsAVS && [(id)self isKindOfClass:clsAVS]) {
        SEL sSR = @selector(setPreferredSampleRate:error:);
        SEL sIO = @selector(setPreferredIOBufferDuration:error:);
        ((void (*)(id, SEL, double, id))objc_msgSend)(self, sSR, 48000.0, nil);
        ((void (*)(id, SEL, double, id))objc_msgSend)(self, sIO, 0.010, nil);
    }
    return ok;
}

static void kp_disable_agc(void) {
    if (!g_customProc) g_customProc = [[KPCustomAudioProcessor alloc] init];

    // ① Hook AVAudioSession / RTCAudioSession：切掉 VoiceChat 语音处理链
    for (NSString *clsName in @[@"AVAudioSession", @"RTCAudioSession"]) {
        Class cls = objc_getClass(clsName.UTF8String);
        if (!cls) continue;
        SEL sel = @selector(setCategory:mode:options:error:);
        Method m = class_getInstanceMethod(cls, sel);
        if (m && !orig_av_setCatModeOpt) {
            orig_av_setCatModeOpt = (BOOL (*)(id, SEL, NSString *, NSString *, NSUInteger, NSError **))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_hook_av_setCatModeOpt);
        }
    }

    // ② Hook RTCDefaultAudioProcessingModule：关 AGC/NS/HPF，并用 g_customProc 完全顶掉官方 KakaAudioMixer
    Class apmCls = objc_getClass("RTCDefaultAudioProcessingModule");
    if (apmCls) {
        SEL initSel = NSSelectorFromString(@"initWithConfig:capturePostProcessingDelegate:renderPreProcessingDelegate:");
        Method mInit = class_getInstanceMethod(apmCls, initSel);
        if (mInit) {
            IMP origInit = method_getImplementation(mInit);
            method_setImplementation(mInit, imp_implementationWithBlock(^id(id _s, id cfg, id capDel, id renDel) {
                kp_tune_apm_config(cfg);
                // v31.9：链式保留官方渲染代理，改传 g_renderMon 做下行统计（不影响收听）
                if (renDel && renDel != (id)g_renderMon) g_origRenderDel = renDel;
                if (!g_renderMon) g_renderMon = [[KPRenderMonitorProcessor alloc] init];
                // 直接传 g_customProc，不再挂官方 capDel (KakaAudioMixer)
                return ((id (*)(id, SEL, id, id, id))origInit)(_s, initSel, cfg, g_customProc, g_renderMon);
            }));
        }
        SEL setCfgSel = NSSelectorFromString(@"setConfig:");
        Method mCfg = class_getInstanceMethod(apmCls, setCfgSel);
        if (mCfg) {
            IMP origCfg = method_getImplementation(mCfg);
            method_setImplementation(mCfg, imp_implementationWithBlock(^(id _s, id cfg) {
                kp_tune_apm_config(cfg);
                ((void (*)(id, SEL, id))origCfg)(_s, setCfgSel, cfg);
            }));
        }
        SEL setDelSel = NSSelectorFromString(@"setCapturePostProcessingDelegate:");
        Method mDel = class_getInstanceMethod(apmCls, setDelSel);
        if (mDel) {
            IMP origDel = method_getImplementation(mDel);
            method_setImplementation(mDel, imp_implementationWithBlock(^(id _s, id del) {
                // 无论 App 试图把 KakaAudioMixer 设成什么，都强行换成我们的 g_customProc
                ((void (*)(id, SEL, id))origDel)(_s, setDelSel, g_customProc);
            }));
        }
    }

    // ③ Hook RTCAudioDeviceModule：关 advancedDuckingEnabled 和 duckingLevel
    Class adm = objc_getClass("RTCAudioDeviceModule");
    if (adm) {
        SEL initAdm = NSSelectorFromString(@"initWithNativeModule:workerThread:audioDeviceModuleType:");
        Method mAdm = class_getInstanceMethod(adm, initAdm);
        if (mAdm) {
            IMP origAdm = method_getImplementation(mAdm);
            method_setImplementation(mAdm, imp_implementationWithBlock(^id(id _s, void *nm, void *wt, NSInteger t) {
                id obj = ((id (*)(id, SEL, void *, void *, NSInteger))origAdm)(_s, initAdm, nm, wt, t);
                kp_tune_device_module(obj);
                return obj;
            }));
        }
        Method m1 = class_getInstanceMethod(adm, @selector(setVoiceProcessingAGCEnabled:));
        if (m1) method_setImplementation(m1, imp_implementationWithBlock(^(id _s, BOOL en) { (void)en; }));
        Method m2 = class_getInstanceMethod(adm, @selector(isVoiceProcessingAGCEnabled));
        if (m2) method_setImplementation(m2, imp_implementationWithBlock(^(id _s) { return NO; }));
    }

    // ④ RTCAudioProcessingConfig 兜底锁（v31 原有）：AGC1/2/NS/TS/HPF 全部锁 NO，AEC 按模式放行
    Class cfg = objc_getClass("RTCAudioProcessingConfig");
    if (cfg) {
        kp_lock_bool_prop(cfg, @"isAutoGainControl1Enabled", @"setIsAutoGainControl1Enabled:");
        kp_lock_bool_prop(cfg, @"isAutoGainControl2Enabled", @"setIsAutoGainControl2Enabled:");
        kp_lock_bool_prop(cfg, @"isNoiseSuppressionEnabled", @"setIsNoiseSuppressionEnabled:");
        kp_lock_bool_prop(cfg, @"isTransientSuppressionEnabled", @"setIsTransientSuppressionEnabled:");
        kp_lock_bool_prop(cfg, @"isHighPassFilterEnabled", @"setIsHighPassFilterEnabled:");

        Method mg = class_getInstanceMethod(cfg, @selector(isEchoCancellerEnabled));
        if (mg) {
            IMP orig = method_getImplementation(mg);
            method_setImplementation(mg, imp_implementationWithBlock(^BOOL(id _s) {
                if (g_losslessPriority || g_priorityLoud || g_shieldRemote) return NO;
                return ((BOOL (*)(id, SEL))orig)(_s, @selector(isEchoCancellerEnabled));
            }));
        }
        Method ms = class_getInstanceMethod(cfg, @selector(setIsEchoCancellerEnabled:));
        if (ms) {
            IMP orig = method_getImplementation(ms);
            method_setImplementation(ms, imp_implementationWithBlock(^(id _s, BOOL en) {
                BOOL v = (g_losslessPriority || g_priorityLoud || g_shieldRemote) ? NO : en;
                ((void (*)(id, SEL, BOOL))orig)(_s, @selector(setIsEchoCancellerEnabled:), v);
            }));
        }
    }

    // ⑤ AVAudioSession setMode 兜底改写（v31 原有）
    Class avs = objc_getClass("AVAudioSession");
    if (avs) {
        Method m = class_getInstanceMethod(avs, @selector(setMode:error:));
        if (m && !kp_orig_av_setMode) {
            kp_orig_av_setMode = (BOOL (*)(id, SEL, NSString *, NSError **))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_hook_av_setMode);
        }
    }

    // ⑥ AVAudioInputNode 平台 AGC 锁（v31 原有）
    Class ion = objc_getClass("AVAudioInputNode");
    if (ion) {
        Method m1 = class_getInstanceMethod(ion, @selector(setVoiceProcessingAGCEnabled:));
        if (m1) method_setImplementation(m1, imp_implementationWithBlock(^(id _s, BOOL en) { (void)en; }));
        Method m2 = class_getInstanceMethod(ion, @selector(isVoiceProcessingAGCEnabled));
        if (m2) method_setImplementation(m2, imp_implementationWithBlock(^(id _s) { return NO; }));
    }
}

// 克制 SDP 补丁：单声道 48k + 禁用静音断流 + 开启带内抗丢包；码率顺应服务端分配
static id (*kp_orig_init_sdp)(id, SEL, NSInteger, NSString *) = NULL;

static NSString *kp_sdp_patch(NSString *sdp) {
    if (![sdp containsString:@"opus/48000"]) return sdp;
    NSString *sep = [sdp containsString:@"\r\n"] ? @"\r\n" : @"\n";
    NSMutableArray<NSString *> *lines = [[sdp componentsSeparatedByString:sep] mutableCopy];

    NSString *pt = nil;
    NSUInteger rtpmapIdx = NSNotFound;
    for (NSUInteger i = 0; i < lines.count; i++) {
        NSString *ln = lines[i];
        if (![ln hasPrefix:@"a=rtpmap:"] || [ln rangeOfString:@"opus/48000"].location == NSNotFound) continue;
        NSRange sp = [ln rangeOfString:@" "];
        if (sp.location != NSNotFound && sp.location > 9) {
            pt = [ln substringWithRange:NSMakeRange(9, sp.location - 9)];
            rtpmapIdx = i;
            break;
        }
    }
    if (pt.length == 0) pt = @"111";

    BOOL changed = NO, hitFmtp = NO;
    NSString *fkey = [NSString stringWithFormat:@"a=fmtp:%@", pt];

    for (NSUInteger i = 0; i < lines.count; i++) {
        NSString *ln = lines[i];
        if (![ln hasPrefix:fkey]) continue;
        if (ln.length > fkey.length && [ln characterAtIndex:fkey.length] != ' ') continue;

        NSString *rest = (ln.length > fkey.length) ? [ln substringFromIndex:fkey.length] : @"";
        NSMutableArray<NSString *> *keep = [NSMutableArray array];
        for (NSString *kv in [rest componentsSeparatedByString:@";"]) {
            NSString *t = [kv stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (t.length == 0) continue;
            if ([t hasPrefix:@"stereo="] || [t hasPrefix:@"sprop-stereo="] ||
                [t hasPrefix:@"usedtx="] || [t hasPrefix:@"useinbandfec="] ||
                [t hasPrefix:@"maxplaybackrate="] || [t hasPrefix:@"sprop-maxcapturerate="]) continue;
            [keep addObject:t];
        }
        [keep addObject:@"stereo=0"];
        [keep addObject:@"sprop-stereo=0"];
        [keep addObject:@"maxplaybackrate=48000"];
        [keep addObject:@"sprop-maxcapturerate=48000"];
        [keep addObject:@"usedtx=0"];
        [keep addObject:@"useinbandfec=1"];
        lines[i] = [NSString stringWithFormat:@"%@ %@", fkey, [keep componentsJoinedByString:@";"]];
        hitFmtp = YES;
        changed = YES;
        break;
    }

    if (!hitFmtp && rtpmapIdx != NSNotFound) {
        NSString *nf = [NSString stringWithFormat:@"%@ stereo=0;sprop-stereo=0;maxplaybackrate=48000;sprop-maxcapturerate=48000;usedtx=0;useinbandfec=1", fkey];
        [lines insertObject:nf atIndex:rtpmapIdx + 1];
        changed = YES;
    }
    return changed ? [lines componentsJoinedByString:sep] : sdp;
}

static id kp_hook_init_sdp(id self, SEL _cmd, NSInteger type, NSString *sdp) {
    NSString *patched = sdp;
    @try {
        if (sdp.length) {
            NSString *p = kp_sdp_patch(sdp);
            if ([p containsString:@"m=audio"] && [p containsString:@"opus/48000"]) patched = p;
        }
    } @catch (NSException *e) { patched = sdp; }
    return kp_orig_init_sdp(self, _cmd, type, patched);
}

static void kp_setup_sdp_hook(void) {
    Class cls = objc_getClass("RTCSessionDescription");
    Method m = cls ? class_getInstanceMethod(cls, @selector(initWithType:sdp:)) : NULL;
    if (m && !kp_orig_init_sdp) {
        kp_orig_init_sdp = (id (*)(id, SEL, NSInteger, NSString *))method_getImplementation(m);
        method_setImplementation(m, (IMP)kp_hook_init_sdp);
    }
}

static BOOL kp_senderHooked = NO;
static void (*kp_orig_setParamsCH)(id, SEL, id, void (^)(NSError *)) = NULL;
static void (*kp_orig_setParams)(id, SEL, id) = NULL;

static void kp_lock_send_params(id params) {
    if (!params) return;
    id encs = nil;
    @try { encs = [params valueForKey:@"encodings"]; } @catch (NSException *e) { return; }
    if (![encs isKindOfClass:[NSArray class]]) return;
    for (id enc in encs) {
        @try { [enc setValue:@(4) forKey:@"networkPriority"]; } @catch (NSException *e) {}
        @try { [enc setValue:@(1) forKey:@"priority"]; } @catch (NSException *e) {}
    }
}

static void kp_hook_setParamsCH(id self, SEL _cmd, id params, void (^handler)(NSError *)) {
    kp_lock_send_params(params);
    if (kp_orig_setParamsCH) kp_orig_setParamsCH(self, _cmd, params, handler);
}

static void kp_hook_setParams(id self, SEL _cmd, id params) {
    kp_lock_send_params(params);
    if (kp_orig_setParams) kp_orig_setParams(self, _cmd, params);
}

static void kp_setup_sender_hook(void) {
    if (kp_senderHooked) return;
    Class cls = objc_getClass("RTCRtpSender");
    if (!cls) return;
    Method m1 = class_getInstanceMethod(cls, @selector(setParameters:completionHandler:));
    if (m1) {
        kp_orig_setParamsCH = (void (*)(id, SEL, id, void (^)(NSError *)))method_getImplementation(m1);
        method_setImplementation(m1, (IMP)kp_hook_setParamsCH);
    }
    Method m2 = class_getInstanceMethod(cls, @selector(setParameters:));
    if (m2) {
        kp_orig_setParams = (void (*)(id, SEL, id))method_getImplementation(m2);
        method_setImplementation(m2, (IMP)kp_hook_setParams);
    }
    if (m1 || m2) kp_senderHooked = YES;
}

// 本地远端屏蔽护盾
static BOOL kp_shieldHooked = NO;
static id   (*kp_orig_recv_track)(id, SEL) = NULL;
static void (*kp_orig_recv_setTrack)(id, SEL, id) = NULL;
static BOOL (*kp_orig_mst_isEnabled)(id, SEL) = NULL;
static void (*kp_orig_mst_setEnabled)(id, SEL, BOOL) = NULL;
static void (*kp_orig_aud_setEnabled)(id, SEL, BOOL) = NULL;

static void kp_shield_note_track(id t) {
    if (!t) return;
    if (!g_shieldTracks) g_shieldTracks = [NSMutableArray array];
    @synchronized (g_shieldTracks) {
        if (![g_shieldTracks containsObject:t]) {
            [g_shieldTracks addObject:t];
            if (g_shieldTracks.count > 24) [g_shieldTracks removeObjectAtIndex:0];
        }
    }
    if (g_shieldRemote) kp_shield_apply();
}

static void kp_shield_set_volume(id t, float v) {
    @try {
        id src = [t valueForKey:@"source"];
        SEL s = NSSelectorFromString(@"setVolume:");
        if (src && [src respondsToSelector:s]) {
            ((void (*)(id, SEL, double))objc_msgSend)(src, s, (double)v);
        }
    } @catch (NSException *e) {}
}

static int kp_shield_level(void) {
    if (!g_shieldRemote) return 0;
    return g_shieldLowOnly ? 1 : 2;
}

static void kp_shield_apply(void) {
    if (!g_shieldTracks) return;
    int lv = kp_shield_level();
    NSArray *snapshot = nil;
    @synchronized (g_shieldTracks) { snapshot = [g_shieldTracks copy]; }
    for (id t in snapshot) {
        @try {
            BOOL en = (lv != 2);
            [t setValue:@(en) forKey:@"isEnabled"];
            kp_shield_set_volume(t, lv == 1 ? 0.2f : (lv == 2 ? 0.0f : 1.0f));
        } @catch (NSException *e) {}
    }
}

static id kp_hook_recv_track(id self, SEL _cmd) {
    id t = kp_orig_recv_track ? kp_orig_recv_track(self, _cmd) : nil;
    kp_shield_note_track(t);
    return t;
}

static void kp_hook_recv_setTrack(id self, SEL _cmd, id t) {
    kp_shield_note_track(t);
    if (kp_orig_recv_setTrack) kp_orig_recv_setTrack(self, _cmd, t);
}

static BOOL kp_hook_mst_isEnabled(id self, SEL _cmd) {
    if (g_shieldRemote && !g_shieldLowOnly && g_shieldTracks && [g_shieldTracks containsObject:self]) return NO;
    return kp_orig_mst_isEnabled ? kp_orig_mst_isEnabled(self, _cmd) : YES;
}

static void kp_hook_mst_setEnabled(id self, SEL _cmd, BOOL en) {
    if (g_shieldRemote && !g_shieldLowOnly && g_shieldTracks && [g_shieldTracks containsObject:self]) en = NO;
    if (kp_orig_mst_setEnabled) kp_orig_mst_setEnabled(self, _cmd, en);
}

static void kp_hook_aud_setEnabled(id self, SEL _cmd, BOOL en) {
    if (g_shieldRemote && !g_shieldLowOnly && g_shieldTracks && [g_shieldTracks containsObject:self]) en = NO;
    if (kp_orig_aud_setEnabled) kp_orig_aud_setEnabled(self, _cmd, en);
}

static void kp_setup_shield_hook(void) {
    if (kp_shieldHooked) return;
    Class recv = objc_getClass("RTCRtpReceiver");
    Class mst  = objc_getClass("RTCMediaStreamTrack");
    Class aud  = objc_getClass("RTCAudioTrack");
    if (!recv && !mst && !aud) return;

    BOOL ok = NO;
    if (recv) {
        Method m1 = class_getInstanceMethod(recv, @selector(track));
        Method m2 = class_getInstanceMethod(recv, @selector(setTrack:));
        if (m1) { kp_orig_recv_track = (id (*)(id, SEL))method_getImplementation(m1); method_setImplementation(m1, (IMP)kp_hook_recv_track); ok = YES; }
        if (m2) { kp_orig_recv_setTrack = (void (*)(id, SEL, id))method_getImplementation(m2); method_setImplementation(m2, (IMP)kp_hook_recv_setTrack); ok = YES; }
    }
    Class eCls = mst ?: aud;
    if (eCls) {
        Method g = class_getInstanceMethod(eCls, @selector(isEnabled));
        Method s = class_getInstanceMethod(eCls, @selector(setIsEnabled:));
        if (g) { kp_orig_mst_isEnabled = (BOOL (*)(id, SEL))method_getImplementation(g); method_setImplementation(g, (IMP)kp_hook_mst_isEnabled); ok = YES; }
        if (s) { kp_orig_mst_setEnabled = (void (*)(id, SEL, BOOL))method_getImplementation(s); method_setImplementation(s, (IMP)kp_hook_mst_setEnabled); ok = YES; }
    }
    if (aud) {
        Method s2 = class_getInstanceMethod(aud, @selector(setEnabled:));
        if (s2) { kp_orig_aud_setEnabled = (void (*)(id, SEL, BOOL))method_getImplementation(s2); method_setImplementation(s2, (IMP)kp_hook_aud_setEnabled); ok = YES; }
    }
    if (ok) kp_shieldHooked = YES;
}

// KAKA 放行与混音观测 Hook
static BOOL kp_kakaAllowHooked = NO;
static BOOL (*kp_orig_capAllow)(id, SEL) = NULL;
static void (*kp_orig_setCapAllow)(id, SEL, BOOL) = NULL;
static BOOL (*kp_orig_musicAllow)(id, SEL) = NULL;
static void (*kp_orig_setMusicAllow)(id, SEL, BOOL) = NULL;
static void (*kp_orig_mixProc)(id, SEL, int16_t *, unsigned long long, unsigned long long, double) = NULL;
static _Atomic long g_mixProcCalls = 0;

static BOOL kp_hook_capAllow(id self, SEL _cmd) {
    if (g_losslessPriority) return YES;
    return kp_orig_capAllow ? kp_orig_capAllow(self, _cmd) : YES;
}

static void kp_hook_setCapAllow(id self, SEL _cmd, BOOL v) {
    if (g_losslessPriority) v = YES;
    if (kp_orig_setCapAllow) kp_orig_setCapAllow(self, _cmd, v);
}

static BOOL kp_hook_musicAllow(id self, SEL _cmd) {
    if (g_losslessPriority) return YES;
    return kp_orig_musicAllow ? kp_orig_musicAllow(self, _cmd) : YES;
}

static void kp_hook_setMusicAllow(id self, SEL _cmd, BOOL v) {
    if (g_losslessPriority) v = YES;
    if (kp_orig_setMusicAllow) kp_orig_setMusicAllow(self, _cmd, v);
}

// 台下采集心跳计数（kp_hook_mixProc 在下方使用，需先声明）
static _Atomic long g_usCapTicks = 0;

static void kp_hook_mixProc(id self, SEL _cmd, int16_t *pcm, unsigned long long frames,
                            unsigned long long chs, double rate) {
    long n = ++g_mixProcCalls;

    // v31.6 台下采集心跳：understage 开启时确认本地采集推流仍在跑（~250 次回调打一条）
    if (g_understageEnabled) {
        long c = ++g_usCapTicks;
        if (c % 250 == 1) {
            kp_log(@"[understage-diag] capture alive ticks=%ld understage=ON mixcalls=%ld", c, n);
        }
    }

    // v31.3：mixProcessedPCM: 是 KAKA 1.2.4 真实的每秒最终上行出口（probe-m + 日志实证），
    // 直接在这里接管处理（全链 DSP + BGM/音效混音 + tanhf 软限幅写入 pcm 缓冲区）
    if (g_dspEnabled && pcm && frames > 0) {
        if (rate >= 8000.0 && rate <= 96000.0 && fabsf((float)rate - g_sampleRate) > 10.0f) {
            g_sampleRate = (float)rate;
            kp_rebuild_filter_bank();
        }
        kp_process_pcm(pcm, (UInt32)frames, (UInt32)(chs > 0 ? chs : 1), YES);
    }

    // v31.4：处理完之后放行给原方法，恢复本地耳返监听（_monitor/_musicMonitor 路由）
    // 满血音频既发给全房，也回放到自己耳机；对端响度不受影响
    if (kp_orig_mixProc) {
        kp_orig_mixProc(self, _cmd, pcm, frames, chs, rate);
    }

    // 统计并打印真实输出电平（处理后）
    static double lastT = 0;
    static int peak = 0;
    static double sumSq = 0;
    static long samples = 0;
    if (pcm && frames > 0) {
        unsigned long long total = frames * (chs > 0 ? chs : 1);
        for (unsigned long long i = 0; i < total; i++) {
            int a = pcm[i] < 0 ? -(int)pcm[i] : (int)pcm[i];
            int p = (int)((a * 100) / 32768);
            if (p > peak) peak = p;
            double f = (double)pcm[i] / 32768.0;
            sumSq += f * f;
            samples++;
        }
    }
    double now = CACurrentMediaTime();
    if (lastT == 0) { lastT = now; return; }
    if (now - lastT >= 5.0) {
        double rms = (samples > 0) ? sqrt(sumSq / (double)samples) : 0.0;
        double db  = 20.0 * log10(rms > 1e-9 ? rms : 1e-9);
        kp_log(@"[KV-MIX-TAKEOVER] calls=%ld frames=%llu ch=%llu outPeak=%d%% outRMS=%.1fdB",
               n, frames, chs, peak, db);
        lastT = now; peak = 0; sumSq = 0; samples = 0;
    }
}

// ==========================================
// v31.5 台下开麦（Understage）：强开采集投递 + 强解本地静音
// 报告 13.3 节 / 附录 C.3：roomCaptureGateEnabled=NO / roomCaptureDeliveryAllowed=YES，
// RTCAudioDeviceModule setMicrophoneMuted: 与 RTCDefaultAudioProcessingModule setMuted: 强制 NO。
// 默认关闭，防止平时闭麦/离麦时"热麦"把环境音传出去。
// ==========================================
static BOOL (*orig_us_capGate)(id, SEL) = NULL;
static void (*orig_us_setCapGate)(id, SEL, BOOL) = NULL;
static BOOL (*orig_us_capAllow)(id, SEL) = NULL;
static void (*orig_us_setCapAllow)(id, SEL, BOOL) = NULL;
static void (*orig_us_setMicMuted)(id, SEL, BOOL) = NULL;
static void (*orig_us_setApmMuted)(id, SEL, BOOL) = NULL;

// v31.6 台下状态诊断日志（节流打印，避免刷爆 rack.log）
static double g_usLastLogTime = 0.0;

static void kp_us_log_throttled(NSString *msg) {
    double now = CACurrentMediaTime();
    if (now - g_usLastLogTime >= 1.5) {
        g_usLastLogTime = now;
        kp_log(@"[understage-diag] %@", msg);
    }
}

static BOOL kp_us_hook_capGate(id self, SEL _cmd) {
    if (g_understageEnabled) return NO;
    return orig_us_capGate ? orig_us_capGate(self, _cmd) : NO;
}

static void kp_us_hook_setCapGate(id self, SEL _cmd, BOOL en) {
    if (en) {
        kp_us_log_throttled([NSString stringWithFormat:@"拦截 setRoomCaptureGateEnabled:YES -> understage=%d", (int)g_understageEnabled]);
    }
    BOOL target = g_understageEnabled ? NO : en;
    if (orig_us_setCapGate) orig_us_setCapGate(self, _cmd, target);
}

static BOOL kp_us_hook_capAllow(id self, SEL _cmd) {
    if (g_understageEnabled) return YES;
    return orig_us_capAllow ? orig_us_capAllow(self, _cmd) : YES;
}

static void kp_us_hook_setCapAllow(id self, SEL _cmd, BOOL allow) {
    if (!allow) {
        kp_us_log_throttled([NSString stringWithFormat:@"拦截 setRoomCaptureDeliveryAllowed:NO -> understage=%d", (int)g_understageEnabled]);
    }
    BOOL target = g_understageEnabled ? YES : allow;
    if (orig_us_setCapAllow) orig_us_setCapAllow(self, _cmd, target);
}

static void kp_us_hook_setMicMuted(id self, SEL _cmd, BOOL muted) {
    if (muted) {
        kp_us_log_throttled([NSString stringWithFormat:@"拦截 setMicrophoneMuted:YES -> understage=%d", (int)g_understageEnabled]);
    }
    BOOL target = g_understageEnabled ? NO : muted;
    if (orig_us_setMicMuted) orig_us_setMicMuted(self, _cmd, target);
}

static void kp_us_hook_setApmMuted(id self, SEL _cmd, BOOL muted) {
    if (muted) {
        kp_us_log_throttled([NSString stringWithFormat:@"拦截 setMuted:YES -> understage=%d", (int)g_understageEnabled]);
    }
    BOOL target = g_understageEnabled ? NO : muted;
    if (orig_us_setApmMuted) orig_us_setApmMuted(self, _cmd, target);
}

static void kp_setup_understage_hooks(void) {
    Class dev = objc_getClass("KakaStereoAudioDevice");
    if (dev) {
        Method m1 = class_getInstanceMethod(dev, @selector(roomCaptureGateEnabled));
        if (m1 && !orig_us_capGate) {
            orig_us_capGate = (BOOL (*)(id, SEL))method_getImplementation(m1);
            method_setImplementation(m1, (IMP)kp_us_hook_capGate);
        }
        Method m2 = class_getInstanceMethod(dev, @selector(setRoomCaptureGateEnabled:));
        if (m2 && !orig_us_setCapGate) {
            orig_us_setCapGate = (void (*)(id, SEL, BOOL))method_getImplementation(m2);
            method_setImplementation(m2, (IMP)kp_us_hook_setCapGate);
        }
        Method m3 = class_getInstanceMethod(dev, @selector(roomCaptureDeliveryAllowed));
        if (m3 && !orig_us_capAllow) {
            orig_us_capAllow = (BOOL (*)(id, SEL))method_getImplementation(m3);
            method_setImplementation(m3, (IMP)kp_us_hook_capAllow);
        }
        Method m4 = class_getInstanceMethod(dev, @selector(setRoomCaptureDeliveryAllowed:));
        if (m4 && !orig_us_setCapAllow) {
            orig_us_setCapAllow = (void (*)(id, SEL, BOOL))method_getImplementation(m4);
            method_setImplementation(m4, (IMP)kp_us_hook_setCapAllow);
        }
    }

    Class adm = objc_getClass("RTCAudioDeviceModule");
    if (adm) {
        SEL sMicMute = NSSelectorFromString(@"setMicrophoneMuted:");
        Method mMute = class_getInstanceMethod(adm, sMicMute);
        if (mMute && !orig_us_setMicMuted) {
            orig_us_setMicMuted = (void (*)(id, SEL, BOOL))method_getImplementation(mMute);
            method_setImplementation(mMute, (IMP)kp_us_hook_setMicMuted);
        }
    }

    Class apm = objc_getClass("RTCDefaultAudioProcessingModule");
    if (apm) {
        SEL sApmMute = NSSelectorFromString(@"setMuted:");
        Method mApmMute = class_getInstanceMethod(apm, sApmMute);
        if (mApmMute && !orig_us_setApmMuted) {
            orig_us_setApmMuted = (void (*)(id, SEL, BOOL))method_getImplementation(mApmMute);
            method_setImplementation(mApmMute, (IMP)kp_us_hook_setApmMuted);
        }
    }
}

static void kp_setup_kaka_allow_hooks(void) {
    if (kp_kakaAllowHooked) return;
    Class dev = objc_getClass("KakaStereoAudioDevice");
    Class mix = objc_getClass("KakaAudioMixer");
    if (!dev && !mix) return;

    BOOL ok = NO;
    if (dev) {
        Method g = class_getInstanceMethod(dev, @selector(roomCaptureDeliveryAllowed));
        Method s = class_getInstanceMethod(dev, @selector(setRoomCaptureDeliveryAllowed:));
        if (g) { kp_orig_capAllow = (BOOL (*)(id, SEL))method_getImplementation(g); method_setImplementation(g, (IMP)kp_hook_capAllow); ok = YES; }
        if (s) { kp_orig_setCapAllow = (void (*)(id, SEL, BOOL))method_getImplementation(s); method_setImplementation(s, (IMP)kp_hook_setCapAllow); ok = YES; }
    }
    if (mix) {
        Method g = class_getInstanceMethod(mix, @selector(roomMusicAllowed));
        Method s = class_getInstanceMethod(mix, @selector(setRoomMusicAllowed:));
        Method mp = class_getInstanceMethod(mix, @selector(mixProcessedPCM:frames:channels:rate:));
        if (g) { kp_orig_musicAllow = (BOOL (*)(id, SEL))method_getImplementation(g); method_setImplementation(g, (IMP)kp_hook_musicAllow); ok = YES; }
        if (s) { kp_orig_setMusicAllow = (void (*)(id, SEL, BOOL))method_getImplementation(s); method_setImplementation(s, (IMP)kp_hook_setMusicAllow); ok = YES; }
        if (mp) { kp_orig_mixProc = (void (*)(id, SEL, int16_t *, unsigned long long, unsigned long long, double))method_getImplementation(mp); method_setImplementation(mp, (IMP)kp_hook_mixProc); ok = YES; }
    }
    if (ok) kp_kakaAllowHooked = YES;
}

// ==========================================
// v31.7 台下开麦信令层：WebSocket 发送改写（muted:true -> false）
// 13.5 判定表确认本地已放行、卡在信令层后，拦截
// NSURLSessionWebSocketTask sendMessage:completionHandler:，
// 当 g_understageEnabled == YES 且消息是 Janus JSON 时，
// 原地把 "muted":true（含带空格变体）改写为 "muted":false 再发出。
// ==========================================
static void (*orig_ws_sendMsg)(id, SEL, NSURLSessionWebSocketMessage *, void (^)(NSError *)) = NULL;

static void kp_hook_ws_sendMsg(id self, SEL _cmd, NSURLSessionWebSocketMessage *message, void (^completionHandler)(NSError *)) {
    NSURLSessionWebSocketMessage *outMsg = message;
    if (g_understageEnabled && message && message.type == NSURLSessionWebSocketMessageTypeString && message.string.length > 0) {
        NSString *s = message.string;
        if ([s containsString:@"\"janus\""] && ([s containsString:@"\"muted\":true"] || [s containsString:@"\"muted\": true"])) {
            NSString *rewritten = [[s stringByReplacingOccurrencesOfString:@"\"muted\":true" withString:@"\"muted\":false"]
                                      stringByReplacingOccurrencesOfString:@"\"muted\": true" withString:@"\"muted\":false"];
            outMsg = [[NSURLSessionWebSocketMessage alloc] initWithString:rewritten];
            kp_log(@"[understage-ws] 已改写信令 muted:true -> false");
        }
    }
    if (message && message.type == NSURLSessionWebSocketMessageTypeString && message.string.length > 0) {
        kp_pk_ws_tx_probe(self, message.string);
    }
    if (orig_ws_sendMsg) {
        orig_ws_sendMsg(self, _cmd, outMsg, completionHandler);
    }
}

static void kp_setup_ws_unmute_hook(void) {
    Class wsCls = objc_getClass("__NSURLSessionWebSocketTask");
    if (!wsCls) wsCls = objc_getClass("NSURLSessionWebSocketTask");
    if (wsCls) {
        SEL sel = @selector(sendMessage:completionHandler:);
        Method m = class_getInstanceMethod(wsCls, sel);
        if (m && !orig_ws_sendMsg) {
            orig_ws_sendMsg = (void (*)(id, SEL, NSURLSessionWebSocketMessage *, void (^)(NSError *)))method_getImplementation(m);
            method_setImplementation(m, (IMP)kp_hook_ws_sendMsg);
            kp_log(@"[understage-ws] WebSocket 信令钩子已挂载");
        }
    }
}

// ==========================================
// v31.9 三路监听：WebRTC 通道统计 + WebSocket 下行信令 + 挂载器
// ==========================================

// 定时拉取 WebRTC 底层统计：上行/下行包数、丢包、抖动、audioLevel
static void kp_poll_rtc_stats(void) {
    if (!g_roomMonitorEnabled || !g_allPeerConns) return;
    NSArray *pcs = [g_allPeerConns allObjects];
    SEL statSel = NSSelectorFromString(@"statisticsWithCompletionHandler:");

    for (id pc in pcs) {
        if (![pc respondsToSelector:statSel]) continue;
        @try {
            void (^cb)(id) = ^(id report) {
                if (!report) return;
                @try {
                    NSDictionary *stats = [report valueForKey:@"statistics"];
                    if (![stats isKindOfClass:[NSDictionary class]]) return;

                    NSMutableString *line = [NSMutableString stringWithFormat:@"[RTC-STATS pc=%p] ", pc];
                    BOOL hasInfo = NO;

                    for (id key in stats) {
                        id st = stats[key];
                        NSString *type = [st valueForKey:@"type"];
                        NSDictionary *vals = [st valueForKey:@"values"];
                        if (![vals isKindOfClass:[NSDictionary class]]) continue;

                        if ([type isEqualToString:@"outbound-rtp"]) {
                            [line appendFormat:@"TX(pkts=%@ bytes=%@) ",
                             vals[@"packetsSent"] ?: @"0", vals[@"bytesSent"] ?: @"0"];
                            hasInfo = YES;
                        } else if ([type isEqualToString:@"media-source"]) {
                            if (vals[@"audioLevel"]) {
                                double lvl = [vals[@"audioLevel"] doubleValue];
                                [line appendFormat:@"MIC-LVL=%.0f%% ", lvl * 100.0];
                                hasInfo = YES;
                            }
                        } else if ([type isEqualToString:@"inbound-rtp"]) {
                            double lvl = vals[@"audioLevel"] ? [vals[@"audioLevel"] doubleValue] : 0.0;
                            [line appendFormat:@"RX(pkts=%@ lost=%@ lvl=%.0f%%) ",
                             vals[@"packetsReceived"] ?: @"0",
                             vals[@"packetsLost"] ?: @"0",
                             lvl * 100.0];
                            hasInfo = YES;
                        }
                    }
                    if (hasInfo) kp_log(@"%@", line);
                } @catch (NSException *e) {}
            };
            ((void (*)(id, SEL, id))objc_msgSend)(pc, statSel, cb);
        } @catch (NSException *e) {}
    }
}

// 拦截 WebSocket 收包：打印 Janus 房间号、成员列表、谁在说话、谁被静音
static void (*orig_ws_recvMsg)(id, SEL, void (^)(NSURLSessionWebSocketMessage *, NSError *)) = NULL;
static void kp_hook_ws_recvMsg(id self, SEL _cmd, void (^completionHandler)(NSURLSessionWebSocketMessage *, NSError *)) {
    void (^wrapped)(NSURLSessionWebSocketMessage *, NSError *) = ^(NSURLSessionWebSocketMessage *msg, NSError *err) {
        if (g_roomMonitorEnabled && !err && msg && msg.type == NSURLSessionWebSocketMessageTypeString && msg.string.length > 0) {
            NSString *s = msg.string;
            // 只抓取房间事件、成员、说话状态、静音、音量相关消息，过滤心跳
            if ([s containsString:@"audiobridge"] || [s containsString:@"participants"] ||
                [s containsString:@"talking"] || [s containsString:@"muted"] || [s containsString:@"volume"]) {
                NSString *clip = s.length > 360 ? [[s substringToIndex:360] stringByAppendingString:@"..."] : s;
                kp_log(@"[ROOM-WS-RX] %@", clip);
            }
        }
        if (!err && msg && msg.type == NSURLSessionWebSocketMessageTypeString && msg.string.length > 0) {
            kp_pk_ws_rx_probe(self, msg.string);
        }
        if (completionHandler) completionHandler(msg, err);
    };
    if (orig_ws_recvMsg) orig_ws_recvMsg(self, _cmd, wrapped);
}

static void kp_setup_room_monitor_hooks(void) {
    if (!g_renderMon) g_renderMon = [[KPRenderMonitorProcessor alloc] init];

    // 1. 挂载房间下行混音监听（链式不破坏官方播放）
    Class apmCls = objc_getClass("RTCDefaultAudioProcessingModule");
    if (apmCls) {
        SEL setRenSel = NSSelectorFromString(@"setRenderPreProcessingDelegate:");
        Method mRen = class_getInstanceMethod(apmCls, setRenSel);
        if (mRen) {
            static BOOL hookedRen = NO;
            if (!hookedRen) {
                hookedRen = YES;
                IMP origRen = method_getImplementation(mRen);
                method_setImplementation(mRen, imp_implementationWithBlock(^(id _s, id del) {
                    if (del && del != (id)g_renderMon) g_origRenderDel = del;
                    ((void (*)(id, SEL, id))origRen)(_s, setRenSel, g_renderMon);
                }));
            }
        }
    }

    // 2. 捕获活跃的 RTCPeerConnection，用于每 5 秒拉取 RTP 通道统计
    Class facCls = objc_getClass("RTCPeerConnectionFactory");
    if (facCls) {
        SEL pcSel = NSSelectorFromString(@"peerConnectionWithConfiguration:constraints:delegate:");
        Method mPc = class_getInstanceMethod(facCls, pcSel);
        if (mPc) {
            static BOOL hookedPc = NO;
            if (!hookedPc) {
                hookedPc = YES;
                IMP origPc = method_getImplementation(mPc);
                method_setImplementation(mPc, imp_implementationWithBlock(^id(id _s, id cfg, id cons, id del) {
                    id pc = ((id (*)(id, SEL, id, id, id))origPc)(_s, pcSel, cfg, cons, del);
                    g_rtcFactory = _s;
                    if (!g_allPeerConns) g_allPeerConns = [NSHashTable weakObjectsHashTable];
                    if (pc) [g_allPeerConns addObject:pc];
                    kp_log(@"[ROOM-MON] 已记录 RTCPeerConnection=%p (总数=%lu)", pc, (unsigned long)g_allPeerConns.count);
                    return pc;
                }));
            }
        }
    }

    // 3. 监听 WebSocket 下行房间信令
    Class wsCls = objc_getClass("__NSURLSessionWebSocketTask");
    if (!wsCls) wsCls = objc_getClass("NSURLSessionWebSocketTask");
    if (wsCls) {
        SEL recvSel = @selector(receiveMessageWithCompletionHandler:);
        Method mRecv = class_getInstanceMethod(wsCls, recvSel);
        if (mRecv && !orig_ws_recvMsg) {
            orig_ws_recvMsg = (void (*)(id, SEL, void (^)(NSURLSessionWebSocketMessage *, NSError *)))method_getImplementation(mRecv);
            method_setImplementation(mRecv, (IMP)kp_hook_ws_recvMsg);
        }
    }

    // 4. 启动每 5 秒一次的 RTP 通道统计定时器
    static dispatch_source_t statsTimer = nil;
    if (!statsTimer) {
        statsTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
        dispatch_source_set_timer(statsTimer, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), 5 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
        dispatch_source_set_event_handler(statsTimer, ^{
            kp_poll_rtc_stats();
        });
        dispatch_resume(statsTimer);
    }
}

// ==========================================
// v34 PK 网关探测（依据 deliver/PK网关越权发布逆向与验证.md）
// 官方 PK 接收端 = RecvOnly + 无本地音轨 + 不发 configure。
// 本模块纯观测，不改官方行为；三条判据全部写进 rack.log：
//   1) 本地 offer / 远端 answer 的 m=audio 方向（recvonly / sendrecv）
//   2) answer 里 a=ssrc 行数
//   3) PK 连接上是否出现 addTrack（本地音轨挂载）
// 捕获到原生 WS 的 join 帧时，额外记录 ticket / configure 回包。
// ==========================================
static NSMapTable *g_pkPCState = nil;    // PC -> {isPK,lastOffer,lastAnswer}
static NSMapTable *g_pkWSTasks = nil;    // ws task -> {url,ticket,configureSent}

// 提取 SDP 里 m=audio 段的方向与 a=ssrc 行数
static NSString *kp_pk_audio_summary(NSString *sdp, NSString **outMline, int *outSsrc) {
    if (![sdp isKindOfClass:[NSString class]] || sdp.length == 0) return @"none";
    NSArray<NSString *> *lines = [sdp componentsSeparatedByString:@"\n"];
    BOOL inAudio = NO;
    NSString *dir = @"none", *mline = @"";
    int ssrc = 0;
    for (NSString *raw in lines) {
        NSString *l = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([l hasPrefix:@"m=audio"]) { inAudio = YES; mline = l; continue; }
        if (inAudio && [l hasPrefix:@"m="]) break;
        if (!inAudio) continue;
        if ([l hasPrefix:@"a=recvonly"])       dir = @"recvonly";
        else if ([l hasPrefix:@"a=sendrecv"])  dir = @"sendrecv";
        else if ([l hasPrefix:@"a=sendonly"])  dir = @"sendonly";
        else if ([l hasPrefix:@"a=inactive"])  dir = @"inactive";
        else if ([l hasPrefix:@"a=ssrc:"])     ssrc++;
    }
    if (outMline) *outMline = mline;
    if (outSsrc)  *outSsrc = ssrc;
    return dir;
}

static NSMutableDictionary *kp_pk_state(id pc, BOOL create) {
    if (!g_pkPCState) {
        g_pkPCState = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsWeakMemory
                                             valueOptions:NSPointerFunctionsStrongMemory];
    }
    NSMutableDictionary *st = [g_pkPCState objectForKey:pc];
    if (!st && create) {
        st = [NSMutableDictionary dictionary];
        [g_pkPCState setObject:st forKey:pc];
    }
    return st;
}

static NSString *kp_pk_desc_sdp(id desc) {
    if (!desc) return nil;
    @try {
        id v = [desc valueForKey:@"sdp"];
        if ([v isKindOfClass:[NSString class]]) return v;
    } @catch (NSException *e) {}
    return nil;
}

static void (*orig_pk_setLocal)(id, SEL, id, void (^)(NSError *))  = NULL;
static void (*orig_pk_setRemote)(id, SEL, id, void (^)(NSError *)) = NULL;
static id   (*orig_pk_addTrack)(id, SEL, id, void (^)(NSError *))  = NULL;

static void kp_hook_pk_setLocal(id self, SEL _cmd, id desc, void (^handler)(NSError *)) {
    if (g_pkProbeEnabled) {
        @try {
            NSString *sdp = kp_pk_desc_sdp(desc);
            NSString *ml = @""; int ssrc = 0;
            NSString *dir = kp_pk_audio_summary(sdp, &ml, &ssrc);
            NSMutableDictionary *st = kp_pk_state(self, YES);
            BOOL pk = [st[@"isPK"] boolValue];
            if ([dir isEqualToString:@"recvonly"] && !pk) {
                pk = YES;
                st[@"isPK"] = @YES;
                kp_log(@"[PK-PROBE] ★ 本地 offer audio=recvonly → 判定为 PK 接收端 pc=%p", self);
                kp_log(@"[PK-PROBE] offer m-line=%@", (ml.length > 140 ? [ml substringToIndex:140] : ml));
                kp_log(@"[PK-PROBE] 官方语义确认：只收不发（无本地音轨 / 不发 configure）");
            }
            BOOL changed = ![st[@"lastOffer"] isEqualToString:dir];
            if (pk || changed) {
                st[@"lastOffer"] = dir ?: @"none";
                kp_log(@"[PK-PROBE] 本地 offer audio=%@ ssrc行=%d pk=%d", dir, ssrc, pk ? 1 : 0);
            }
        } @catch (NSException *e) {}
    }
    if (orig_pk_setLocal) orig_pk_setLocal(self, _cmd, desc, handler);
}

static void kp_hook_pk_setRemote(id self, SEL _cmd, id desc, void (^handler)(NSError *)) {
    if (g_pkProbeEnabled) {
        @try {
            NSString *sdp = kp_pk_desc_sdp(desc);
            NSString *ml = @""; int ssrc = 0;
            NSString *dir = kp_pk_audio_summary(sdp, &ml, &ssrc);
            NSMutableDictionary *st = kp_pk_state(self, YES);
            BOOL pk = [st[@"isPK"] boolValue];
            BOOL changed = ![st[@"lastAnswer"] isEqualToString:dir];
            if (pk || changed) {
                st[@"lastAnswer"] = dir ?: @"none";
                kp_log(@"[PK-PROBE] 远端 answer audio=%@ ssrc行=%d pk=%d", dir, ssrc, pk ? 1 : 0);
                if (pk && [dir isEqualToString:@"recvonly"]) {
                    kp_log(@"[PK-PROBE] 结论A：服务端按 ticket 角色拦截，PK 仍然只能收（无越权口）");
                } else if (pk && [dir isEqualToString:@"sendrecv"]) {
                    kp_log(@"[PK-PROBE] 结论B：answer 放行 sendrecv，SDP 协商已开上行；还需 B 房听众验收");
                    if (ssrc > 0) kp_log(@"[PK-PROBE] answer 含 a=ssrc 行 %d 条（有 SSRC 不等于媒体通）", ssrc);
                } else if (pk) {
                    kp_log(@"[PK-PROBE] 结论C：answer 方向=%@，需结合 configure 回包判断", dir);
                }
            }
        } @catch (NSException *e) {}
    }
    if (orig_pk_setRemote) orig_pk_setRemote(self, _cmd, desc, handler);
}

static id kp_hook_pk_addTrack(id self, SEL _cmd, id track, void (^handler)(NSError *)) {
    if (g_pkProbeEnabled) {
        @try {
            NSMutableDictionary *st = kp_pk_state(self, NO);
            if ([st[@"isPK"] boolValue]) {
                kp_log(@"[PK-PROBE] ⚠️ PK 连接上出现 addTrack：本地音轨挂载（越权发布第一步）");
            }
        } @catch (NSException *e) {}
    }

    id ret = orig_pk_addTrack ? orig_pk_addTrack(self, _cmd, track, handler) : nil;

    // ---- v34.1 第二 SSRC：只给房间 PC 的第一条音频轨加，且全局只加一次 ----
    if (g_secondSSRC && !g_secondSSRCApplied) {
        @try {
            NSMutableDictionary *st = kp_pk_state(self, YES);
            BOOL isAudio = YES;
            @try { isAudio = [[track valueForKey:@"kind"] isEqualToString:@"audio"]; } @catch (NSException *e) {}
            if (isAudio && ![st[@"isPK"] boolValue] && ![st[@"ssrcAdded"] boolValue]) {
                id src = nil;
                NSString *oldId = nil;
                @try { src = [track valueForKey:@"source"]; } @catch (NSException *e) {}
                @try { oldId = [track valueForKey:@"trackId"]; } @catch (NSException *e) {}
                if (!src || src == [NSNull null]) src = nil;
                if (oldId.length == 0) oldId = @"audio";

                NSString *newId = [oldId stringByAppendingString:@"-ssrc2"];
                id factory = g_rtcFactory;
                id second = nil;
                SEL selSrc = NSSelectorFromString(@"audioTrackWithSource:trackId:");
                SEL selId  = NSSelectorFromString(@"audioTrackWithTrackId:");

                if (factory && src && [factory respondsToSelector:selSrc]) {
                    second = ((id (*)(id, SEL, id, id))objc_msgSend)(factory, selSrc, src, newId);
                } else if (factory && [factory respondsToSelector:selId]) {
                    second = ((id (*)(id, SEL, id))objc_msgSend)(factory, selId, newId);
                    kp_log(@"[2SSRC] 取不到原轨 source，退回 audioTrackWithTrackId（等于第二次采集，音色可能不同）");
                }

                if (second) {
                    g_secondSSRCApplied = YES;
                    st[@"ssrcAdded"] = @YES;
                    kp_log(@"[2SSRC] 同一轮协商追加第二条音频轨 id=%@（期望 offer 出现 2 个 m=audio）", newId);
                    if (orig_pk_addTrack) {
                        orig_pk_addTrack(self, _cmd, second, ^(NSError *err) {
                            kp_log(@"[2SSRC] 第二条 addTrack 完成 err=%@；看 answer 是否 2 个 m=audio 且第二条 sendrecv", err ? err.localizedDescription : @"nil");
                        });
                    }
                } else {
                    kp_log(@"[2SSRC] 第二条轨道创建失败：factory=%@ source=%@（不做静音兜底）",
                           factory ? @"ok" : @"nil", src ? @"ok" : @"nil");
                }
            }
        } @catch (NSException *e) {}
    }
    return ret;
}

// ---- 信令层：从 WS 帧里抓 PK ticket / configure 回包 ----
static NSString *kp_pk_json_str(NSString *s, NSString *key) {
    if (![s isKindOfClass:[NSString class]]) return nil;
    NSString *needle = [NSString stringWithFormat:@"\"%@\":\"", key];
    NSRange r = [s rangeOfString:needle];
    if (r.location == NSNotFound) return nil;
    NSUInteger start = r.location + r.length;
    if (start >= s.length) return nil;
    NSRange tail = [s rangeOfString:@"\"" options:0 range:NSMakeRange(start, s.length - start)];
    if (tail.location == NSNotFound) return nil;
    return [s substringWithRange:NSMakeRange(start, tail.location - start)];
}

static void kp_pk_ws_tx_probe(id task, NSString *s) {
    if (!g_pkProbeEnabled || ![s isKindOfClass:[NSString class]]) return;
    if (![s containsString:@"\"op\":\"join\""] || ![s containsString:@"ticket"]) return;
    @try {
        if (!g_pkWSTasks) {
            g_pkWSTasks = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsWeakMemory
                                                valueOptions:NSPointerFunctionsStrongMemory];
        }
        NSMutableDictionary *st = [g_pkWSTasks objectForKey:task];
        if (!st) { st = [NSMutableDictionary dictionary]; [g_pkWSTasks setObject:st forKey:task]; }

        NSString *ticket = kp_pk_json_str(s, @"ticket");
        NSString *url = nil;
        @try {
            NSURLRequest *req = [task valueForKey:@"originalRequest"];
            url = req.URL.absoluteString;
        } @catch (NSException *e) {}
        st[@"ticket"] = ticket ?: @"";
        st[@"url"] = url ?: @"";
        kp_log(@"[PK-PROBE] 捕获 PK join → gateway=%@ ticket=%.12s…(len=%lu)",
               url.length ? url : @"?", ticket.length ? ticket.UTF8String : "", (unsigned long)ticket.length);

        if (g_pkProbeActive && ![st[@"configureSent"] boolValue]) {
            st[@"configureSent"] = @YES;
            NSString *reqId = [NSString stringWithFormat:@"pkprobe-%lld",
                               (long long)([[NSDate date] timeIntervalSince1970] * 1000)];
            NSString *json = [NSString stringWithFormat:@"{\"op\":\"configure\",\"muted\":false,\"request_id\":\"%@\"}", reqId];
            kp_log(@"[PK-PROBE] 主动探测：补发 configure muted:false request_id=%@", reqId);
            id wsTask = task;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (!g_pkProbeActive) return;
                NSURLSessionWebSocketMessage *m = [[NSURLSessionWebSocketMessage alloc] initWithString:json];
                if (orig_ws_sendMsg) {
                    orig_ws_sendMsg(wsTask, @selector(sendMessage:completionHandler:), m, ^(NSError *err) {
                        kp_log(@"[PK-PROBE] configure 已发出，completion err=%@", err ? err.localizedDescription : @"nil");
                    });
                }
            });
        }
    } @catch (NSException *e) {}
}

static void kp_pk_ws_rx_probe(id task, NSString *s) {
    if (!g_pkProbeEnabled || ![s isKindOfClass:[NSString class]]) return;
    BOOL interesting = ([s containsString:@"configured"] || [s containsString:@"listen_only"] ||
                        [s containsString:@"publishing"]   || [s containsString:@"\"ready\""]   ||
                        [s containsString:@"\"error\""]     || [s containsString:@"a=sendrecv"]   ||
                        [s containsString:@"a=recvonly"]);
    if (!interesting) return;
    NSString *clip = s.length > 400 ? [[s substringToIndex:400] stringByAppendingString:@"…"] : s;
    kp_log(@"[PK-PROBE] 信令RX %@", clip);
}

static void kp_setup_pk_probe_hooks(void) {
    static BOOL hooked = NO;
    if (hooked) return;
    Class pcCls = objc_getClass("RTCPeerConnection");
    if (!pcCls) return;
    hooked = YES;

    Method m1 = class_getInstanceMethod(pcCls, NSSelectorFromString(@"setLocalDescription:completionHandler:"));
    if (m1 && !orig_pk_setLocal) {
        orig_pk_setLocal = (void (*)(id, SEL, id, void (^)(NSError *)))method_getImplementation(m1);
        method_setImplementation(m1, (IMP)kp_hook_pk_setLocal);
    }

    Method m2 = class_getInstanceMethod(pcCls, NSSelectorFromString(@"setRemoteDescription:completionHandler:"));
    if (m2 && !orig_pk_setRemote) {
        orig_pk_setRemote = (void (*)(id, SEL, id, void (^)(NSError *)))method_getImplementation(m2);
        method_setImplementation(m2, (IMP)kp_hook_pk_setRemote);
    }

    Method m3 = class_getInstanceMethod(pcCls, NSSelectorFromString(@"addTrack:completionHandler:"));
    if (m3 && !orig_pk_addTrack) {
        orig_pk_addTrack = (id (*)(id, SEL, id, void (^)(NSError *)))method_getImplementation(m3);
        method_setImplementation(m3, (IMP)kp_hook_pk_addTrack);
    }

    kp_log(@"[PK-PROBE] SDP 探针已挂载（setLocal/setRemote/addTrack），日志路径 Documents/KakaAudio/rack.log");
}

// ==========================================
// 9. 多开 Keychain 隔离（fishhook）
// ==========================================
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static NSString *g_bundleId = nil;

static NSString *kp_bundle_id(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.isolated.clone";
    });
    return g_bundleId;
}

static CFMutableDictionaryRef kp_isolate_query(CFDictionaryRef query) {
    if (!query) return NULL;
    CFMutableDictionaryRef mq = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
    if (!mq) return NULL;
    NSMutableDictionary *dict = (__bridge NSMutableDictionary *)mq;
    [dict removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
    NSString *bid = kp_bundle_id();
    id service = dict[(__bridge id)kSecAttrService];
    if ([service isKindOfClass:[NSString class]]) {
        dict[(__bridge id)kSecAttrService] = [NSString stringWithFormat:@"%@.%@", service, bid];
    }
    id account = dict[(__bridge id)kSecAttrAccount];
    if ([account isKindOfClass:[NSString class]]) {
        dict[(__bridge id)kSecAttrAccount] = [NSString stringWithFormat:@"%@.%@", account, bid];
    }
    return mq;
}

static OSStatus kp_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFMutableDictionaryRef q = kp_isolate_query(query);
    OSStatus s = orig_SecItemCopyMatching(q ?: query, result);
    if (q) CFRelease(q);
    return s;
}

static OSStatus kp_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFMutableDictionaryRef q = kp_isolate_query(attributes);
    OSStatus s = orig_SecItemAdd(q ?: attributes, result);
    if (q) CFRelease(q);
    return s;
}

static OSStatus kp_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrs) {
    CFMutableDictionaryRef q = kp_isolate_query(query);
    OSStatus s = orig_SecItemUpdate(q ?: query, attrs);
    if (q) CFRelease(q);
    return s;
}

static OSStatus kp_SecItemDelete(CFDictionaryRef query) {
    CFMutableDictionaryRef q = kp_isolate_query(query);
    OSStatus s = orig_SecItemDelete(q ?: query);
    if (q) CFRelease(q);
    return s;
}

struct rebinding { const char *name; void *replacement; void **replaced; };
extern int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

// ==========================================
// 10. 悬浮界面与全局状态同步（已移除变声页，保留 调音 / EQ / 音效 / 话术）
// ==========================================
@interface KPFloatWindowV31 : UIWindow <UIDocumentPickerDelegate>
- (void)kp_show_toast:(NSString *)text;
@end

@implementation KPFloatWindowV31

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    return (v == self) ? nil : v;
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count == 0) return;
    NSString *dir = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject]
                     stringByAppendingPathComponent:@"KakaAudio/BGM"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSMutableArray<NSString *> *imported = [NSMutableArray array];
    for (NSURL *url in urls) {
        BOOL scoped = [url startAccessingSecurityScopedResource];
        NSString *name = url.lastPathComponent;
        if (name.length) {
            NSString *dst = [dir stringByAppendingPathComponent:name];
            [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];
            if ([[NSFileManager defaultManager] copyItemAtURL:url toURL:[NSURL fileURLWithPath:dst] error:nil]) {
                [imported addObject:name];
            }
        }
        if (scoped) [url stopAccessingSecurityScopedResource];
    }

    if (imported.count == 0) {
        [self kp_show_toast:@"导入失败，换个音频格式试试"];
        return;
    }
    NSString *last = imported.lastObject;
    extern void kp_bgm_load_name(NSString *name);
    kp_bgm_load_name(last);
    [self kp_show_toast:[NSString stringWithFormat:@"已导入：%@", last]];
}

- (void)kp_show_toast:(NSString *)text {
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 260, 40)];
    l.text = text;
    l.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.86];
    l.textColor = [UIColor whiteColor];
    l.font = [UIFont systemFontOfSize:12];
    l.textAlignment = NSTextAlignmentCenter;
    l.numberOfLines = 0;
    l.layer.cornerRadius = 10;
    l.layer.masksToBounds = YES;
    l.center = CGPointMake(CGRectGetMidX(self.bounds), CGRectGetMidY(self.bounds));
    l.alpha = 0.0;
    [self addSubview:l];
    [UIView animateWithDuration:0.2 animations:^{ l.alpha = 1.0; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.3 delay:2.0 options:0 animations:^{ l.alpha = 0.0; } completion:^(BOOL d) {
            [l removeFromSuperview];
        }];
    }];
}

@end

static KPFloatWindowV31 *g_win = nil;
static UIButton         *g_ball = nil;
static UIView           *g_panel = nil;
static UIView           *g_pageRack = nil;
static UIView           *g_pageEq   = nil;
static UIView           *g_pageSound = nil;
static UIView           *g_pageClip  = nil;

static UIView           *g_vuInFill  = nil;
static UIView           *g_vuGrFill  = nil;
static UIView           *g_vuOutFill = nil;
static CGFloat           g_vuTrackW  = 84.0;

static UILabel          *g_statLabel = nil;
static UILabel          *g_bgmLabel  = nil;
static UISwitch         *g_bgmSwitch = nil;
static UISwitch         *g_topBgmSw  = nil;
static UISwitch         *g_topDuckSw = nil;
static UISwitch         *g_pageDuckSw = nil;
static UIButton         *g_topLockBtn = nil;
static UILabel          *g_clipStat  = nil;
static UIButton         *g_recBtn    = nil;
static UISwitch         *g_clipLoopSw = nil;
static NSArray<UIButton *> *g_clipBtns = nil;
static NSArray<UIButton *> *g_slotBtns = nil;
static NSArray<UIButton *> *g_tabBtns  = nil;
static int               g_clipSlotSel = 0;
static NSTimer          *g_tick = nil;

#define KP_PANEL_W  304.0f
#define KP_PANEL_H  506.0f
#define KP_PAGE_Y   120.0f
#define KP_PAGE_H   356.0f

static NSString *kp_bgm_dir(void) {
    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio/BGM"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSString *kp_bgm_path(NSString *name) {
    return [kp_bgm_dir() stringByAppendingPathComponent:name];
}

static NSArray<NSString *> *kp_bgm_files(void) {
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kp_bgm_dir() error:nil];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *f in all) {
        NSString *e = f.pathExtension.lowercaseString;
        if ([e isEqualToString:@"mp3"] || [e isEqualToString:@"m4a"] ||
            [e isEqualToString:@"wav"] || [e isEqualToString:@"caf"]) {
            [out addObject:f];
        }
    }
    return [out sortedArrayUsingSelector:@selector(localizedStandardCompare:)];
}

void kp_bgm_load_name(NSString *name) {
    if (!name.length) return;
    NSString *path = kp_bgm_path(name);
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        UInt32 n = 0;
        int16_t *buf = kp_load_audio(path, &n);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!buf || n == 0) return;
            g_bgmOn = 0;
            int16_t *old = g_bgmPcm;
            g_bgmPcm = buf;
            g_bgmLen = (int)n;
            g_bgmPos = 0;
            kp_bgm_retire(old);
            g_bgmName = name;
            [[NSUserDefaults standardUserDefaults] setObject:name forKey:KEY_BGM_NAME];
            g_bgmOn = 1;
            kp_sync_all_ui();
        });
    });
}

static void kp_bgm_delete_name(NSString *name) {
    if (!name.length) return;
    if (g_bgmName && [g_bgmName isEqualToString:name]) {
        kp_delete_bgm();
    }
    [[NSFileManager defaultManager] removeItemAtPath:kp_bgm_path(name) error:nil];
    kp_sync_all_ui();
}

static UIViewController *kp_top_vc(void) {
    UIWindow *target = nil;
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if (![sc isKindOfClass:[UIWindowScene class]]) continue;
        if (sc.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *w in ((UIWindowScene *)sc).windows) {
            if (w == g_win || w == g_licWin || !w.rootViewController) continue;
            if (w.isKeyWindow) { target = w; break; }
            if (!target) target = w;
        }
        if (target && target.isKeyWindow) break;
    }
    if (!target) {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w == g_win || w == g_licWin || !w.rootViewController) continue;
            target = w;
            break;
        }
    }
    UIViewController *vc = target.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void kp_present(UIViewController *vc) {
    UIViewController *top = kp_top_vc();
    if (!top || !vc || top.presentedViewController) return;
    [top presentViewController:vc animated:YES completion:nil];
}

static void kp_open_importer(void) {
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.audio"]
                                                              inMode:UIDocumentPickerModeImport];
    picker.delegate = g_win;
    picker.allowsMultipleSelection = YES;
    kp_present(picker);
}

static void kp_show_bgm_menu(void) {
    NSArray<NSString *> *files = kp_bgm_files();
    if (files.count == 0) { kp_open_importer(); return; }
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"选择播放伴奏" message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in files) {
        BOOL cur = (g_bgmName && [g_bgmName isEqualToString:name]);
        NSString *title = cur ? [NSString stringWithFormat:@"%@ (播放中)", name] : name;
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            kp_bgm_load_name(name);
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (g_ball) {
        sheet.popoverPresentationController.sourceView = g_ball;
        sheet.popoverPresentationController.sourceRect = g_ball.bounds;
    }
    kp_present(sheet);
}

static void kp_show_bgm_delete_menu(void) {
    NSArray<NSString *> *files = kp_bgm_files();
    if (files.count == 0) { [g_win kp_show_toast:@"还没有导入伴奏"]; return; }
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"删除伴奏" message:@"删除后无法恢复" preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in files) {
        [sheet addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"删除 %@", name]
                                                  style:UIAlertActionStyleDestructive
                                                handler:^(UIAlertAction *a) {
            kp_bgm_delete_name(name);
            [g_win kp_show_toast:[NSString stringWithFormat:@"已删除 %@", name]];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (g_ball) {
        sheet.popoverPresentationController.sourceView = g_ball;
        sheet.popoverPresentationController.sourceRect = g_ball.bounds;
    }
    kp_present(sheet);
}

static UILabel *kp_label(CGRect r, NSString *text, CGFloat size, UIColor *color, BOOL bold) {
    UILabel *l = [[UILabel alloc] initWithFrame:r];
    l.text = text;
    l.textColor = color;
    l.font = bold ? [UIFont boldSystemFontOfSize:size] : [UIFont systemFontOfSize:size];
    return l;
}

static UISwitch *kp_switch(CGRect r, BOOL on, void (^handler)(BOOL)) {
    UISwitch *sw = [[UISwitch alloc] initWithFrame:r];
    sw.on = on;
    sw.transform = CGAffineTransformMakeScale(0.85, 0.85);
    [sw addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        handler(sw.on);
    }] forControlEvents:UIControlEventValueChanged];
    return sw;
}

static UISlider *kp_slider(CGRect r, float min, float max, float val, void (^handler)(float)) {
    UISlider *s = [[UISlider alloc] initWithFrame:r];
    s.minimumValue = min;
    s.maximumValue = max;
    s.value = val;
    [s addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        handler(s.value);
    }] forControlEvents:UIControlEventValueChanged];
    return s;
}

static void kp_haptic(void) {
    UIImpactFeedbackGenerator *fb = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
    [fb prepare];
    [fb impactOccurred];
}

static void kp_update_ball(void) {
    if (!g_ball) return;
    if (!g_dspEnabled) {
        [g_ball setTitle:@"调音:关" forState:UIControlStateNormal];
        g_ball.backgroundColor = [UIColor colorWithWhite:0.28 alpha:0.95];
        return;
    }

    BOOL anySfx = NO;
    for (int i = 0; i < SFX_SLOT; i++) if (g_sfxOn[i]) { anySfx = YES; break; }

    NSString *tag = @"";
    if (g_recOn) tag = @" 录";
    else if (g_clipOn) tag = @" 话术";
    else if (anySfx) tag = @" 音效";
    else if (g_bgmOn) tag = @" BGM";

    NSString *title = (g_pcmCalls == 0)
        ? [NSString stringWithFormat:@"%.1fx 待触发", (double)g_makeupGain]
        : [NSString stringWithFormat:@"%.1fx%s|%d", (double)g_makeupGain, tag.UTF8String, g_vuMic];
    if (g_oneTapMasterLock) title = [NSString stringWithFormat:@"锁|%@", title];

    [g_ball setTitle:title forState:UIControlStateNormal];
    g_ball.backgroundColor = (g_vuMic > 8 || anySfx || g_clipOn)
        ? [UIColor colorWithRed:0.00 green:0.70 blue:0.34 alpha:0.98]
        : [UIColor colorWithRed:0.05 green:0.46 blue:0.24 alpha:0.96];
}

static void kp_sync_all_ui(void) {
    if (g_topLockBtn) {
        BOOL on = (g_oneTapMasterLock != 0);
        [g_topLockBtn setTitle:on ? @"🔒 霸麦锁定中（点击解除）" : @"🔓 点击开启一键霸麦锁定"
                      forState:UIControlStateNormal];
        g_topLockBtn.backgroundColor = on
            ? [UIColor colorWithRed:0.15 green:0.62 blue:0.35 alpha:1.0]
            : [UIColor colorWithWhite:0.22 alpha:1.0];
    }
    if (g_topBgmSw)   g_topBgmSw.on   = (g_bgmOn != 0);
    if (g_bgmSwitch)  g_bgmSwitch.on  = (g_bgmOn != 0);
    if (g_topDuckSw)  g_topDuckSw.on  = (g_duckEnabled != 0);
    if (g_pageDuckSw) g_pageDuckSw.on = (g_duckEnabled != 0);
    kp_update_ball();
}

static void kp_toggle_master_lock(BOOL lock) {
    double now = [[NSDate date] timeIntervalSince1970];
    if (now - g_lastLockTap < 0.35) return;
    g_lastLockTap = now;
    g_oneTapMasterLock = lock;

    if (lock) {
        g_dspEnabled       = YES;
        g_losslessPriority = YES;
        g_priorityLoud     = YES;
        g_lowCutEnabled    = YES;
        g_throatEnabled    = YES;
        g_compEnabled      = YES;
        g_compThresh       = 0.15f;
        g_compRatio        = 3.2f;
        g_eq10Enabled      = YES;
        g_limiterEnabled   = YES;
        g_limiterCeiling   = 29800.0f;
        g_makeupGain       = 1.55f;
        g_shieldRemote     = YES;
        g_shieldLowOnly    = YES;
        kp_shield_apply();

        static const float masterEq[EQ10_BANDS] = {
            -5.0f, -3.0f, -1.0f, 0.5f, 1.5f, 3.5f, 4.5f, 3.0f, 1.5f, 1.0f
        };
        for (int i = 0; i < EQ10_BANDS; i++) g_eq10Gains[i] = masterEq[i];
        kp_rebuild_filter_bank();
        kp_log(@"[MASTER-LOCK] 已锁定高穿透清晰链路");
    } else {
        g_shieldRemote = NO;
        kp_shield_apply();
        kp_log(@"[MASTER-LOCK] 已解除锁定");
    }
    save_current_settings();
    kp_sync_all_ui();
}

static void kp_attach_scene(void) {
    if (!g_win) return;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            if (ws.activationState == UISceneActivationStateForegroundActive ||
                ws.activationState == UISceneActivationStateForegroundInactive) {
                g_win.windowScene = ws;
                return;
            }
        }
    }
}

static void kp_clip_refresh_ui(void) {
    for (NSInteger i = 0; g_clipBtns && i < (NSInteger)g_clipBtns.count; i++) {
        UIButton *b = g_clipBtns[i];
        BOOL has = kp_clip_exists((int)i);
        BOOL playing = (g_clipOn != 0) && (g_clipPlayingSlot == (int)i);

        if (playing) {
            [b setTitle:[NSString stringWithFormat:(g_clipLoop ? @"%ld 循环中" : @"%ld 播放中"), (long)i + 1]
               forState:UIControlStateNormal];
            b.backgroundColor = [UIColor colorWithRed:0.14 green:0.58 blue:0.33 alpha:0.98];
            [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        } else if (has) {
            [b setTitle:[NSString stringWithFormat:@"%ld 已录制", (long)i + 1] forState:UIControlStateNormal];
            b.backgroundColor = [UIColor colorWithRed:0.16 green:0.32 blue:0.46 alpha:0.98];
            [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        } else {
            [b setTitle:[NSString stringWithFormat:@"%ld 空槽位", (long)i + 1] forState:UIControlStateNormal];
            b.backgroundColor = [UIColor colorWithWhite:0.22 alpha:0.95];
            [b setTitleColor:[UIColor colorWithWhite:0.62 alpha:1.0] forState:UIControlStateNormal];
        }
    }

    for (NSInteger i = 0; g_slotBtns && i < (NSInteger)g_slotBtns.count; i++) {
        UIButton *b = g_slotBtns[i];
        BOOL sel = ((int)i == g_clipSlotSel);
        b.backgroundColor = sel ? [UIColor colorWithRed:0.68 green:0.26 blue:0.24 alpha:0.98]
                                : [UIColor colorWithWhite:0.24 alpha:0.95];
    }

    if (g_recBtn) {
        if (g_recOn) {
            int sec = (int)(g_recCount / 48000);
            [g_recBtn setTitle:[NSString stringWithFormat:@"停止并保存 %d:%02d", sec / 60, sec % 60] forState:UIControlStateNormal];
            g_recBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.62 blue:0.30 alpha:1.0];
        } else {
            [g_recBtn setTitle:[NSString stringWithFormat:@"录到槽位 %d", g_clipSlotSel + 1] forState:UIControlStateNormal];
            g_recBtn.backgroundColor = [UIColor colorWithRed:0.66 green:0.20 blue:0.20 alpha:0.98];
        }
    }

    if (g_clipStat) {
        if (g_recOn) {
            g_clipStat.text = @"录制中… 最长 60 秒";
            g_clipStat.textColor = [UIColor colorWithRed:1.0 green:0.42 blue:0.38 alpha:1.0];
        } else {
            NSMutableArray *have = [NSMutableArray array];
            for (int i = 0; i < CLIP_SLOT; i++) if (kp_clip_exists(i)) [have addObject:[NSString stringWithFormat:@"%d", i + 1]];
            g_clipStat.text = have.count ? [NSString stringWithFormat:@"已录制槽位 %@，点上方播放", [have componentsJoinedByString:@" / "]]
                                         : @"还没有录音：先选槽位再点红色按钮";
            g_clipStat.textColor = have.count ? [UIColor colorWithRed:0.30 green:0.80 blue:0.50 alpha:1.0]
                                             : [UIColor colorWithWhite:0.60 alpha:1.0];
        }
    }
}

static void kp_tick(void) {
    if (g_win && g_ball) {
        if (@available(iOS 13.0, *)) {
            if (!g_win.windowScene) kp_attach_scene();
        }
    }
    kp_update_ball();

    if (g_panel && !g_panel.hidden) {
        if (g_pageClip && !g_pageClip.hidden) kp_clip_refresh_ui();
        if (g_statLabel) {
            NSString *st = (g_hookState == 3) ? @"A+B" : ((g_hookState == 1) ? @"仅A" : ((g_hookState == 2) ? @"仅B" : @"未找类"));
            g_statLabel.text = [NSString stringWithFormat:@"%@ · %.1fkHz · A%ld B%ld",
                                st, (double)g_sampleRate / 1000.0, (long)g_pcmCalls, (long)g_mixCalls];
        }
        if (g_bgmLabel) {
            if (g_bgmLen <= 0) {
                g_bgmLabel.text = @"伴奏未导入";
                g_bgmLabel.textColor = [UIColor colorWithWhite:0.62 alpha:1.0];
            } else {
                UInt32 sec = (UInt32)(g_bgmLen / 48000);
                g_bgmLabel.text = [NSString stringWithFormat:@"%@ · %u:%02u %@",
                                   g_bgmName ?: @"已载入", sec / 60, sec % 60, g_bgmOn ? @"播放中" : @"已停止"];
                g_bgmLabel.textColor = [UIColor colorWithRed:0.25 green:0.82 blue:0.45 alpha:0.95];
            }
        }
        if (g_vuInFill) {
            g_vuInFill.frame  = CGRectMake(0, 0, g_vuTrackW * (CGFloat)g_vuIn  / 100.0f, 7);
            g_vuGrFill.frame  = CGRectMake(0, 0, g_vuTrackW * (CGFloat)g_vuGr  / 100.0f, 7);
            g_vuOutFill.frame = CGRectMake(0, 0, g_vuTrackW * (CGFloat)g_vuOut / 100.0f, 7);
            if (g_vuIn  > 0) g_vuIn  = (int)(g_vuIn  * 0.78f);
            if (g_vuGr  > 0) g_vuGr  = (int)(g_vuGr  * 0.82f);
            if (g_vuOut > 0) g_vuOut = (int)(g_vuOut * 0.78f);
        }
    } else {
        g_vuIn = g_vuGr = g_vuOut = 0;
    }

    if (g_vuMic > 0) g_vuMic = (int)(g_vuMic * 0.55f);
    if (g_vuMix > 0) g_vuMix = (int)(g_vuMix * 0.55f);
}

static UISwitch *kp_row_switch(UIView *parent, CGFloat y, CGFloat w, NSString *title, BOOL on, void (^handler)(BOOL)) {
    [parent addSubview:kp_label(CGRectMake(16, y, w - 92, 22), title, 12, [UIColor colorWithWhite:0.88 alpha:1.0], NO)];
    UISwitch *sw = kp_switch(CGRectMake(w - 62, y - 2, 50, 22), on, handler);
    [parent addSubview:sw];
    return sw;
}

static void kp_build_rack_page(CGFloat w) {
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    sv.showsVerticalScrollIndicator = YES;
    sv.alwaysBounceVertical = YES;
    sv.contentSize = CGSizeMake(w, 892);
    [g_panel addSubview:sv];
    g_pageRack = sv;

    UIView *c = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, 892)];
    [sv addSubview:c];

    UIColor *dim = [UIColor colorWithWhite:0.60 alpha:1.0];
    UIColor *sec = [UIColor colorWithRed:0.30 green:0.78 blue:0.50 alpha:1.0];
    CGFloat y = 4;

    [c addSubview:kp_label(CGRectMake(16, y, w - 32, 16), @"人声穿透与防削波", 10, sec, YES)];
    y += 22;

    kp_row_switch(c, y, w, @"电台总开关", g_dspEnabled, ^(BOOL on) { g_dspEnabled = on; save_current_settings(); kp_sync_all_ui(); });
    y += 30;
    kp_row_switch(c, y, w, @"强声穿透模式（2.2k/3.4k提亮）", g_priorityLoud, ^(BOOL on) { g_priorityLoud = on; kp_rebuild_filter_bank(); save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"高通低切（去闷响/喷麦）", g_lowCutEnabled, ^(BOOL on) { g_lowCutEnabled = on; save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"中高频人声提亮", g_throatEnabled, ^(BOOL on) { g_throatEnabled = on; save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"双向压缩（稳音量/不抬底噪）", g_compEnabled, ^(BOOL on) { g_compEnabled = on; save_current_settings(); });
    y += 28;

    UILabel *ct = kp_label(CGRectMake(16, y, 260, 14), [NSString stringWithFormat:@"压缩门限 %.2f", (double)g_compThresh], 10, dim, NO);
    [c addSubview:ct];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 0.10f, 0.75f, g_compThresh, ^(float v) {
        g_compThresh = v; ct.text = [NSString stringWithFormat:@"压缩门限 %.2f", (double)v]; save_current_settings();
    })];
    y += 36;

    UILabel *gt = kp_label(CGRectMake(16, y, 260, 14), [NSString stringWithFormat:@"总增益 %.2fx", (double)g_makeupGain], 10, dim, NO);
    [c addSubview:gt];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 1.0f, 4.0f, g_makeupGain, ^(float v) {
        g_makeupGain = v; gt.text = [NSString stringWithFormat:@"总增益 %.2fx", (double)v]; save_current_settings(); kp_update_ball();
    })];
    y += 36;

    UILabel *lt = kp_label(CGRectMake(16, y, 260, 14), [NSString stringWithFormat:@"前瞻限幅峰值 %.0f / 32767", (double)g_limiterCeiling], 10, dim, NO);
    [c addSubview:lt];
    [c addSubview:kp_slider(CGRectMake(16, y + 14, w - 32, 18), 22000.0f, 32500.0f, g_limiterCeiling, ^(float v) {
        g_limiterCeiling = v; lt.text = [NSString stringWithFormat:@"前瞻限幅峰值 %.0f / 32767", (double)v]; save_current_settings();
    })];
    y += 38;

    [c addSubview:kp_label(CGRectMake(16, y, w - 32, 16), @"混音 / 降噪旁路 / 远端屏蔽", 10, sec, YES)];
    y += 22;

    kp_row_switch(c, y, w, @"混音通道同步处理", g_mixDspEnabled, ^(BOOL on) { g_mixDspEnabled = on; save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"大厅混响", g_reverbEnabled, ^(BOOL on) { g_reverbEnabled = on; if (on) kp_reverb_reset(); save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"关系统回声/降噪/AGC", g_losslessPriority, ^(BOOL on) { g_losslessPriority = on; save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"深度旁路 VoiceChat 模式", g_deepBypassVP, ^(BOOL on) { g_deepBypassVP = on; save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"台下开麦（强开采集/解静音）", g_understageEnabled, ^(BOOL on) {
        g_understageEnabled = on;
        save_current_settings();
        kp_log(@"[understage] state=%s", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"房间与通道监听日志", g_roomMonitorEnabled, ^(BOOL on) {
        g_roomMonitorEnabled = on;
        kp_log(@"[ROOM-MON] 监听开关=%s", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"PK 网关探测（SDP/信令写日志）", g_pkProbeEnabled, ^(BOOL on) {
        g_pkProbeEnabled = on;
        save_current_settings();
        kp_log(@"[PK-PROBE] 探测开关=%s", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"PK configure 主动探测（默认关）", g_pkProbeActive, ^(BOOL on) {
        g_pkProbeActive = on;
        save_current_settings();
        kp_log(@"[PK-PROBE] 主动探测=%s（只对自己账号当前 PK 连接补发 configure）", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"只播 BGM/MP3（麦克风置零）", g_bgmOnly, ^(BOOL on) {
        g_bgmOnly = on;
        save_current_settings();
        kp_log(@"[BGMOnly] state=%s（麦克风路径置零，只留伴奏/音效）", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"第二 SSRC 实验（仅测试房）", g_secondSSRC, ^(BOOL on) {
        g_secondSSRC = on;
        if (!on) g_secondSSRCApplied = NO;
        save_current_settings();
        kp_log(@"[2SSRC] state=%s（重进房间生效；answer 只有 1 个 m=audio 就是服务端不受理）", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"智能噪声门（静音省码率/防底噪占道）", g_noiseGateEnabled, ^(BOOL on) {
        g_noiseGateEnabled = on;
        save_current_settings();
        kp_log(@"[gate] state=%s", on ? "ON" : "OFF");
    });
    y += 30;
    kp_row_switch(c, y, w, @"屏蔽他人声音（远端护盾）", g_shieldRemote, ^(BOOL on) { g_shieldRemote = on; kp_shield_apply(); save_current_settings(); });
    y += 30;
    kp_row_switch(c, y, w, @"远端压低到 20%（关则全静音）", g_shieldLowOnly, ^(BOOL on) { g_shieldLowOnly = on; kp_shield_apply(); save_current_settings(); });
    y += 34;

    g_statLabel = kp_label(CGRectMake(16, y, w - 32, 18), @"Hook:安装中...", 9, [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:0.95], NO);
    g_statLabel.textAlignment = NSTextAlignmentCenter;
    [c addSubview:g_statLabel];
}

static void kp_build_eq_page(CGFloat w) {
    UIScrollView *sv = [[UIScrollView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    sv.showsVerticalScrollIndicator = YES;
    sv.alwaysBounceVertical = YES;
    sv.hidden = YES;
    [g_panel addSubview:sv];
    g_pageEq = sv;

    CGFloat contentH = 24 + EQ10_BANDS * 42 + 40;
    sv.contentSize = CGSizeMake(w, contentH);
    UIView *c = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, contentH)];
    [sv addSubview:c];

    [c addSubview:kp_label(CGRectMake(16, 2, w - 32, 16), @"10 段 EQ（-12 dB ~ +12 dB）", 10,
                           [UIColor colorWithRed:0.30 green:0.78 blue:0.50 alpha:1.0], YES)];

    UIColor *dim = [UIColor colorWithWhite:0.60 alpha:1.0];
    NSMutableArray<UILabel *>  *valLabels = [NSMutableArray array];
    NSMutableArray<UISlider *> *sliders   = [NSMutableArray array];

    for (int i = 0; i < EQ10_BANDS; i++) {
        CGFloat y = 24 + i * 42;
        float f = kEq10Freqs[i];
        NSString *fs = (f >= 1000.0f) ? [NSString stringWithFormat:@"%.1fk", (double)(f / 1000.0f)]
                                      : [NSString stringWithFormat:@"%.0f", (double)f];
        [c addSubview:kp_label(CGRectMake(16, y + 2, 44, 16), fs, 10, dim, NO)];

        UILabel *vl = kp_label(CGRectMake(w - 60, y + 2, 44, 16),
                               [NSString stringWithFormat:@"%+.1f", (double)g_eq10Gains[i]], 10,
                               [UIColor colorWithRed:0.35 green:0.80 blue:1.0 alpha:1.0], YES);
        vl.textAlignment = NSTextAlignmentRight;
        [c addSubview:vl];
        [valLabels addObject:vl];

        UISlider *s = kp_slider(CGRectMake(62, y + 2, w - 62 - 16 - 48, 18), -12.0f, 12.0f, g_eq10Gains[i], ^(float v) {
            g_eq10Gains[i] = v;
            vl.text = [NSString stringWithFormat:@"%+.1f", (double)v];
            kp_rebuild_filter_bank();
            save_current_settings();
        });
        [c addSubview:s];
        [sliders addObject:s];
    }

    UIButton *rst = [UIButton buttonWithType:UIButtonTypeCustom];
    rst.frame = CGRectMake(16, 24 + EQ10_BANDS * 42, w - 32, 30);
    rst.layer.cornerRadius = 8;
    rst.backgroundColor = [UIColor colorWithWhite:0.22 alpha:0.95];
    [rst setTitle:@"恢复默认清晰 EQ" forState:UIControlStateNormal];
    rst.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [rst addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        static const float def[EQ10_BANDS] = { -5.0f, -3.0f, -1.0f, 0.5f, 1.5f, 3.5f, 4.5f, 3.0f, 1.5f, 1.0f };
        for (int i = 0; i < EQ10_BANDS; i++) {
            g_eq10Gains[i] = def[i];
            sliders[i].value = def[i];
            valLabels[i].text = [NSString stringWithFormat:@"%+.1f", (double)def[i]];
        }
        kp_rebuild_filter_bank();
        save_current_settings();
        kp_haptic();
    }] forControlEvents:UIControlEventTouchUpInside];
    [c addSubview:rst];
}

static void kp_build_sound_page(CGFloat w) {
    g_pageSound = [[UIView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    g_pageSound.hidden = YES;
    [g_panel addSubview:g_pageSound];

    NSArray *titles = @[@"掌声", @"笑声", @"欢呼", @"口哨"];
    for (int i = 0; i < SFX_SLOT; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + (i % 2) * ((w - 32) / 2 + 6), 6 + (i / 2) * 44, (w - 44) / 2, 38);
        b.backgroundColor = [UIColor colorWithRed:0.18 green:0.28 blue:0.36 alpha:0.95];
        b.layer.cornerRadius = 8;
        [b setTitle:titles[i] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
        int idx = i;
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) { kp_play_sfx(idx); }] forControlEvents:UIControlEventTouchUpInside];

        SEL lpSel = NSSelectorFromString([NSString stringWithFormat:@"kp_sfx_lp_%d:", idx]);
        class_addMethod([b class], lpSel, imp_implementationWithBlock(^(id _self, UILongPressGestureRecognizer *rec) {
            if (rec.state != UIGestureRecognizerStateBegan) return;
            BOOL removed = kp_reset_sfx_slot(idx);
            kp_haptic();
            [g_win kp_show_toast:removed ? @"已删除自定义音效，恢复默认" : @"当前已是默认音效"];
        }), "v@:@");
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:b action:lpSel];
        lp.minimumPressDuration = 0.5;
        [b addGestureRecognizer:lp];
        [g_pageSound addSubview:b];
    }

    UIColor *fg = [UIColor colorWithWhite:0.86 alpha:1.0];
    UILabel *sfxVolText = kp_label(CGRectMake(16, 102, 260, 16), [NSString stringWithFormat:@"音效音量 %.0f%%", (double)(g_sfxVolume * 100)], 10, [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:sfxVolText];
    [g_pageSound addSubview:kp_slider(CGRectMake(16, 118, w - 32, 18), 0.0f, 1.0f, g_sfxVolume, ^(float v) {
        g_sfxVolume = v; sfxVolText.text = [NSString stringWithFormat:@"音效音量 %.0f%%", (double)(v * 100)]; save_current_settings();
    })];

    [g_pageSound addSubview:kp_label(CGRectMake(16, 148, 140, 22), @"伴奏 BGM 开关", 12, fg, NO)];
    g_bgmSwitch = kp_switch(CGRectMake(w - 62, 146, 50, 22), (g_bgmOn != 0), ^(BOOL on) {
        if (on && g_bgmLen == 0) {
            NSString *pick = g_bgmName.length ? g_bgmName : kp_bgm_files().firstObject;
            if (pick) { kp_bgm_load_name(pick); return; }
            g_bgmOn = 0;
            kp_sync_all_ui();
            [g_win kp_show_toast:@"还没有伴奏，先点导入"];
            return;
        }
        g_bgmOn = on ? 1 : 0;
        kp_sync_all_ui();
    });
    [g_pageSound addSubview:g_bgmSwitch];

    g_bgmLabel = kp_label(CGRectMake(16, 174, w - 32, 16), @"伴奏未导入", 10, [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:g_bgmLabel];

    CGFloat bw3 = (w - 44) / 3.0f;
    UIButton *importBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    importBtn.frame = CGRectMake(16, 196, bw3, 34);
    importBtn.backgroundColor = [UIColor colorWithRed:0.15 green:0.45 blue:0.85 alpha:0.95];
    importBtn.layer.cornerRadius = 8;
    [importBtn setTitle:@"导入" forState:UIControlStateNormal];
    importBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [importBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) { kp_open_importer(); }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageSound addSubview:importBtn];

    UIButton *switchBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    switchBtn.frame = CGRectMake(16 + bw3 + 6, 196, bw3, 34);
    switchBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.58 blue:0.34 alpha:0.95];
    switchBtn.layer.cornerRadius = 8;
    [switchBtn setTitle:@"切换" forState:UIControlStateNormal];
    switchBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [switchBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) { kp_show_bgm_menu(); }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageSound addSubview:switchBtn];

    UIButton *deleteBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    deleteBtn.frame = CGRectMake(16 + (bw3 + 6) * 2, 196, bw3, 34);
    deleteBtn.backgroundColor = [UIColor colorWithRed:0.72 green:0.18 blue:0.18 alpha:0.95];
    deleteBtn.layer.cornerRadius = 8;
    [deleteBtn setTitle:@"删除" forState:UIControlStateNormal];
    deleteBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    [deleteBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) { kp_show_bgm_delete_menu(); }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageSound addSubview:deleteBtn];

    [g_pageSound addSubview:kp_label(CGRectMake(16, 238, 200, 22), @"说话自动闪避 BGM", 12, fg, NO)];
    g_pageDuckSw = kp_switch(CGRectMake(w - 62, 236, 50, 22), (g_duckEnabled != 0), ^(BOOL on) {
        g_duckEnabled = on;
        save_current_settings();
        kp_sync_all_ui();
    });
    [g_pageSound addSubview:g_pageDuckSw];

    UILabel *bgmVolText = kp_label(CGRectMake(16, 268, 260, 16), [NSString stringWithFormat:@"伴奏音量 %.0f%%", (double)(g_bgmVolume * 100)], 10, [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:bgmVolText];
    [g_pageSound addSubview:kp_slider(CGRectMake(16, 284, w - 32, 18), 0.0f, 2.0f, g_bgmVolume, ^(float v) {
        g_bgmVolume = v; bgmVolText.text = [NSString stringWithFormat:@"伴奏音量 %.0f%%", (double)(v * 100)]; save_current_settings();
    })];

    UILabel *duckFloorText = kp_label(CGRectMake(16, 306, 260, 16), [NSString stringWithFormat:@"闪避保留音量 %.0f%%", (double)(g_bgmDuckFloor * 100)], 10, [UIColor colorWithWhite:0.62 alpha:1.0], NO);
    [g_pageSound addSubview:duckFloorText];
    [g_pageSound addSubview:kp_slider(CGRectMake(16, 322, w - 32, 18), 0.05f, 0.70f, g_bgmDuckFloor, ^(float v) {
        g_bgmDuckFloor = v; duckFloorText.text = [NSString stringWithFormat:@"闪避保留音量 %.0f%%", (double)(v * 100)]; save_current_settings();
    })];
}

static void kp_build_clip_page(CGFloat w) {
    UIColor *dim = [UIColor colorWithWhite:0.55 alpha:1.0];
    g_pageClip = [[UIView alloc] initWithFrame:CGRectMake(0, KP_PAGE_Y, w, KP_PAGE_H)];
    g_pageClip.hidden = YES;
    [g_panel addSubview:g_pageClip];

    [g_pageClip addSubview:kp_label(CGRectMake(16, 0, w - 32, 16), @"录好的话术会走统一限幅总线播出去", 10, dim, NO)];

    NSMutableArray *clipBtns = [NSMutableArray array];
    for (int i = 0; i < CLIP_SLOT; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + (i % 2) * 136, 20 + (i / 2) * 44, 130, 38);
        b.layer.cornerRadius = 8;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            kp_haptic(); kp_clip_play((int)i); kp_clip_refresh_ui();
        }] forControlEvents:UIControlEventTouchUpInside];

        SEL lpSel = NSSelectorFromString([NSString stringWithFormat:@"kpClipLpV31_%d:", i]);
        class_addMethod([b class], lpSel, imp_implementationWithBlock(^(id _self, UILongPressGestureRecognizer *gr) {
            if (gr.state != UIGestureRecognizerStateBegan || !kp_clip_exists(i)) return;
            kp_clip_delete(i); kp_haptic(); kp_clip_refresh_ui();
            [g_win kp_show_toast:[NSString stringWithFormat:@"已删除槽位 %d", i + 1]];
        }), "v@:@");
        [b addGestureRecognizer:[[UILongPressGestureRecognizer alloc] initWithTarget:b action:lpSel]];
        [g_pageClip addSubview:b];
        [clipBtns addObject:b];
    }
    g_clipBtns = clipBtns;

    [g_pageClip addSubview:kp_label(CGRectMake(16, 112, w - 32, 16), @"录制到槽位", 10, dim, NO)];
    NSMutableArray *slotBtns = [NSMutableArray array];
    CGFloat slotW = (w - 32 - 18) / 4.0f;
    for (int i = 0; i < CLIP_SLOT; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(16 + i * (slotW + 6), 130, slotW, 28);
        b.layer.cornerRadius = 7;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [b setTitle:[NSString stringWithFormat:@"%d", i + 1] forState:UIControlStateNormal];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            if (g_recOn) return;
            g_clipSlotSel = (int)i; kp_haptic(); kp_clip_refresh_ui();
        }] forControlEvents:UIControlEventTouchUpInside];
        [g_pageClip addSubview:b];
        [slotBtns addObject:b];
    }
    g_slotBtns = slotBtns;

    g_recBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    g_recBtn.frame = CGRectMake(16, 168, w - 32, 40);
    g_recBtn.layer.cornerRadius = 9;
    g_recBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    [g_recBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [g_recBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        if (g_recOn) {
            BOOL ok = kp_rec_stop();
            kp_haptic();
            [g_win kp_show_toast:ok ? @"已保存" : @"录音太短未保存"];
        } else {
            if (g_pcmCalls == 0) { [g_win kp_show_toast:@"请先上麦再录音"]; return; }
            kp_rec_start(g_clipSlotSel);
            kp_haptic();
        }
        kp_clip_refresh_ui();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_pageClip addSubview:g_recBtn];

    [g_pageClip addSubview:kp_label(CGRectMake(16, 214, 200, 20), @"循环播放当前话术", 11, [UIColor colorWithWhite:0.85 alpha:1.0], NO)];
    g_clipLoopSw = kp_switch(CGRectMake(w - 62, 212, 50, 22), (g_clipLoop != 0), ^(BOOL on) {
        g_clipLoop = on; save_current_settings(); kp_clip_refresh_ui();
    });
    [g_pageClip addSubview:g_clipLoopSw];

    g_clipStat = kp_label(CGRectMake(16, 244, w - 32, 30), @"", 10, dim, NO);
    g_clipStat.numberOfLines = 2;
    g_clipStat.textAlignment = NSTextAlignmentCenter;
    [g_pageClip addSubview:g_clipStat];

    kp_clip_refresh_ui();
}

static void kp_select_tab(NSInteger idx) {
    g_pageRack.hidden  = (idx != 0);
    g_pageEq.hidden    = (idx != 1);
    g_pageSound.hidden = (idx != 2);
    g_pageClip.hidden  = (idx != 3);

    for (UIButton *b in g_tabBtns) {
        BOOL sel = (b.tag == idx);
        b.backgroundColor = sel ? [UIColor colorWithRed:0.15 green:0.60 blue:0.34 alpha:1.0]
                                : [UIColor colorWithRed:0.20 green:0.20 blue:0.24 alpha:1.0];
        [b setTitleColor:sel ? [UIColor whiteColor] : [UIColor colorWithWhite:0.80 alpha:1.0] forState:UIControlStateNormal];
    }
}

static void kp_build_panel(void) {
    CGFloat w = KP_PANEL_W, h = KP_PANEL_H;
    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;

    g_panel = [[UIView alloc] initWithFrame:CGRectMake((sw - w) / 2, (sh - h) / 2, w, h)];
    g_panel.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.97];
    g_panel.layer.cornerRadius = 16;
    g_panel.layer.borderWidth = 1.0;
    g_panel.layer.borderColor = [UIColor colorWithWhite:0.34 alpha:0.85].CGColor;
    g_panel.hidden = YES;

    NSArray<NSString *> *titles = @[@"调音", @"EQ", @"音效", @"话术"];
    NSMutableArray *btns = [NSMutableArray array];
    CGFloat btnW = 54, btnH = 30, gap = 5, x = 10;
    for (NSUInteger i = 0; i < titles.count; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(x + (CGFloat)i * (btnW + gap), 8, btnW, btnH);
        b.tag = (NSInteger)i;
        b.layer.cornerRadius = 7;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [b setTitle:titles[i] forState:UIControlStateNormal];
        [b addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) { kp_select_tab(b.tag); }] forControlEvents:UIControlEventTouchUpInside];
        [g_panel addSubview:b];
        [btns addObject:b];
    }
    g_tabBtns = btns;

    UIButton *close = [UIButton buttonWithType:UIButtonTypeCustom];
    close.frame = CGRectMake(w - 40, 8, 32, 30);
    [close setTitle:@"✕" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
    [close addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        g_panel.hidden = YES;
        save_current_settings();
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:close];

    NSArray<NSString *> *vuNames = @[@"IN", @"GR", @"OUT"];
    UIColor *vuColors[3] = {
        [UIColor colorWithRed:0.22 green:0.82 blue:0.42 alpha:1.0],
        [UIColor colorWithRed:0.98 green:0.68 blue:0.20 alpha:1.0],
        [UIColor colorWithRed:0.28 green:0.62 blue:1.00 alpha:1.0]
    };
    CGFloat vuW = (w - 32 - 16) / 3.0f;
    g_vuTrackW = vuW;
    for (int i = 0; i < 3; i++) {
        CGFloat vx = 16 + i * (vuW + 8);
        [g_panel addSubview:kp_label(CGRectMake(vx, 40, vuW, 12), vuNames[i], 8.5, [UIColor colorWithWhite:0.55 alpha:1.0], YES)];
        UIView *track = [[UIView alloc] initWithFrame:CGRectMake(vx, 53, vuW, 7)];
        track.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.13];
        track.layer.cornerRadius = 3.5;
        track.layer.masksToBounds = YES;
        UIView *fill = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 0, 7)];
        fill.backgroundColor = vuColors[i];
        fill.layer.cornerRadius = 3.5;
        fill.layer.masksToBounds = YES;
        [track addSubview:fill];
        [g_panel addSubview:track];
        if (i == 0)      g_vuInFill  = fill;
        else if (i == 1) g_vuGrFill  = fill;
        else             g_vuOutFill = fill;
    }

    UIButton *lockBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    lockBtn.frame = CGRectMake(16, 63, w - 32, 24);
    lockBtn.layer.cornerRadius = 6;
    lockBtn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    g_topLockBtn = lockBtn;
    [lockBtn addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
        kp_toggle_master_lock(!(g_oneTapMasterLock != 0));
    }] forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:lockBtn];

    UIColor *qfg = [UIColor colorWithWhite:0.74 alpha:1.0];
    [g_panel addSubview:kp_label(CGRectMake(16, 93, 56, 18), @"🎵 BGM", 10, qfg, YES)];
    g_topBgmSw = kp_switch(CGRectMake(72, 90, 46, 22), (g_bgmOn != 0), ^(BOOL on) {
        if (on && g_bgmLen == 0) {
            NSString *pick = g_bgmName.length ? g_bgmName : kp_bgm_files().firstObject;
            if (pick) { kp_bgm_load_name(pick); return; }
            g_bgmOn = 0; kp_sync_all_ui(); [g_win kp_show_toast:@"还没有伴奏，先点导入"]; return;
        }
        g_bgmOn = on ? 1 : 0;
        kp_sync_all_ui();
    });
    [g_panel addSubview:g_topBgmSw];

    [g_panel addSubview:kp_label(CGRectMake(154, 93, 72, 18), @"说话闪避", 10, qfg, NO)];
    g_topDuckSw = kp_switch(CGRectMake(w - 62, 90, 46, 22), (g_duckEnabled != 0), ^(BOOL on) {
        g_duckEnabled = on;
        save_current_settings();
        kp_sync_all_ui();
    });
    [g_panel addSubview:g_topDuckSw];

    kp_build_rack_page(w);
    kp_build_eq_page(w);
    kp_build_sound_page(w);
    kp_build_clip_page(w);

    CGFloat barH = 17;
    g_licBar = [UIButton buttonWithType:UIButtonTypeCustom];
    g_licBar.frame = CGRectMake(10, h - barH - 3, w - 20, barH);
    g_licBar.layer.cornerRadius = 5;
    g_licBar.titleLabel.font = [UIFont systemFontOfSize:9];
    [g_licBar addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) { kp_lic_show_alert(); }] forControlEvents:UIControlEventTouchUpInside];
    [g_panel addSubview:g_licBar];
    kp_lic_refresh_bar();

    kp_select_tab(0);
    kp_sync_all_ui();
    [g_win addSubview:g_panel];
}

static void kp_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSString *dir = [kp_documents_path() stringByAppendingPathComponent:@"KakaAudio"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *path = [dir stringByAppendingPathComponent:@"rack.log"];
    NSString *line = [NSString stringWithFormat:@"[%.2f] %@\n", [NSDate date].timeIntervalSince1970, msg];

    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

static void kp_build_ui(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_win) return;
        load_saved_settings();
        kp_reverb_reset();
        kp_load_sfx_library();

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            NSString *name = g_bgmName;
            if (!name.length) return;
            NSString *p = kp_bgm_path(name);
            if (![[NSFileManager defaultManager] fileExistsAtPath:p]) return;
            UInt32 n = 0;
            int16_t *buf = kp_load_audio(p, &n);
            if (!buf || n == 0) return;
            dispatch_async(dispatch_get_main_queue(), ^{
                if (g_bgmLen > 0) { free(buf); return; }
                g_bgmPcm = buf;
                g_bgmLen = (int)n;
                g_bgmPos = 0;
            });
        });

        g_win = [[KPFloatWindowV31 alloc] initWithFrame:[UIScreen mainScreen].bounds];
        kp_attach_scene();
        g_win.windowLevel = UIWindowLevelAlert + 100;
        g_win.backgroundColor = [UIColor clearColor];
        g_win.hidden = NO;

        g_ball = [UIButton buttonWithType:UIButtonTypeCustom];
        g_ball.frame = CGRectMake(16, 160, 150, 36);
        g_ball.layer.cornerRadius = 18;
        g_ball.layer.masksToBounds = YES;
        g_ball.layer.borderWidth = 1.2;
        g_ball.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.75].CGColor;
        g_ball.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        [g_ball setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [g_ball addAction:[UIAction actionWithHandler:^(__kindof UIAction * _Nonnull action) {
            if (g_panel) g_panel.hidden = !g_panel.hidden;
        }] forControlEvents:UIControlEventTouchUpInside];

        SEL panSel = NSSelectorFromString(@"kp_pan_v31:");
        class_addMethod([g_ball class], panSel, imp_implementationWithBlock(^(id _self, UIPanGestureRecognizer *pan) {
            UIView *v = pan.view;
            CGPoint t = [pan translationInView:v.superview];
            v.center = CGPointMake(v.center.x + t.x, v.center.y + t.y);
            [pan setTranslation:CGPointZero inView:v.superview];
        }), "v@:@");
        [g_ball addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:g_ball action:panSel]];
        [g_win addSubview:g_ball];

        kp_build_panel();
        kp_tick();
        g_tick = [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer *_Nonnull t) { kp_tick(); }];
    });
}

// ==========================================
// 11. 入口
// ==========================================
__attribute__((constructor)) static void kp_entry(void) {
    load_saved_settings();
    kp_lic_load();
    kp_disable_agc();
    kp_eq_init();
    // v31.1：官方 SDP 已带 stereo=1;sprop-stereo=1;maxaveragebitrate=（报告 2.3 节证实），
    // 放行官方 SDP 即可，不再自行改写（避免与网关对抗触发重协商）
    // kp_setup_sdp_hook();
    kp_setup_sender_hook();
    kp_setup_shield_hook();
    kp_setup_kaka_allow_hooks();
    kp_setup_understage_hooks();
    kp_setup_ws_unmute_hook();
    kp_setup_room_monitor_hooks();
    kp_setup_pk_probe_hooks();
    kp_reverb_reset();
    kp_lim_reset();

    struct rebinding rebinds[] = {
        {"SecItemCopyMatching", (void *)kp_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemAdd",          (void *)kp_SecItemAdd,          (void **)&orig_SecItemAdd},
        {"SecItemUpdate",       (void *)kp_SecItemUpdate,       (void **)&orig_SecItemUpdate},
        {"SecItemDelete",       (void *)kp_SecItemDelete,       (void **)&orig_SecItemDelete},
    };
    rebind_symbols(rebinds, sizeof(rebinds) / sizeof(rebinds[0]));

    dispatch_async(dispatch_get_main_queue(), ^{
        kp_log(@"dylib loaded %@", KP_VERSION);
        __block int tries = 0;
        [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *_Nonnull timer) {
            int s = kp_install_hooks();
            if (s != g_hookState) kp_log(@"hooks state -> %d", s);
            g_hookState = s;
            kp_setup_sender_hook();
            kp_setup_shield_hook();
            kp_setup_kaka_allow_hooks();
            kp_setup_understage_hooks();   // 防类晚加载，定时补挂
            kp_setup_pk_probe_hooks();
            kp_shield_apply();
            if ((s == 3 && kp_senderHooked && kp_shieldHooked && kp_kakaAllowHooked) || ++tries > 90) {
                [timer invalidate];
            }
        }];

        [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *_Nonnull timer) {
            if (g_shieldRemote) kp_shield_apply();
        }];
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        kp_build_ui();
    });
}
