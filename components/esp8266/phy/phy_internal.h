// Copyright 2026 Adam5Wu (ESP8266_RTOS_SDK OSS contributors)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "esp_attr.h"
#include "phy_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * External SDK & Mask ROM Symbols Consumed by OSS PHY
 * -------------------------------------------------------------------------- */

extern void vPortETSIntrLock(void);
extern void vPortETSIntrUnlock(void);
extern void vPortEnterCritical(void);
extern void vPortExitCritical(void);
extern void Cache_Read_Disable(void);
extern void Cache_Read_Enable_New(void);
extern void ets_delay_us(uint32_t us);
extern void os_delay_us(uint16_t us);
extern void ets_update_cpu_frequency(uint32_t ticks_per_us);
extern void gpio_output_set(uint32_t set_mask, uint32_t clear_mask,
                            uint32_t enable_mask, uint32_t disable_mask);
extern void Uart_Init(uint32_t uart_no);
extern void uart_buff_switch(uint8_t uart_no);

/* --------------------------------------------------------------------------
 * Calibration & Runtime State Flags (phy_sleep_params_t::param_flag)
 * -------------------------------------------------------------------------- */

#define PHY_PARAM_RX_GAIN_VALID         BIT(16)
#define PHY_PARAM_TXIQ_VALID            BIT(17)
#define PHY_PARAM_TXCAP_VALID           BIT(18)
#define PHY_PARAM_TXDC_VALID            BIT(19)
#define PHY_PARAM_TX_PWCTRL_VALID       BIT(20)
#define PHY_PARAM_NOISE_VALID           BIT(21)
#define PHY_PARAM_VDD33_APPLIED         BIT(22)
#define PHY_PARAM_RCCAL_VALID           BIT(23)
#define PHY_PARAM_BOOT_DONE             BIT(25)
#define PHY_PARAM_WAKEUP_RF             BIT(27)
#define PHY_PARAM_TX_SLOPE_WARN         BIT(29)
#define PHY_PARAM_BBPLL160_DONE         BIT(30)

#define PHY_RTC_CHUNK1_BYTES            84U
#define PHY_RTC_CHUNK2_OFFSET           0x54U
#define PHY_RTC_CHUNK2_BYTES            12U
#define PHY_VER_1167_0_WORD             0x048F0000U

/* --------------------------------------------------------------------------
 * ABI-Locked RTC Calibration Parameters (96 B: W0..W23 @ 0x60001000..0x105F)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint32_t param_flag;                /* +0x00 (W0) */
    uint16_t txdc[4];                   /* +0x04 (W1..W2) */
    int16_t  tx_pwr_backoff[4];         /* +0x0C (W3..W4) */
    uint16_t txiq;                      /* +0x14 (W5 lo) */
    uint16_t rxiq[5];                   /* +0x16 (W5 hi..W7) */
    uint8_t  txcap[4][3];               /* +0x20 (W8..W10) */
    uint8_t  rx_filt_dcap;              /* +0x2C (W11 b0) */
    uint8_t  tx_filt_dcap;              /* +0x2D (W11 b1) */
    int16_t  rx_noise;                  /* +0x2E (W11 hi) */
    uint8_t  cur_chan;                  /* +0x30 (W12 b0) */
    int8_t   fcc_edge_atten;            /* +0x31 (W12 b1) */
    int8_t   target_power_vdd[6];       /* +0x32 (W12..W13) */
    int8_t   tx_pwctrl_atten[4][6];     /* +0x38 (W14..W19) */
    int16_t  pwctrl_err_accum;          /* +0x50 (W20 lo) */
    uint8_t  fcc_active;                /* +0x52 (W20 b2) */
    int8_t   dpd_atten_off;             /* +0x53 (W20 b3) -- end of Chunk 1 */
    uint32_t vdd33_tsen_off;            /* +0x54 (W21) -- start of Chunk 2 */
    int16_t  loop_noisefloor;           /* +0x58 (W22 lo) */
    uint16_t rf_ana_gain;               /* +0x5A (W22 hi) */
    int8_t   coatt;                     /* +0x5C (W23 b0) */
    int8_t   tot_p;                     /* +0x5D (W23 b1) */
    int8_t   periodic_delta;            /* +0x5E (W23 b2) */
    uint8_t  pad;                       /* +0x5F (W23 b3) -- end of Chunk 2 */
} phy_sleep_params_t;

_Static_assert(sizeof(phy_sleep_params_t) == 96U, "phy_sleep_params_t must be 96 bytes");
_Static_assert(offsetof(phy_sleep_params_t, param_flag) == 0x00U, "param_flag offset");
_Static_assert(offsetof(phy_sleep_params_t, txdc) == 0x04U, "txdc offset");
_Static_assert(offsetof(phy_sleep_params_t, tx_pwr_backoff) == 0x0CU, "tx_pwr_backoff offset");
_Static_assert(offsetof(phy_sleep_params_t, txiq) == 0x14U, "txiq offset");
_Static_assert(offsetof(phy_sleep_params_t, rxiq) == 0x16U, "rxiq offset");
_Static_assert(offsetof(phy_sleep_params_t, txcap) == 0x20U, "txcap offset");
_Static_assert(offsetof(phy_sleep_params_t, rx_filt_dcap) == 0x2CU, "rx_filt_dcap offset");
_Static_assert(offsetof(phy_sleep_params_t, tx_filt_dcap) == 0x2DU, "tx_filt_dcap offset");
_Static_assert(offsetof(phy_sleep_params_t, rx_noise) == 0x2EU, "rx_noise offset");
_Static_assert(offsetof(phy_sleep_params_t, cur_chan) == 0x30U, "cur_chan offset");
_Static_assert(offsetof(phy_sleep_params_t, fcc_edge_atten) == 0x31U, "fcc_edge_atten offset");
_Static_assert(offsetof(phy_sleep_params_t, target_power_vdd) == 0x32U, "target_power_vdd offset");
_Static_assert(offsetof(phy_sleep_params_t, tx_pwctrl_atten) == 0x38U, "tx_pwctrl_atten offset");
_Static_assert(offsetof(phy_sleep_params_t, pwctrl_err_accum) == 0x50U, "pwctrl_err_accum offset");
_Static_assert(offsetof(phy_sleep_params_t, fcc_active) == 0x52U, "fcc_active offset");
_Static_assert(offsetof(phy_sleep_params_t, dpd_atten_off) == 0x53U, "dpd_atten_off offset");
_Static_assert(offsetof(phy_sleep_params_t, vdd33_tsen_off) == 0x54U, "vdd33_tsen_off offset");
_Static_assert(offsetof(phy_sleep_params_t, loop_noisefloor) == 0x58U, "loop_noisefloor offset");
_Static_assert(offsetof(phy_sleep_params_t, rf_ana_gain) == 0x5AU, "rf_ana_gain offset");
_Static_assert(offsetof(phy_sleep_params_t, coatt) == 0x5CU, "coatt offset");
_Static_assert(offsetof(phy_sleep_params_t, tot_p) == 0x5DU, "tot_p offset");
_Static_assert(offsetof(phy_sleep_params_t, periodic_delta) == 0x5EU, "periodic_delta offset");

/* --------------------------------------------------------------------------
 * ABI-Locked g_phyFuns Dispatch Table (280 B = 70 Slots)
 * -------------------------------------------------------------------------- */

typedef struct {
    void *slots_lo[36];
    uint8_t (*rom_i2c_readReg)(uint8_t block, uint8_t host_id, uint8_t reg_add);
    uint8_t (*rom_i2c_readReg_Mask)(uint8_t block, uint8_t host_id, uint8_t reg_add,
                                    uint8_t msb, uint8_t lsb);
    void (*rom_i2c_writeReg)(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data);
    void (*rom_i2c_writeReg_Mask)(uint8_t block, uint8_t host_id, uint8_t reg_add,
                                  uint8_t msb, uint8_t lsb, uint8_t data);
    void *slots_hi[30];
} esp_phy_funs_t;

_Static_assert(sizeof(esp_phy_funs_t) == 280U, "esp_phy_funs_t must be 280 bytes");
_Static_assert(offsetof(esp_phy_funs_t, rom_i2c_readReg) == 0x90U,
               "esp_phy_funs_t::rom_i2c_readReg must be at offset 0x90");
_Static_assert(offsetof(esp_phy_funs_t, rom_i2c_writeReg) == 0x98U,
               "esp_phy_funs_t::rom_i2c_writeReg must be at offset 0x98");

/* --------------------------------------------------------------------------
 * Exported Globals (Explicitly Initialized in Owning .c — 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

/* phy_i2c_pbus.c */
extern const esp_phy_funs_t *g_phyFuns;

/* phy_adc.c */
extern unsigned int adc_rand_noise;

/* phy_sleep.c */
extern uint8_t sleep_wake_bbpll;
extern uint8_t software_slp_reject;
extern uint8_t hardware_reject;

/* phy_soc.c */
extern uint8_t chip6_phy_init_ctrl[80];

/* phy_core.c */
extern uint32_t *phy_rx_gain_dc_table;

/* --------------------------------------------------------------------------
 * Internal Cross-TU Globals (Explicitly Initialized in Owning .c)
 * -------------------------------------------------------------------------- */

/* phy_soc.c */
extern uint8_t g_phy_sleep_mode_flag;
extern uint8_t g_phy_wakeup_rf_flag;

/* phy_core.c */
extern phy_sleep_params_t g_phy_sleep_params;
extern uint8_t g_phy_rx_table_renew_en;
extern uint8_t g_phy_init_rf_no_cal;
extern int16_t g_phy_freq_offset;
extern const uint8_t *g_phy_rx_gain_swp_step;
extern uint8_t g_phy_rxmax_ext_level;
extern uint8_t g_phy_rx_max_gain_val;
extern uint8_t g_phy_chan14_mic_en;
extern uint8_t g_phy_chan14_mic_most_power;
extern uint8_t g_phy_rfcal_bb_atten_init;
extern uint32_t g_phy_check_result;

/* phy_cal_tx.c */
extern uint8_t g_phy_in_most_power;
extern int8_t g_phy_in_vdd33_offset;
extern uint8_t g_phy_set_most_tpw_flag;
extern uint8_t g_phy_set_most_tpw_val;
extern uint8_t g_phy_set_most_tpw_index;
extern uint8_t g_phy_set_most_tpw_disbg;
extern uint8_t g_phy_periodic_cal_flag;
extern uint8_t g_phy_periodic_cal_sat;
extern uint8_t g_phy_bbpll_cal_flag;
extern uint8_t g_phy_tx_pwctrl_track_num;
extern int8_t g_phy_txpwr_diff_flash[2];
extern uint8_t g_phy_dpd_bypass_original;
extern uint8_t g_phy_txbk_dpdby_flag;

/* phy_adc.c */
extern uint8_t g_phy_tout_dis_txpwr_track;

/* phy_rf_chan.c */
extern uint8_t g_phy_vga_lna_dcap[2];
extern uint8_t g_phy_rfpll_sdm_reg[3];
extern uint8_t g_phy_or_pll_cap_last;
extern uint8_t g_phy_rfpll_unlock;
extern uint8_t g_phy_rx_gain_dc_flag;

/* phy_rxgain.c */
extern uint8_t g_phy_sw_scan_mode;

/* phy_sleep.c */
extern uint8_t g_phy_rtc_cali_trig_en;
extern uint16_t g_phy_lslp_mem_opt_8266;

/* --------------------------------------------------------------------------
 * phy_i2c_pbus.c — ROM-I2C, PBUS, IQ Estimator, TX Tone & dB Helpers
 * -------------------------------------------------------------------------- */

uint8_t rom_i2c_readReg(uint8_t block, uint8_t host_id, uint8_t reg_add);
uint8_t rom_i2c_readReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add,
                             uint8_t msb, uint8_t lsb);
void rom_i2c_writeReg(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data);
void rom_i2c_writeReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add,
                           uint8_t msb, uint8_t lsb, uint8_t data);
uint32_t phy_get_mactime(void);
void phy_get_romfunc_addr(void);

void phy_pbus_soc_cfg(void);
uint16_t phy_pbus_rd(uint8_t reg, uint8_t width);
void phy_pbus_force(uint8_t reg, uint8_t width, uint16_t val);
void phy_pbus_debugmode(void);
void phy_pbus_enter_debugmode(uint16_t tx_rf_ana_gain);
void phy_pbus_exit_debugmode(void);
void phy_pbus_workmode(void);
void phy_pbus_xpd_tx_off(void);
void phy_pbus_xpd_tx_on(uint16_t rf_ana_gain);
void phy_pbus_xpd_rx_on(void);
void phy_pbus_xpd_rx_off(int16_t reg2_val);
void phy_pbus_set_txgain(uint16_t gain);
void phy_pbus_set_rxgain(uint16_t gain);
void phy_pbus_set_rxbbgain(int16_t bbgain);

void phy_set_txclk_en(uint8_t en);
void phy_set_rxclk_en(uint8_t en);
uint8_t phy_set_ana_inf_tx_scale(uint8_t val);
void phy_ana_inf_gating_en(uint8_t en, uint32_t int_div, uint32_t frac_div);
void phy_set_loopback_gain(uint16_t pa_gain, uint16_t pbus_r2,
                           uint16_t pbus_r3_1, uint16_t pbus_r3_2);
void phy_dpd_bypass(void);
void phy_dpd_scale_set(void);
void phy_sar_init(void);
void phy_en_pwdet(uint8_t en);

void phy_iq_est_enable(uint8_t mode, uint16_t samples);
void phy_iq_est_disable(void);
void phy_dc_iq_est(uint8_t mode, uint16_t samples, int32_t out_iq[2]);
void phy_get_corr_power(int32_t out_pwr[3], uint8_t shift);
void phy_start_tx_tone(uint8_t en1, int16_t freq1, uint8_t atten1,
                       uint8_t en2, int16_t freq2, uint8_t atten2,
                       uint8_t en3, int16_t freq3, uint8_t atten3);
void phy_stop_tx_tone(uint8_t tone_idx);
int32_t phy_txtone_linear_pwr(uint8_t avg_cnt, uint8_t shift);
int32_t phy_linear_to_db(int32_t val, uint8_t shift);

uint8_t phy_mhz2ieee(uint16_t freq_mhz, uint8_t flags);
void phy_chip_v5_enable_cca(void);
void phy_chip_v5_disable_cca(void);
void phy_chip_v5_sense_backoff(uint8_t backoff);
void phy_chip_v5_tx_init(void);

/* --------------------------------------------------------------------------
 * phy_clock.c — BBPLL, Chip Revision & Boot Crystal / UART Clock
 * -------------------------------------------------------------------------- */

void change_bbpll160_sleep(void);
void change_bbpll160(void);
void bbpll_cal(uint8_t slow);

void phy_set_crystal_uart(void);
uint32_t phy_get_chip_version(void);

/* --------------------------------------------------------------------------
 * phy_rf_chan.c — RF Power-On/Wake/Close, RFPLL SDM, Channel, Spur & BB RX
 * -------------------------------------------------------------------------- */

int phy_change_channel(uint16_t freq_mhz);
void phy_enable_agc(void);
void phy_disable_agc(void);
void chip_v6_rxmax_ext(uint8_t level);
void phy_set_rx11b_reg(uint8_t enable);
void phy_close_rf(void);

int phy_rf_init(void);
void phy_rf_i2c_init(void);
void phy_wakeup_rf(void);
void phy_rfpll_reset(void);
void phy_write_rfpll_sdm(const uint8_t sdm[3]);
void phy_rfpll_restart_cal(void);
void phy_wait_rfpll_cal_end(void);
void phy_rfpll_calc_sdm(uint16_t freq_mhz, uint8_t xtal_flag, int16_t freq_off,
                        uint8_t sdm[3]);
uint16_t phy_set_channel_freq(uint8_t chan, uint8_t xtal_flag, int16_t freq_off);
void phy_set_chan_60(uint8_t chan, uint8_t xtal_flag, uint8_t unused,
                     int16_t freq_off, phy_sleep_params_t *slp,
                     uint16_t delay_us, uint8_t wait_pll);
void phy_set_chan(uint8_t chan);
void phy_set_chan_misc(uint8_t chan);
void phy_set_chan_wakeup(uint8_t chan);
void phy_set_chan_wakeup_exit(uint8_t chan);
void phy_bb_rx_cfg(void);
void phy_dig_11b_filt_sel(uint8_t sel);
void phy_ant_switch_init(void);
void phy_gpio_cfg(void);
void phy_reduce_current_init(void);
void phy_tx_cont_en(void);
void phy_tx_cont_dis(void);
void phy_sleep_set_rxpbus(uint8_t en);
uint32_t phy_stop_dig_rx(void);
void phy_start_dig_rx(uint32_t saved_dig_rx);
void phy_after_init_enrx(void);
void phy_rxmax_ext_dig(uint8_t level);
void phy_rxmax_ext_ana(uint8_t level);
void phy_chan14_mic_cfg(uint8_t is_ch14);

/* --------------------------------------------------------------------------
 * phy_rxgain.c — RX Gain Table, PBUS DC Servo, RXIQ Cal & Noise Floor
 * -------------------------------------------------------------------------- */

int16_t read_hw_noisefloor(void);
void noise_check_loop(uint8_t chan_idx, uint8_t apply_now);

void phy_set_rx_gain_table(uint8_t rxmax);
void phy_noise_init(uint8_t chan_start, uint8_t num_samples, uint8_t max_ch,
                    uint16_t timeout_us, uint8_t use_min, uint32_t unused,
                    uint32_t *param_flag);
void phy_set_noise_floor(int16_t nf);
int16_t phy_get_noisefloor(void);
void phy_start_noisefloor(uint8_t chan_idx);

/* --------------------------------------------------------------------------
 * phy_cal_tx.c — IRAM Errata/FIQ, RC/TXDC/TXCAP/TXIQ/PWCTRL & Background
 * -------------------------------------------------------------------------- */

uint16_t phy_get_bb_evm(void);
int16_t phy_get_bb_freqoffset(void);
void phy_set_most_tpw(uint8_t max_tpw_qdb);
uint8_t phy_get_most_tpw(void);
void phy_vdd33_set_tpw(uint16_t vdd33);
void tx_pwctrl_background(uint8_t apply_enable, uint8_t debug_print);

void phy_fix_cache_bug(void);
void phy_rc_cal(void);
void phy_init_cal_dcoffset(uint32_t *param_flag, uint16_t txdc[4]);
void phy_txpwr_offset(int16_t extra_off);
void phy_tx_cap_init(void);
void phy_set_txcap_reg(const uint8_t txcap[4][3], uint8_t chan);
void phy_tx_pwctrl_init(uint8_t calibrate_now);
void phy_tx_atten_set_interp(uint8_t chan, int8_t out_atten[6]);
void phy_tx_pwctrl_bg_init(void);
void phy_periodic_cal_top(void);
void phy_rfcal_txiq(uint32_t *param_flag, uint16_t *txiq_out,
                    uint16_t rf_ana_gain, uint8_t amp, int8_t bb_atten,
                    uint8_t sign_flag, uint8_t mode_flag, uint8_t apply_bb);
void phy_low_power_set(uint8_t en, uint8_t stage10, uint8_t bb_delta);
void phy_set_txdc_pbus(uint16_t gain, int8_t out_iq[2], uint8_t apply_pbus);
void phy_set_rfanagain_dc_reg(uint16_t rf_ana_gain, const int8_t dc_iq[2]);
void phy_set_most_pwr_reg(void);

/* --------------------------------------------------------------------------
 * phy_adc.c — SAR ADC, VDD33, TOUT, TSEN, Power Detector & RNG Entropy
 * -------------------------------------------------------------------------- */

uint16_t phy_get_vdd33(void);
void phy_adc_read_fast(uint16_t *dst, uint16_t len, uint8_t clk_div);
uint16_t test_tout(uint8_t no_sleep_mode);

void phy_read_sar_dout(int16_t out[8]);
uint16_t phy_readvdd33(uint8_t pbus_dbg);
uint8_t phy_tsen_meas(void);
void phy_get_fm_sar_dout(int16_t *out1, int16_t *out2);
int16_t phy_get_sar_dout(uint16_t ref);
int16_t phy_get_power_db(uint16_t ref);
uint32_t phy_get_adc_rand(void);

/* --------------------------------------------------------------------------
 * phy_sleep.c — PMU Sleep/Wake, RTC Analog Reset & Slow-Clock Calibration
 * -------------------------------------------------------------------------- */

void clockgate_watchdog(uint8_t disable);
void pm_set_sleep_cycles(uint32_t cycles);
void pm_set_sleep_mode(uint32_t mode);
uint32_t pm_goto_sleep(uint32_t mode);
void pm_wakeup_init(uint32_t mode, uint32_t skip_bbpll);
void pm_set_wakeup_mac(void);
void pm_set_wakeup_btco(void);
void pm_rtc_clock_cali(uint32_t *pm_ctx);
uint32_t pm_rtc_clock_cali_proc(void);
uint32_t pm_usec2rtc(uint32_t usec, uint32_t cali_q12);
uint64_t pm_usec2rtc_64(uint64_t usec, uint32_t cali_q12);
uint64_t pm_get_sleep_cycles_64(uint64_t usec);
void sleep_reset_analog_rtcreg_8266(void);

#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
void phy_pm_rf_off_boot(void);
#endif

void phy_pm_wait4wakeup(uint32_t mode);
void phy_pm_wakeup_opt(uint32_t wakeup_opt, uint32_t wakeup_opt2);
void phy_pm_set_pll_xtal_wait_time(void);
void phy_pm_open_rf(void);
void phy_pm_sleep_opt(uint32_t slp_state1, uint32_t unused,
                      uint32_t pll_ctrl, uint32_t mode);
void phy_pm_sleep_opt_bb_off(uint32_t mode);
void phy_pm_sleep_opt_bb_on(uint32_t mode);

/* --------------------------------------------------------------------------
 * phy_soc.c — SoC Init Data Parser
 * -------------------------------------------------------------------------- */

int register_chipv6_phy_init_param(const uint8_t *init_data);

/* --------------------------------------------------------------------------
 * phy_core.c — Top-Level Bring-Up & RTC Cal Storage
 * -------------------------------------------------------------------------- */

int register_chipv6_phy(uint8_t *init_data_256);
uint8_t phy_check_data_table(uint32_t *table, uint8_t len, uint8_t mode);
void write_data_to_rtc(uint8_t *cal_data_128);
void get_data_from_rtc(uint8_t *cal_data_128);
void phy_afterwake_set_rfoption(uint8_t option);
void deep_sleep_set_option(uint8_t option);
void phy_set_powerup_option(uint8_t option);

int phy_initialize_bb(void);
void phy_rtc_mem_backup_chunk1(void);
void phy_rtc_mem_backup_chunk2(void);
void phy_rtc_mem_recovery_chunk1(void);
void phy_rtc_mem_recovery_chunk2(void);
bool phy_rtc_mem_check(uint8_t verify_only);

#ifdef __cplusplus
}
#endif
