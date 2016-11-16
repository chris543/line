/* Copyright (c) 2014 Nordic Semiconductor. All Rights Reserved.
 *
 * The information contained herein is property of Nordic Semiconductor ASA.
 * Terms and conditions of usage are described in detail in NORDIC
 * SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */

/** @file
 *
 * @defgroup ble_sdk_app_beacon_main main.c
 * @{
 * @ingroup ble_sdk_app_beacon
 * @brief Beacon Transmitter Sample Application main file.
 *
 * This file contains the source code for an Beacon transmitter sample application.
 */

#include <stdbool.h>
#include <stdint.h>
#include "ble_advdata.h"
#include "nordic_common.h"
#include "softdevice_handler.h"
#include "bsp.h"
#include "app_timer.h"
#include <sha256.h>
#include "LineBeacon_config.h"

#define CENTRAL_LINK_COUNT              0                                 /**< Number of central links used by the application. When changing this number remember to adjust the RAM settings*/
#define PERIPHERAL_LINK_COUNT           0                                 /**< Number of peripheral links used by the application. When changing this number remember to adjust the RAM settings*/

#define IS_SRVC_CHANGED_CHARACT_PRESENT 0                                 /**< Include or not the service_changed characteristic. if not enabled, the server's database cannot be changed for the lifetime of the device*/

#define APP_CFG_NON_CONN_ADV_TIMEOUT    0                                 /**< Time for which the device must be advertising in non-connectable mode (in seconds). 0 disables timeout. */
#define NON_CONNECTABLE_ADV_INTERVAL    MSEC_TO_UNITS(250, UNIT_0_625_MS) /**< The advertising interval for non-connectable advertisement (100 ms). This value can vary between 100ms to 10.24s). */

#define APP_BEACON_INFO_LENGTH          0x17                              /**< Total length of information advertised by the Beacon. */
#define APP_ADV_DATA_LENGTH             0x15                              /**< Length of manufacturer specific data in the advertisement. */
#define APP_DEVICE_TYPE                 0x02                              /**< 0x02 refers to Beacon. */
#define APP_MEASURED_RSSI               0xC3                              /**< The Beacon's measured RSSI at 1 meter distance in dBm. */
#define APP_COMPANY_IDENTIFIER          0x004C                            /**< Company identifier for Nordic Semiconductor ASA. as per www.bluetooth.org. */
#define APP_MAJOR_VALUE                 0x4C, 0x49                        /**< Major value used to identify Beacons. */
#define APP_MINOR_VALUE                 0x4E, 0x45                        /**< Minor value used to identify Beacons. */
#define APP_BEACON_UUID                 0xD0, 0xD2, 0xCE, 0x24, \
                                        0x9E, 0xFC, 0x11, 0xE5, \
                                        0x82, 0xC4, 0x1C, 0x6A, \
                                        0x7A, 0x17, 0xEF, 0x38            /**< Proprietary UUID for Beacon. */

#define DEAD_BEEF                       0xDEADBEEF                        /**< Value used as error code on stack dump, can be used to identify stack location on stack unwind. */

#define APP_TIMER_PRESCALER             0                                 /**< Value of the RTC1 PRESCALER register. */
#define APP_TIMER_OP_QUEUE_SIZE         4                                 /**< Size of timer operation queues. */

#if defined(USE_UICR_FOR_MAJ_MIN_VALUES)
#define MAJ_VAL_OFFSET_IN_BEACON_INFO   18                                /**< Position of the MSB of the Major Value in m_beacon_info array. */
#define UICR_ADDRESS                    0x10001080                        /**< Address of the UICR register used by this example. The major and minor versions to be encoded into the advertising data will be picked up from this location. */
#endif

static ble_gap_adv_params_t m_adv_params;                                 /**< Parameters to be passed to the stack when starting advertising. */
static uint8_t m_beacon_info[APP_BEACON_INFO_LENGTH] =                    /**< Information advertised by the Beacon. */
{
    APP_DEVICE_TYPE,     // Manufacturer specific information. Specifies the device type in this
    // implementation.
    APP_ADV_DATA_LENGTH, // Manufacturer specific information. Specifies the length of the
    // manufacturer specific data in this implementation.
    APP_BEACON_UUID,     // 128 bit UUID value.
    APP_MAJOR_VALUE,     // Major arbitrary value that can be used to distinguish between Beacons.
    APP_MINOR_VALUE,     // Minor arbitrary value that can be used to distinguish between Beacons.
    APP_MEASURED_RSSI    // Manufacturer specific information. The Beacon's measured TX power in
    // this implementation.
};

#define APP_TIMER_PRESCALER             0                                 /**< Value of the RTC1 PRESCALER register. */
#define APP_TIMER_OP_QUEUE_SIZE         4
APP_TIMER_DEF(m_led_a_timer_id);
#define uudi_IDENTIFIER          0xFE6F                           /**< Company identifier for Nordic Semiconductor ASA. as per www.bluetooth.org. */
uint8_t toggle_adv;

// uint8_t HWID[5] = {0x2b, 0x01, 0xed, 0xdc, 0xa0};  //5 byte LINE generated
// uint8_t VENDER_KEY[4] = {0x23, 0xa4, 0xf2, 0x5c};           //4 byte LINE generated
// uint8_t LOT_KEY[8] = {0x4f, 0xe3, 0x7f, 0x1d, 0xe4, 0x4f, 0x19, 0x8c}; //8 byte self depand on HWID



uint8_t combine_tmp[25] = {
    // 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    HWID_t,
    VENDER_KEY_t,
    LOT_KEY_t
};

uint64_t TIMESTAMP = 0;
uint8_t countTo_1;
uint8_t countTo_15;
uint8_t combineData[25];
uint8_t secMsg[6];

static void Gen_SecureMessage(void);
uint64_t lastTimestamp = 0;

// uint64_t TIMESTAMP_test = 0x7abcdef123456789;
uint64_t TIMESTAMP_test = 0x7fffffffffffffff;


/*
        Timestamp -   HWID  -  Security Key(Vendor key - lot key)
        8 byte       5 byte    12 byte     (4 byte       8 byte )

        =(SAH256) Hashed Data (32 byte)

        16 byte  XOR 16 byte        =  16 byte
                                      8 byte XOR 8 byte = 8 byte
                                                         4 byte XOR 4 byte = MAC (4byte)
        secure Message = MAC (4byte) - Masked Timestamp(= Timestamp last 2 byte)
*/

/**@brief Callback function for asserts in the SoftDevice.
 *
 * @details This function will be called in case of an assert in the SoftDevice.
 *
 * @warning This handler is an example only and does not fit a final product. You need to analyze
 *          how your product is supposed to react in case of Assert.
 * @warning On assert from the SoftDevice, the system can only recover on reset.
 *
 * @param[in]   line_num   Line number of the failing ASSERT call.
 * @param[in]   file_name  File name of the failing ASSERT call.
 */
void assert_nrf_callback(uint16_t line_num, const uint8_t * p_file_name)
{
    app_error_handler(DEAD_BEEF, line_num, p_file_name);
}

/**@brief Function for initializing the Advertising functionality.
 *
 * @details Encodes the required advertising data and passes it to the stack.
 *          Also builds a structure to be passed to the stack when starting advertising.
 */

static void iBeacon(void)
{
    uint32_t      err_code;
    ble_advdata_t advdata;
//    uint8_t       flags = BLE_GAP_ADV_FLAG_BR_EDR_NOT_SUPPORTED;
    uint8_t       flags = 6;

    ble_advdata_manuf_data_t manuf_specific_data;

    manuf_specific_data.company_identifier = APP_COMPANY_IDENTIFIER;

#if defined(USE_UICR_FOR_MAJ_MIN_VALUES)
    // If USE_UICR_FOR_MAJ_MIN_VALUES is defined, the major and minor values will be read from the
    // UICR instead of using the default values. The major and minor values obtained from the UICR
    // are encoded into advertising data in big endian order (MSB First).
    // To set the UICR used by this example to a desired value, write to the address 0x10001080
    // using the nrfjprog tool. The command to be used is as follows.
    // nrfjprog --snr <Segger-chip-Serial-Number> --memwr 0x10001080 --val <your major/minor value>
    // For example, for a major value and minor value of 0xabcd and 0x0102 respectively, the
    // the following command should be used.
    // nrfjprog --snr <Segger-chip-Serial-Number> --memwr 0x10001080 --val 0xabcd0102
    uint16_t major_value = ((*(uint32_t *)UICR_ADDRESS) & 0xFFFF0000) >> 16;
    uint16_t minor_value = ((*(uint32_t *)UICR_ADDRESS) & 0x0000FFFF);

    uint8_t index = MAJ_VAL_OFFSET_IN_BEACON_INFO;

    m_beacon_info[index++] = MSB_16(major_value);
    m_beacon_info[index++] = LSB_16(major_value);

    m_beacon_info[index++] = MSB_16(minor_value);
    m_beacon_info[index++] = LSB_16(minor_value);
#endif

    manuf_specific_data.data.p_data = (uint8_t *) m_beacon_info;
    manuf_specific_data.data.size   = APP_BEACON_INFO_LENGTH;

    // Build and set advertising data.
    memset(&advdata, 0, sizeof(advdata));

    advdata.name_type             = BLE_ADVDATA_NO_NAME;
    advdata.flags                 = flags;
    advdata.p_manuf_specific_data = &manuf_specific_data;

    err_code = ble_advdata_set(&advdata, NULL);
    APP_ERROR_CHECK(err_code);

    // Initialize advertising parameters (used when starting advertising).
    memset(&m_adv_params, 0, sizeof(m_adv_params));

    m_adv_params.type        = BLE_GAP_ADV_TYPE_ADV_NONCONN_IND;
    m_adv_params.p_peer_addr = NULL;                             // Undirected advertisement.
    m_adv_params.fp          = BLE_GAP_ADV_FP_ANY;
    m_adv_params.interval    = NON_CONNECTABLE_ADV_INTERVAL;
    m_adv_params.timeout     = APP_CFG_NON_CONN_ADV_TIMEOUT;
}
void LineBeacon(void) {

    uint32_t      err_code;
    uint8_t       flags = BLE_GAP_ADV_FLAG_BR_EDR_NOT_SUPPORTED;
    ble_advdata_t Line_advdata;
    ble_uuid_t  myLINE_UUID;
    ble_advdata_service_data_t  srv_data;
    uint8_array_t               data_array;
    uint8_t                     data[13];
    data[0] = 0x02;         //02 LINE BLE beacon

    data[1] = 0xAA;         //next 5 bytes is HWID
    data[2] = 0xAA;
    data[3] = 0xAA;
    data[4] = 0xAA;
    data[5] = 0xAA;
    uint8_t HWID_tmp[5]={HWID_t};
    memcpy(data + 1, HWID_tmp, 5);
    data[6] = APP_MEASURED_RSSI;
    data[7] = 0xBB;         //next 6 bytes is SecureMessage
    data[8] = 0xBB;
    data[9] = 0xBB;
    data[10] = 0xBB;
    data[11] = 0xBB;
    data[12] = 0xBB;
    //to save mcu calculate time
    if (lastTimestamp != TIMESTAMP)
    {
        Gen_SecureMessage();
        lastTimestamp = TIMESTAMP;
    }
    memcpy(data + 7, secMsg, 6);

    data_array.p_data = data;
    data_array.size = sizeof(data);
    srv_data.service_uuid = uudi_IDENTIFIER;
    srv_data.data = data_array;

    // Build and set advertising data.
    memset(&Line_advdata, 0, sizeof(Line_advdata));

    myLINE_UUID.uuid = uudi_IDENTIFIER;
    myLINE_UUID.type = BLE_UUID_TYPE_BLE;

    Line_advdata.uuids_complete.uuid_cnt = 1;
    Line_advdata.uuids_complete.p_uuids = &myLINE_UUID;

    Line_advdata.name_type             = BLE_ADVDATA_NO_NAME;
    Line_advdata.flags                 = flags;

    Line_advdata.p_service_data_array    = &srv_data;
    Line_advdata.service_data_count      = 1;

    err_code = ble_advdata_set(&Line_advdata, NULL);
    // err_code = ble_advdata_set(&advdata, &scanrsp);
    APP_ERROR_CHECK(err_code);

    // Initialize advertising parameters (used when starting advertising).
    memset(&m_adv_params, 0, sizeof(m_adv_params));

    // m_adv_params.type        = BLE_GAP_ADV_TYPE_ADV_NONCONN_IND;
    m_adv_params.type        = BLE_GAP_ADV_TYPE_ADV_SCAN_IND;

    m_adv_params.p_peer_addr = NULL;                             // Undirected advertisement.
    m_adv_params.fp          = BLE_GAP_ADV_FP_ANY;
    m_adv_params.interval    = NON_CONNECTABLE_ADV_INTERVAL;
    m_adv_params.timeout     = APP_CFG_NON_CONN_ADV_TIMEOUT;
}
static void advertising_init(void)
{
    iBeacon();
}
/**@brief Function for starting advertising.
 */
static void advertising_start(void)
{
    uint32_t err_code;

    err_code = sd_ble_gap_adv_start(&m_adv_params);
    APP_ERROR_CHECK(err_code);

    err_code = bsp_indication_set(BSP_INDICATE_ADVERTISING);
    APP_ERROR_CHECK(err_code);
}


/**@brief Function for initializing the BLE stack.
 *
 * @details Initializes the SoftDevice and the BLE event interrupt.
 */
static void ble_stack_init(void)
{
    uint32_t err_code;

    nrf_clock_lf_cfg_t clock_lf_cfg = NRF_CLOCK_LFCLKSRC;

    // Initialize the SoftDevice handler module.
    SOFTDEVICE_HANDLER_INIT(&clock_lf_cfg, NULL);

    ble_enable_params_t ble_enable_params;
    err_code = softdevice_enable_get_default_config(CENTRAL_LINK_COUNT,
               PERIPHERAL_LINK_COUNT,
               &ble_enable_params);
    APP_ERROR_CHECK(err_code);

    //Check the ram settings against the used number of links
    CHECK_RAM_START_ADDR(CENTRAL_LINK_COUNT, PERIPHERAL_LINK_COUNT);

    // Enable BLE stack.
    err_code = softdevice_enable(&ble_enable_params);
    APP_ERROR_CHECK(err_code);
}


/**@brief Function for doing power management.
 */
static void power_manage(void)
{
    uint32_t err_code = sd_app_evt_wait();
    APP_ERROR_CHECK(err_code);
}
// Timeout handler for the repeated timer
static void timer_a_handler(void * p_context)
{
//    nrf_drv_gpiote_out_toggle(LED_1_PIN);

    countTo_1++;
    if (countTo_1 % 4 == 0)
    {
        countTo_15++;
        if (countTo_15 % 15 == 0 )
        {
            TIMESTAMP ++;
            countTo_15 = 0;
            nrf_gpio_pin_toggle(20);
        }
        countTo_1 = 0;
    }

    toggle_adv = !toggle_adv;
    if (toggle_adv)
    {
        // iBeacon();
        advertising_init();
        // nrf_gpio_pin_toggle(BSP_LED_2); //Toggle the status of the LED on each radio notification event
    }
    else {
        LineBeacon();
        // nrf_gpio_pin_toggle(BSP_LED_3); //Toggle the status of the LED on each radio notification event
    }

}

// Create timers
static void create_timers()
{
    uint32_t err_code;

    // Create timers
    err_code = app_timer_create(&m_led_a_timer_id,
                                APP_TIMER_MODE_REPEATED,
                                timer_a_handler);
    APP_ERROR_CHECK(err_code);

//        err_code = app_timer_create(&m_led_b_timer_id,
//                                APP_TIMER_MODE_SINGLE_SHOT,
//                                timer_b_handler);
//    APP_ERROR_CHECK(err_code);

}

void reverse_array(uint8_t *data, size_t n)
{
    size_t i;

    for (i = 0; i < n / 2; ++i) {
        uint8_t tmp = data[i];
        data[i] = data[n - 1 - i];
        data[n - 1 - i] = tmp;
    }
}
void Gen_SecureMessage() {
    // memcpy(combineData + 17, &TIMESTAMP_test, 8);
    // memcpy(combineData + 12, HWID, 5);
    // memcpy(combineData + 8, VENDER_KEY, 4);
    // memcpy(combineData , LOT_KEY, 8);

    // uint8_t timestamp_temp[8];
    // memcpy(timestamp_temp, &TIMESTAMP_test, 8);
    // reverse_array(timestamp_temp, sizeof(timestamp_temp));
    // memcpy(combine_tmp, timestamp_temp, sizeof(timestamp_temp));

    memcpy(combineData, combine_tmp, 25);

    // uint8_t shift;
    for (int i = 0; i < 8; i++)
    {
        combineData[i] = ((*(uint64_t *)&TIMESTAMP) ) >> (56 - (i * 8));
        if (i == 6)
        {
            secMsg[4] = ((*(uint64_t *)&TIMESTAMP) ) >> 8;
        } else if ( i == 7) {
            secMsg[5] = ((*(uint64_t *)&TIMESTAMP) ) ;
        }
    }
    // combineData[0] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 56;
    // combineData[1] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 48;
    // combineData[2] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 40;
    // combineData[3] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 32;
    // combineData[4] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 24;
    // combineData[5] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 16;
    // combineData[6] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 8;
    // combineData[7] = ((*(uint64_t *)&TIMESTAMP_test) ) ;

    // combineData[0] = ((*(uint64_t *)&TIMESTAMP_test) & 0xFF00000000000000) >> 56;
    // combineData[1] = ((*(uint64_t *)&TIMESTAMP_test) & 0x00FF000000000000) >> 48;
    // combineData[2] = ((*(uint64_t *)&TIMESTAMP_test) & 0x0000FF0000000000) >> 40;
    // combineData[3] = ((*(uint64_t *)&TIMESTAMP_test) & 0x000000FF00000000) >> 32;
    // combineData[4] = ((*(uint64_t *)&TIMESTAMP_test) & 0x00000000FF000000) >> 24;
    // combineData[5] = ((*(uint64_t *)&TIMESTAMP_test) & 0x0000000000FF0000) >> 16;
    // combineData[6] = ((*(uint64_t *)&TIMESTAMP_test) & 0x000000000000FF00) >> 8;
    // combineData[7] = ((*(uint64_t *)&TIMESTAMP_test) & 0x00000000000000FF) ;

    uint8_t sha256_data[32];
    sha256_context_t ctx_data;
    sha256_init(&ctx_data);

    sha256_update(&ctx_data, combineData, sizeof(combineData));
    sha256_final(&ctx_data, sha256_data);

    uint8_t c_16byte[16];
    uint8_t c_8byte[8];
    uint8_t c_4byte[4];
    for (int i = 0; i < 16; ++i)
    {
        c_16byte[i] = sha256_data[i] ^ sha256_data[i + 16];
    }
    for (int i = 0; i < 8; ++i)
    {
        c_8byte[i] = c_16byte[i] ^ c_16byte[i + 8];
    }
    for (int i = 0; i < 4; ++i)
    {
        c_4byte[i] = c_8byte[i] ^ c_8byte[i + 4];
    }
    memcpy(secMsg, c_4byte, 4);
    // secMsg[4]= ((*(uint64_t *)&TIMESTAMP_test) & 0x00000000000000FF) ;
    // secMsg[4] = ((*(uint64_t *)&TIMESTAMP_test) ) >> 8;
    // secMsg[5] = ((*(uint64_t *)&TIMESTAMP_test) ) ;

    // c_16byte[0] = sha256_data[0] ^ sha256_data[16];
    // c_16byte[1] = sha256_data[1] ^ sha256_data[17];
    // c_16byte[2] = sha256_data[2] ^ sha256_data[18];
    // c_16byte[15] = sha256_data[15] ^ sha256_data[31];

    // combineData[i] = ((*(uint64_t *)&TIMESTAMP_test) ) >> (56 - (i * 8));
    // HSB16_byte= ((*(uint64_t *)&TIMESTAMP_test) ) >> (56 - (i * 8));
}
/**
 * @brief Function for application main entry.
 */
int main(void)
{
    uint32_t err_code;
    // Initialize.
//    APP_TIMER_INIT(APP_TIMER_PRESCALER, APP_TIMER_OP_QUEUE_SIZE, false);
//    err_code = bsp_init(BSP_INIT_LED, APP_TIMER_TICKS(100, APP_TIMER_PRESCALER), NULL);
//    APP_ERROR_CHECK(err_code);

    APP_TIMER_INIT(APP_TIMER_PRESCALER, APP_TIMER_OP_QUEUE_SIZE, false);
    create_timers();


    ble_stack_init();
    advertising_init();

    err_code = app_timer_start(m_led_a_timer_id, APP_TIMER_TICKS(250, APP_TIMER_PRESCALER), NULL);
    APP_ERROR_CHECK(err_code);

    // Start execution.
    advertising_start();
    nrf_gpio_cfg_output(20);
    Gen_SecureMessage();

    // Enter main loop.
    for (;; )
    {
        power_manage();
    }
}


/**
 * @}
 */
