/**************************************************************************//**
 * @file coexistence_hal.h
 * @brief This file contains the EFR32 radio coexistence interface.
 * @copyright Copyright 2017 Silicon Laboratories, Inc. www.silabs.com
 *****************************************************************************/

#ifndef __COEXISTENCE_HAL_H__
#define __COEXISTENCE_HAL_H__

#include "coexistence/coexistence.h"
#include "em_gpio.h"
#include "gpiointerrupt.h"

typedef struct COEX_HAL_GpioConfig {
  /** GPIO port */
  uint8_t port;

  /** GPIO pin */
  uint8_t pin;

  /** GPIO assert polarity */
  bool polarity;

  /** GPIO PWM enabled */
  bool pwmEnabled;

  /** GPIO mode */
  uint8_t mode;

  /** GPIO ISR */
  GPIOINT_IrqCallbackPtr_t isr;

  /** GPIO config */
  COEX_GpioConfig_t config;
} COEX_HAL_GpioConfig_t;

void COEX_HAL_Init(void);
bool COEX_HAL_ConfigRequest(COEX_HAL_GpioConfig_t *gpioConfig);
bool COEX_HAL_ConfigRadioHoldOff(COEX_HAL_GpioConfig_t *gpioConfig);
bool COEX_HAL_ConfigPriority(COEX_HAL_GpioConfig_t *gpioConfig);
bool COEX_HAL_ConfigGrant(COEX_HAL_GpioConfig_t *gpioConfig);

#endif  // __COEXISTENCE_HAL_H__
