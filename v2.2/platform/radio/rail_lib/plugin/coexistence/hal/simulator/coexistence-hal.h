/**************************************************************************//**
 * @file coexistence_hal.h
 * @brief This file contains the simulated radio coexistence HAL interface.
 * @copyright Copyright 2017 Silicon Laboratories, Inc. www.silabs.com
 *****************************************************************************/

#ifndef __COEXISTENCE_HAL_H__
#define __COEXISTENCE_HAL_H__

#include "coexistence/coexistence.h"

typedef void (*COEX_SIM_Isr_t)(bool gpioValue);

typedef struct COEX_HAL_GpioConfig {
  /** GPIO assert polarity */
  bool polarity;

  /** Simulated GPIO input state */
  bool inputState;

  /** Simulated GPIO output state */
  bool outputState;

  /** Simulated GPIO enable state */
  bool intEnabled;

  /** Simulator GPIO callback */
  COEX_SIM_Isr_t cb;

  /** GPIO config */
  COEX_GpioConfig_t config;
} COEX_HAL_GpioConfig_t;

void COEX_HAL_Init(void);
bool COEX_HAL_ConfigRequest(COEX_HAL_GpioConfig_t *gpioConfig);
bool COEX_HAL_ConfigRadioHoldOff(COEX_HAL_GpioConfig_t *gpioConfig);
bool COEX_HAL_ConfigPriority(COEX_HAL_GpioConfig_t *gpioConfig);
bool COEX_HAL_ConfigGrant(COEX_HAL_GpioConfig_t *gpioConfig);

typedef enum COEX_GpioId {
  COEX_GPIO_ID_GNT = 0,
  COEX_GPIO_ID_REQ = 1,
  COEX_GPIO_ID_RHO = 2,
  COEX_GPIO_ID_PRI = 3,
  COEX_GPIO_ID_COUNT = 4
} COEX_GpioId_t;

void COEX_SIM_SetGpio(COEX_GpioId_t gpio, bool value);
bool COEX_SIM_GetGpio(COEX_GpioId_t gpio);
const COEX_HAL_GpioConfig_t* COEX_SIM_GetGpioConfig(COEX_GpioId_t gpio);
void COEX_SIM_SetGpioConfig(COEX_GpioId_t gpio,
                            const COEX_HAL_GpioConfig_t* config);

#endif  // __COEXISTENCE_HAL_H__
