// -----------------------------------------------------------------------------
/// @file
/// @brief Radio coexistence simulation HAL utilities
///
/// @author Silicon Laboratories Inc.
/// @version 1.0.0
///
/// @section License
/// <b>(C) Copyright 2017 Silicon Laboratories, http://www.silabs.com</b>
///
/// This file is licensed under the Silabs License Agreement. See the file
/// "Silabs_License_Agreement.txt" for details. Before using this software for
/// any purpose, you must agree to the terms of that agreement.
///
// -----------------------------------------------------------------------------
#include "coexistence-hal.h"

static COEX_HAL_GpioConfig_t gpioConfigs[4];

static void enableGpioInt(COEX_GpioHandle_t gpioHandle,
                          bool enabled,
                          bool *wasAsserted)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;

  if (enabled && wasAsserted != NULL) {
    *wasAsserted = false; // Ensures we won't miss GNT assertion
  }
  gpio->intEnabled = enabled;
}

static void setGpio(COEX_GpioHandle_t gpioHandle, bool enabled)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;

  gpio->inputState = (enabled == gpio->polarity);
}

static void configGpio(COEX_GpioHandle_t gpioHandle, COEX_GpioConfig_t *coexGpio)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  bool defaultAsserted = (coexGpio->options & COEX_GPIO_OPTION_DEFAULT_ASSERTED) != 0U;
  gpio->config = *coexGpio;

  setGpio(gpio, defaultAsserted);
}

static void setGpioFlag(COEX_GpioHandle_t gpioHandle, bool enabled)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;

  if (enabled && gpio->cb != NULL) {
    gpio->cb(gpio->inputState);
  }
}

static bool isGpioOutSet(COEX_GpioHandle_t gpioHandle)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  return gpio->outputState == gpio->polarity;
}

static bool isGpioInSet(COEX_GpioHandle_t gpioHandle)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  return gpio->inputState == gpio->polarity;
}

static const COEX_HalCallbacks_t coexHalCallbacks = {
  .setGpio = &setGpio,
  .setGpioFlag = &setGpioFlag,
  .enableGpioInt = &enableGpioInt,
  .configGpio = &configGpio,
  .isGpioOutSet = &isGpioOutSet,
  .isGpioInSet = &isGpioInSet
};

void COEX_HAL_CallAtomic(COEX_AtomicCallback_t cb, void *arg)
{
  (*cb)(arg);
}

bool COEX_HAL_ConfigRequest(COEX_HAL_GpioConfig_t *gpioConfig)
{
  return COEX_ConfigRequest(gpioConfig);
}

bool COEX_HAL_ConfigRadioHoldOff(COEX_HAL_GpioConfig_t *gpioConfig)
{
  return COEX_ConfigRadioHoldOff(gpioConfig);
}

bool COEX_HAL_ConfigPriority(COEX_HAL_GpioConfig_t *gpioConfig)
{
  return COEX_ConfigPriority(gpioConfig);
}

bool COEX_HAL_ConfigGrant(COEX_HAL_GpioConfig_t *gpioConfig)
{
  return COEX_ConfigGrant(gpioConfig);
}

bool COEX_SIM_GetGpio(COEX_GpioId_t gpio)
{
  return gpioConfigs[gpio].outputState;
}

const COEX_HAL_GpioConfig_t* COEX_SIM_GetGpioConfig(COEX_GpioId_t gpioId)
{
  return &gpioConfigs[gpioId];
}

void COEX_SIM_SetGpioConfig(COEX_GpioId_t gpioId,
                            const COEX_HAL_GpioConfig_t* config)
{
  gpioConfigs[gpioId] = *config;
}

void COEX_SIM_SetGpio(COEX_GpioId_t gpioId, bool gpioValue)
{
  COEX_GpioConfig_t *coexGpio = &(gpioConfigs[gpioId].config);
  bool intAsserted = (coexGpio->options & COEX_GPIO_OPTION_INT_ASSERTED) != 0U;
  bool intDeasserted = (coexGpio->options & COEX_GPIO_OPTION_INT_DEASSERTED) != 0U;

  if (gpioConfigs[gpioId].intEnabled
      && gpioConfigs[gpioId].config.cb != NULL
      && gpioValue != gpioConfigs[gpioId].inputState
      && ((intAsserted && gpioValue)
          || (intDeasserted && !gpioValue))) {
    gpioConfigs[gpioId].inputState = gpioValue;
    gpioConfigs[gpioId].config.cb();
  }
}

void COEX_HAL_Init(void)
{
  COEX_SetHalCallbacks(&coexHalCallbacks);
  COEX_Options_t options = (COEX_Options_t)0;

  #ifdef BSP_COEX_REQ_PORT
  COEX_HAL_ConfigRequest(&ptaReqCfg);
  #endif //BSP_COEX_REQ_PORT
  #ifdef BSP_COEX_RHO_PORT
  COEX_HAL_ConfigRadioHoldOff(&rhoCfg);
  options |= COEX_OPTION_RHO_ENABLED;
  #endif //BSP_COEX_RHO_PORT
  #ifdef BSP_COEX_PRI_PORT
  COEX_HAL_ConfigPriority(&ptaPriCfg);
  #endif //BSP_COEX_PRI_PORT
  #ifdef BSP_COEX_GNT_PORT
  COEX_HAL_ConfigGrant(&ptaGntCfg);
  options |= COEX_OPTION_COEX_ENABLED;
  #endif //BSP_COEX_GNT_PORT
  #ifdef HAL_COEX_REQ_BACKOFF
  options |= COEX_OPTION_MAX_REQ_BACKOFF_MASK;
  options |= COEX_OPTION_COEX_ENABLED;
  #endif //HAL_COEX_REQ_BACKOFF
  #ifdef HAL_COEX_REQ_SHARED
  options |= COEX_OPTION_REQ_SHARED;
  #endif //HAL_COEX_REQ_SHARED
  #ifdef HAL_COEX_PRI_SHARED
  options |= COEX_OPTION_PRI_SHARED;
  #endif //HAL_COEX_PRI_SHARED
  #ifdef HAL_COEX_TX_ABORT
  options |= COEX_OPTION_TX_ABORT;
  #endif //HAL_COEX_TX_ABORT
  COEX_SetOptions(options);
}
