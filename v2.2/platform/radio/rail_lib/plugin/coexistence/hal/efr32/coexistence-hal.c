// -----------------------------------------------------------------------------
/// @file
/// @brief Radio coexistence EFR32 utilities
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
#include "em_core.h"
#include "coexistence-hal.h"

#ifdef HAL_CONFIG
#include "hal-config.h"

#ifdef BSP_COEX_GNT_PORT
static COEX_HAL_GpioConfig_t ptaGntCfg = {
  .port = BSP_COEX_GNT_PORT,
  .pin = BSP_COEX_GNT_PIN,
  .polarity = BSP_COEX_GNT_ASSERT_LEVEL
};
#endif //BSP_COEX_GNT_PORT

#ifdef BSP_COEX_PRI_PORT
static COEX_HAL_GpioConfig_t ptaPriCfg = {
  .port = BSP_COEX_PRI_PORT,
  .pin = BSP_COEX_PRI_PIN,
  .polarity = BSP_COEX_PRI_ASSERT_LEVEL
};
#endif //BSP_COEX_PRI_PORT

#ifdef BSP_COEX_REQ_PORT
static COEX_HAL_GpioConfig_t ptaReqCfg = {
  .port = BSP_COEX_REQ_PORT,
  .pin = BSP_COEX_REQ_PIN,
  .polarity = BSP_COEX_REQ_ASSERT_LEVEL
};
#endif //BSP_COEX_REQ_PORT

#ifdef BSP_COEX_RHO_PORT
static COEX_HAL_GpioConfig_t rhoCfg = {
  .port = BSP_COEX_RHO_PORT,
  .pin = BSP_COEX_RHO_PIN,
  .polarity = BSP_COEX_RHO_ASSERT_LEVEL
};
#endif //BSP_COEX_RHO_PORT

#endif //HAL_CONFIG

#define GPIO_FLAG(x) (1ul << x)

static void (*reqCallback)(void) = NULL;
static void (*gntCallback)(void) = NULL;
static void (*rhoCallback)(void) = NULL;

static void COEX_HAL_REQ_ISR(uint8_t pin)
{
  (void)pin;
  reqCallback();
}

static void COEX_HAL_GNT_ISR(uint8_t pin)
{
  (void)pin;
  gntCallback();
}

static void COEX_HAL_RHO_ISR(uint8_t pin)
{
  (void)pin;
  rhoCallback();
}

static void setGpioConfig(COEX_GpioHandle_t gpioHandle)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;

  GPIO_PinModeSet((GPIO_Port_TypeDef)gpio->port,
                  gpio->pin,
                  (GPIO_Mode_TypeDef)gpio->mode,
                  GPIO_PinOutGet((GPIO_Port_TypeDef)gpio->port,
                                 gpio->pin));
}

static void enableGpioInt(COEX_GpioHandle_t gpioHandle,
                          bool enabled,
                          bool *wasAsserted)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  COEX_GpioConfig_t *coexGpio = &(gpio->config);

  bool intAsserted = (coexGpio->options & COEX_GPIO_OPTION_INT_ASSERTED) != 0U;
  bool intDeasserted = (coexGpio->options & COEX_GPIO_OPTION_INT_DEASSERTED) != 0U;

  if (enabled) {
    // Disable triggering and clear any stale events
    GPIO_IntConfig((GPIO_Port_TypeDef)gpio->port, gpio->pin,
                   false, false, false);
    if (wasAsserted != NULL) {
      *wasAsserted = false; // Ensures we won't miss GNT assertion
    }
    // Register callbacks before setting up and enabling pin interrupt
    GPIOINT_CallbackRegister(gpio->pin, gpio->isr);
    // Enable both edges' interrupt
    GPIO_IntConfig((GPIO_Port_TypeDef)gpio->port,
                   gpio->pin,
                   gpio->polarity ? intAsserted : intDeasserted,
                   gpio->polarity ? intDeasserted : intAsserted,
                   true);
  } else {
    GPIO_IntDisable(GPIO_FLAG(gpio->pin));
    GPIO_IntClear(GPIO_FLAG(gpio->pin));
  }
}

static void setGpio(COEX_GpioHandle_t gpioHandle, bool enabled)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;

  if (enabled == gpio->polarity) {
    GPIO_PinOutSet((GPIO_Port_TypeDef)gpio->port, gpio->pin);
  } else {
    GPIO_PinOutClear((GPIO_Port_TypeDef)gpio->port, gpio->pin);
  }
}

static void configGpio(COEX_GpioHandle_t gpioHandle, COEX_GpioConfig_t *coexGpio)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  bool defaultAsserted = (coexGpio->options & COEX_GPIO_OPTION_DEFAULT_ASSERTED) != 0U;
  gpio->config = *coexGpio;

  if ((coexGpio->options & COEX_GPIO_OPTION_SHARED) != 0U) {
    gpio->mode = gpio->polarity ? gpioModeWiredOr : gpioModeWiredAnd;
  } else if ((coexGpio->options & COEX_GPIO_OPTION_OUTPUT) != 0U) {
    gpio->mode = gpioModePushPull;
  } else {
    gpio->mode = gpioModeInputPull;
  }
  setGpioConfig(gpio);
  setGpio(gpio, defaultAsserted);
}

static void setGpioFlag(COEX_GpioHandle_t gpioHandle, bool enabled)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;

  if (enabled) {
    GPIO_IntSet(GPIO_FLAG(gpio->pin));
  } else {
    GPIO_IntClear(GPIO_FLAG(gpio->pin));
  }
}

static bool isGpioOutSet(COEX_GpioHandle_t gpioHandle)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  return !!GPIO_PinOutGet((GPIO_Port_TypeDef)gpio->port,
                          gpio->pin) == !!gpio->polarity;
}

static bool isGpioInSet(COEX_GpioHandle_t gpioHandle)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  return !!GPIO_PinInGet((GPIO_Port_TypeDef)gpio->port,
                         gpio->pin) == !!gpio->polarity;
}

#ifdef BSP_COEX_PWM_ON_MS
#include "rail.h"

static RAIL_MultiTimer_t pwmGpioTimer;

static void pwmGpioTimerCb(RAIL_MultiTimer_t *tmr,
                           RAIL_Time_t expectedTimeOfEvent,
                           void *cbArg);

static void setPwmGpioTimer(COEX_HAL_GpioConfig_t *gpio, uint32_t time)
{
  RAIL_SetMultiTimer(&pwmGpioTimer,
                     time * 1000u,
                     RAIL_TIME_DELAY,
                     &pwmGpioTimerCb,
                     gpio);
}

static void pwmGpioTimerCb(RAIL_MultiTimer_t *tmr,
                           RAIL_Time_t expectedTimeOfEvent,
                           void *cbArg)
{
  (void)tmr;
  (void)expectedTimeOfEvent;
  COEX_GpioHandle_t gpioHandle = (COEX_GpioHandle_t)cbArg;
  bool enabled = !isGpioOutSet(&gpioHandle);
  setGpio(gpioHandle, enabled);
  setPwmGpioTimer((COEX_HAL_GpioConfig_t*)gpioHandle,
                  enabled ? BSP_COEX_PWM_ON_MS : BSP_COEX_PWM_OFF_MS);
}

static void setPwmGpio(COEX_GpioHandle_t gpioHandle, bool enabled)
{
  COEX_HAL_GpioConfig_t *gpio = (COEX_HAL_GpioConfig_t*)gpioHandle;
  if (gpio->pwmEnabled) {
    if (enabled) {
      setGpio(gpioHandle, true);
      setPwmGpioTimer(gpio, BSP_COEX_PWM_ON_MS);
    } else {
      RAIL_CancelMultiTimer(&pwmGpioTimer);
      setGpio(gpioHandle, false);
    }
    return;
  }
  setGpio(gpioHandle, enabled);
}
#endif // BSP_COEX_PWM_ON_MS

static const COEX_HalCallbacks_t coexHalCallbacks = {
#ifdef BSP_COEX_PWM_ON_MS
  .setGpio = &setPwmGpio,
#else // !BSP_COEX_PWM_ON_MS
  .setGpio = &setGpio,
#endif // BSP_COEX_PWM_ON_MS
  .setGpioFlag = &setGpioFlag,
  .enableGpioInt = &enableGpioInt,
  .configGpio = &configGpio,
  .isGpioOutSet = &isGpioOutSet,
  .isGpioInSet = &isGpioInSet
};

void COEX_HAL_CallAtomic(COEX_AtomicCallback_t cb, void *arg)
{
  CORE_CRITICAL_SECTION((*cb)(arg); )
}

bool COEX_HAL_ConfigRequest(COEX_HAL_GpioConfig_t *gpioConfig)
{
  bool status = false;

  gpioConfig->isr = &COEX_HAL_REQ_ISR;
  status = COEX_ConfigRequest(gpioConfig);
  if (status) {
    reqCallback = gpioConfig->config.cb;
  }
  return status;
}

bool COEX_HAL_ConfigRadioHoldOff(COEX_HAL_GpioConfig_t *gpioConfig)
{
  bool status = false;

  gpioConfig->isr = &COEX_HAL_RHO_ISR;
  status = COEX_ConfigRadioHoldOff(gpioConfig);
  if (status) {
    rhoCallback = gpioConfig->config.cb;
  }
  return status;
}

bool COEX_HAL_ConfigPriority(COEX_HAL_GpioConfig_t *gpioConfig)
{
  return COEX_ConfigPriority(gpioConfig);
}

bool COEX_HAL_ConfigGrant(COEX_HAL_GpioConfig_t *gpioConfig)
{
  bool status = false;

  gpioConfig->isr = &COEX_HAL_GNT_ISR;
  status = COEX_ConfigGrant(gpioConfig);
  if (status) {
    gntCallback = gpioConfig->config.cb;
  }
  return status;
}

void COEX_HAL_Init(void)
{
  COEX_SetHalCallbacks(&coexHalCallbacks);
  COEX_Options_t options = COEX_OPTION_NONE;

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
