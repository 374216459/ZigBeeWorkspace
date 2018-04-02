/***************************************************************************//**
 * @file nvm3_default.c
 * @brief NVM3 definition of the default data structures.
 * @version 5.4.0
 *******************************************************************************
 * @section License
 * <b>(C) Copyright 2017 Silicon Labs, http://www.silabs.com</b>
 *******************************************************************************
 *
 * This file is licensed under the Silabs License Agreement. See the file
 * "Silabs_License_Agreement.txt" for details. Before using this software for
 * any purpose, you must agree to the terms of that agreement.
 *
 ******************************************************************************/

#include "nvm3.h"

#ifndef NVM3_DEFAULT_CACHE_SIZE
#define NVM3_DEFAULT_CACHE_SIZE  100
#endif
#ifndef NVM3_DEFAULT_NVM_SIZE
#define NVM3_DEFAULT_NVM_SIZE  36864
#endif

#if defined (__ICCARM__)

#ifndef __NVM3__
#define __NVM3__ "SIMEE"
#endif

__root uint8_t nvm3Storage[NVM3_DEFAULT_NVM_SIZE] @ __NVM3__;

#elif defined (__GNUC__)

#ifndef __NVM3__
#define __NVM3__ ".simee"
#endif

__attribute__((used)) uint8_t nvm3Storage[NVM3_DEFAULT_NVM_SIZE] __attribute__ ((section(__NVM3__)));

#else
#error "Unsupported toolchain"
#endif

nvm3_Handle_t  nvm3_defaultHandleData;
nvm3_Handle_t *nvm3_defaultHandle = &nvm3_defaultHandleData;

static nvm3_CacheEntry_t defaultCache[NVM3_DEFAULT_CACHE_SIZE];

nvm3_Init_t    nvm3_defaultInitData =
{
  (nvm3_HalPtr_t) nvm3Storage,
  NVM3_DEFAULT_NVM_SIZE,
  defaultCache,
  NVM3_DEFAULT_CACHE_SIZE,
  NVM3_DEFAULT_MAX_OBJECT_SIZE
};

nvm3_Init_t   *nvm3_defaultInit = &nvm3_defaultInitData;
