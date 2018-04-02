// *****************************************************************************
// * end-device-move.c
// *
// * Code common to SOC and host to handle moving (i.e. rejoining) to a new
// * parent device.
// *
// * Copyright 2012 by Ember Corporation. All rights reserved.              *80*
// *****************************************************************************

#include "app/framework/include/af.h"
#include "app/framework/util/util.h"

// *****************************************************************************
// Globals

#if defined(EMBER_SCRIPTED_TEST)
uint8_t emAfRejoinAttemptsMax = 3;
  #define EMBER_AF_REJOIN_ATTEMPTS_MAX emAfRejoinAttemptsMax
#endif

extern EmberEventControl emberAfPluginEndDeviceSupportMoveNetworkEventControls[];

typedef struct {
  uint8_t moveAttempts; // counts *completed* attempts, i.e. 0 on 1st attempt
#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
  // If sub-GHz network find is enabled, we try to rejoin on each page in turn.
  // The rejoining sequence uses a sliding scale:
  // * moveAttempts == 0 ... the current channel only
  // * moveAttempts == 1 ... the current page only
  // * moveAttempts > 1 .... all pages starting from 0
  // NOTE 1: 'page' is needed *only* if sub-GHz support is enabled, as otherwise
  // "moveAttempts == 1" and "moveAttempts > 1" are functionally identical.
  // NOTE 2: if EMBER_AF_REJOIN_ATTEMPTS_MAX is 2 or less, we skip rejoining
  // on the current page and go from the current channel straight to all pages.
  uint8_t page;
#endif
} State;
static State states[EMBER_SUPPORTED_NETWORKS];

#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
  #if EMBER_AF_REJOIN_ATTEMPTS_MAX > 2
    #define MOVE_ATTEMPTS_BEFORE_TRYING_ALL_PAGES 2
  #else
    #define MOVE_ATTEMPTS_BEFORE_TRYING_ALL_PAGES 1
  #endif
#endif

#define NEVER_STOP_ATTEMPTING_REJOIN 0xFF
#define MOVE_DELAY_QS (10 * 4)

// *****************************************************************************
// Functions

static void scheduleMoveEvent(void)
{
  uint8_t networkIndex = emberGetCurrentNetwork();
  State *state = &states[networkIndex];

  if (EMBER_AF_REJOIN_ATTEMPTS_MAX == NEVER_STOP_ATTEMPTING_REJOIN
      || state->moveAttempts < EMBER_AF_REJOIN_ATTEMPTS_MAX) {
#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
    if (state->moveAttempts >= MOVE_ATTEMPTS_BEFORE_TRYING_ALL_PAGES) {
      emberAfAppPrintln("%p %d: %d, page %d", "Schedule move nwk",
                        networkIndex,
                        state->moveAttempts,
                        state->page);
    } else
#endif
    emberAfAppPrintln("%s %d: %d", "Schedule move nwk",
                      networkIndex,
                      state->moveAttempts);
    emberAfNetworkEventControlSetDelayQS(emberAfPluginEndDeviceSupportMoveNetworkEventControls,
                                         (state->moveAttempts == 0
#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
                                          || (state->moveAttempts >= MOVE_ATTEMPTS_BEFORE_TRYING_ALL_PAGES
                                              && state->page > 0)
#endif
                                          ? 0
                                          : MOVE_DELAY_QS));
  } else {
    emberAfAppPrintln("Max move limit reached nwk %d: %d",
                      networkIndex,
                      state->moveAttempts);
    emberAfStopMoveCallback();
  }
}

bool emberAfMoveInProgressCallback(void)
{
  return emberAfNetworkEventControlGetActive(emberAfPluginEndDeviceSupportMoveNetworkEventControls);
}

bool emberAfStartMoveCallback(void)
{
  if (!emberAfMoveInProgressCallback()) {
    scheduleMoveEvent();
    return true;
  }
  return false;
}

void emberAfStopMoveCallback(void)
{
  uint8_t networkIndex = emberGetCurrentNetwork();
  states[networkIndex].moveAttempts = 0;
#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
  states[networkIndex].page = 0;
#endif
  emberEventControlSetInactive(emberAfPluginEndDeviceSupportMoveNetworkEventControls[networkIndex]);
}

static bool checkForWellKnownTrustCenterLinkKey(void)
{
#if !defined(EMBER_AF_PLUGIN_END_DEVICE_SUPPORT_ALLOW_REJOINS_WITH_WELL_KNOWN_LINK_KEY)
  EmberKeyStruct keyStruct;
  EmberStatus status = emberGetKey(EMBER_TRUST_CENTER_LINK_KEY, &keyStruct);

  const EmberKeyData smartEnergyWellKnownTestKey = SE_SECURITY_TEST_LINK_KEY;
  const EmberKeyData zigbeeAlliance09Key = ZIGBEE_PROFILE_INTEROPERABILITY_LINK_KEY;

  if (status != EMBER_SUCCESS) {
    // Assume by default we have a well-known key if we failed to retrieve it.
    // This will prevent soliciting a TC rejoin that might expose the network
    // key such that a passive attacker can obtain the key.  Better to be
    // conservative in this circumstance.
    return true;
  }

  if ((0 == MEMCOMPARE(emberKeyContents(&(keyStruct.key)),
                       emberKeyContents(&(smartEnergyWellKnownTestKey)),
                       EMBER_ENCRYPTION_KEY_SIZE))
      || (0 == MEMCOMPARE(emberKeyContents(&(keyStruct.key)),
                          emberKeyContents(&(zigbeeAlliance09Key)),
                          EMBER_ENCRYPTION_KEY_SIZE))) {
    return true;
  }
#endif

  return false;
}

#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
typedef struct {
  uint8_t page;
  uint8_t channel;
} PgChan;

// A getChannelMask() helper, factored out of getChannelMask() because it is
// only needed in some cases.
static PgChan getNetworkParamsForChannelMask(void)
{
  EmberNodeType nodeTypeResult = EMBER_UNKNOWN_DEVICE;
  EmberNetworkParameters networkParams = { 0 };
  emberAfGetNetworkParameters(&nodeTypeResult, &networkParams);
  PgChan pgChan;

  pgChan.page = emberAfGetPageFrom8bitEncodedChanPg(networkParams.radioChannel);
  pgChan.channel = emberAfGetChannelFrom8bitEncodedChanPg(networkParams.radioChannel);
  return pgChan;
}

// Get the channel mask for the current move attempt, following the sequence
// outlined in the comment in the struct State definition above.
static uint32_t getChannelMask(const State *state)
{
  PgChan pgChan;

  switch (state->moveAttempts) {
    case 0:
      // The first rejoin attempt. Use the current channel.
      pgChan = getNetworkParamsForChannelMask();
      return EMBER_PAGE_CHANNEL_MASK_FROM_CHANNEL_NUMBER(pgChan.page, pgChan.channel);
#if MOVE_ATTEMPTS_BEFORE_TRYING_ALL_PAGES > 1
    case 1:
      // The second attempt. Try rejoining on the current page.
      pgChan = getNetworkParamsForChannelMask();
      break;
#endif
    default:
      // Any further attempt. Try rejoining on all pages in turn.
      // The state machine determines the page for this round.
      pgChan.page = state->page;
      break;
  }

  switch (pgChan.page) {
    case 0:
      return EMBER_ALL_802_15_4_CHANNELS_MASK;
    case 28:
      // We *could* use EMBER_PAGE_CHANNEL_MASK_FROM_CHANNEL_MASK(page, blabla)
      // and merge cases 28, 30 and 31 where "blabla" is the same value,
      // but this way is probably more efficient as the compiler will do the
      // calculation as opposed to having to compute it at runtime.
      return EMBER_PAGE_CHANNEL_MASK_FROM_CHANNEL_MASK(28, EMBER_ALL_SUBGHZ_CHANNELS_MASK_FOR_PAGES_28_30_31);
    case 29:
      return EMBER_PAGE_CHANNEL_MASK_FROM_CHANNEL_MASK(29, EMBER_ALL_SUBGHZ_CHANNELS_MASK_FOR_PAGES_29);
    case 30:
      return EMBER_PAGE_CHANNEL_MASK_FROM_CHANNEL_MASK(30, EMBER_ALL_SUBGHZ_CHANNELS_MASK_FOR_PAGES_28_30_31);
    case 31:
      return EMBER_PAGE_CHANNEL_MASK_FROM_CHANNEL_MASK(31, EMBER_ALL_SUBGHZ_CHANNELS_MASK_FOR_PAGES_28_30_31);
    default:
      // Return 0 for the current channel only. Rejoin will probably fail,
      // especially on sub-GHz, but since this is an impossible case anyway,
      // it does not really matter. Case included only for MISRA compliance.
      return 0;
  }
}
#endif

void emberAfPluginEndDeviceSupportMoveNetworkEventHandler(void)
{
  const uint8_t networkIndex = emberGetCurrentNetwork();
  State *state = &states[networkIndex];
  EmberStatus status;
  bool secure = (state->moveAttempts == 0);
  if (!secure && checkForWellKnownTrustCenterLinkKey()) {
    emberAfDebugPrintln("Will not attempt TC rejoin due to well-known key.");
    secure = true;
  }
#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
  const uint32_t channels = getChannelMask(state);
#else
  const uint32_t channels = (state->moveAttempts == 0
                             ? 0 // current channel
                             : EMBER_ALL_802_15_4_CHANNELS_MASK);
#endif

  status = emberFindAndRejoinNetworkWithReason(secure,
                                               channels,
                                               EMBER_AF_REJOIN_DUE_TO_END_DEVICE_MOVE);
  emberAfDebugPrintln("Move attempt %d nwk %d, channel mask 0x%4x: 0x%x",
                      state->moveAttempts,
                      networkIndex,
                      channels,
                      status);
  if (status == EMBER_SUCCESS) {
#ifdef EMBER_AF_PLUGIN_NETWORK_FIND_SUB_GHZ
    if (state->moveAttempts < MOVE_ATTEMPTS_BEFORE_TRYING_ALL_PAGES
        || state->page == EMBER_MAX_SUGBHZ_PAGE_NUMBER) {
      state->moveAttempts++;
      state->page = 0;
    } else if (state->page == 0) {
      state->page = EMBER_MIN_SUGBHZ_PAGE_NUMBER;
    } else {
      state->page++;
    }
#else
    state->moveAttempts++;
#endif
  } else {
    scheduleMoveEvent();
  }
}

void emberAfPluginEndDeviceSupportStackStatusCallback(EmberStatus status)
{
  if (status == EMBER_NETWORK_UP) {
    emberAfStopMoveCallback();
    return;
  }

  if (!emberStackIsPerformingRejoin()) {
    EmberNetworkStatus state = emberAfNetworkState();
    if (state == EMBER_JOINED_NETWORK_NO_PARENT) {
      emberAfStartMoveCallback();
    } else if (state == EMBER_NO_NETWORK) {
      emberAfStopMoveCallback();
    }
  }
}
