/***************************************************************************//**
 * @file nvm3.h
 * @brief NVM3 API definition.
 * @version 5.4.0
 *******************************************************************************
 * @section License
 * <b>(C) Copyright 2017 Silicon Labs, www.silabs.com</b>
 *******************************************************************************
 *
 * This file is licensed under the Silabs License Agreement. See the file
 * "Silabs_License_Agreement.txt" for details. Before using this software for
 * any purpose, you must agree to the terms of that agreement.
 *
 ******************************************************************************/

#ifndef NVM3_H
#define NVM3_H

#include <stdint.h>
#include <stdbool.h>
#include "nvm3_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************//**
 * @addtogroup emdrv
 * @{
 ******************************************************************************/

/***************************************************************************//**
 * @addtogroup NVM3
 * @{
 ******************************************************************************/

#define ECODE_NVM3_OK                               (ECODE_OK)                                   ///< Success return value
#define ECODE_NVM3_ERR_ALIGNMENT_INVALID            (ECODE_EMDRV_NVM3_BASE | 0x00000001U)        ///< Invalid data alignment
#define ECODE_NVM3_ERR_SIZE_TOO_SMALL               (ECODE_EMDRV_NVM3_BASE | 0x00000002U)        ///< Not enough nvm memory specified
#define ECODE_NVM3_ERR_NO_VALID_PAGES               (ECODE_EMDRV_NVM3_BASE | 0x00000003U)        ///< Initialisation aborded, no valid page found
#define ECODE_NVM3_ERR_PAGE_SIZE_NOT_SUPPORTED      (ECODE_EMDRV_NVM3_BASE | 0x00000004U)        ///< The page size is not supported
#define ECODE_NVM3_ERR_OBJECT_SIZE_NOT_SUPPORTED    (ECODE_EMDRV_NVM3_BASE | 0x00000005U)        ///< The object size is not supported
#define ECODE_NVM3_ERR_STORAGE_FULL                 (ECODE_EMDRV_NVM3_BASE | 0x00000006U)        ///< No more space available
#define ECODE_NVM3_ERR_NOT_OPENED                   (ECODE_EMDRV_NVM3_BASE | 0x00000007U)        ///< The module has not been sucessfully opened
#define ECODE_NVM3_ERR_OPENED_WITH_OTHER_PARAMETERS (ECODE_EMDRV_NVM3_BASE | 0x00000008U)        ///< The module has already been opened with other parameters
#define ECODE_NVM3_ERR_PARAMETER                    (ECODE_EMDRV_NVM3_BASE | 0x00000009U)        ///< Error in parameter
#define ECODE_NVM3_ERR_KEY_INVALID                  (ECODE_EMDRV_NVM3_BASE | 0x0000000AU)        ///< Invalid key ID
#define ECODE_NVM3_ERR_KEY_NOT_FOUND                (ECODE_EMDRV_NVM3_BASE | 0x0000000BU)        ///< Error, key not found
#define ECODE_NVM3_ERR_OBJECT_IS_NOT_DATA           (ECODE_EMDRV_NVM3_BASE | 0x0000000CU)        ///< Trying to access a data object which is currently a counter object
#define ECODE_NVM3_ERR_OBJECT_IS_NOT_A_COUNTER      (ECODE_EMDRV_NVM3_BASE | 0x0000000DU)        ///< Trying to access a counter object which is currently a data object
#define ECODE_NVM3_ERR_ERASE_FAILED                 (ECODE_EMDRV_NVM3_BASE | 0x0000000EU)        ///< Erase failed
#define ECODE_NVM3_ERR_WRITE_DATA_SIZE              (ECODE_EMDRV_NVM3_BASE | 0x0000000FU)        ///< The object is too large
#define ECODE_NVM3_ERR_WRITE_FAILED                 (ECODE_EMDRV_NVM3_BASE | 0x00000010U)        ///< Error, error during the write operation
#define ECODE_NVM3_ERR_READ_DATA_SIZE               (ECODE_EMDRV_NVM3_BASE | 0x00000011U)        ///< Trying to read more than the actual object size
#define ECODE_NVM3_ERR_READ_COUNTER_SIZE            (ECODE_EMDRV_NVM3_BASE | 0x00000012U)        ///< Trying to read a counter with length different from 4
#define ECODE_NVM3_ERR_INT_WRITE_TO_NOT_ERASED      (ECODE_EMDRV_NVM3_BASE | 0x00000020U)        ///< Write to memory that is not erased
#define ECODE_NVM3_ERR_INT_ADDR_INVALID             (ECODE_EMDRV_NVM3_BASE | 0x00000021U)        ///< Internal error trying to access invalid memory
#define ECODE_NVM3_ERR_INT_KEY_MISMATCH             (ECODE_EMDRV_NVM3_BASE | 0x00000022U)        ///< Key validaton failure
#define ECODE_NVM3_ERR_INT_SIZE_ERROR               (ECODE_EMDRV_NVM3_BASE | 0x00000023U)        ///< Internal size mismatch error
#define ECODE_NVM3_ERR_INT_EMULATOR                 (ECODE_EMDRV_NVM3_BASE | 0x00000024U)        ///< Internal Emulator error
#define ECODE_NVM3_ERR_INT_TEST                     (ECODE_EMDRV_NVM3_BASE | 0x00000025U)        ///< Internal Test error

/***************************************************************************//**
 *  @brief NVM3 default maximum object size. Because the current NVM3 version
 *  only supports the maximum object size equal to NVM3_MAX_OBJECT_SIZE,
 *  this macro can be used to set the maxObjectSize in the initialization structure.
 *  Future versions of NVM3 may support other sizes.
 ******************************************************************************/
#define NVM3_MAX_OBJECT_SIZE          4096U                             ///< Maximum object size
#define NVM3_DEFAULT_MAX_OBJECT_SIZE  NVM3_MAX_OBJECT_SIZE              ///< The default max object size

/***************************************************************************//**
 *  @brief NVM3 static data definition helper macro for applications using linker
 *  script placement of NVM memory area. This macro exports the section 'name'_section
 *  to the linker. The section name must be placed by the user in a linker script
 *  at an address aligned with the page size of the underlying memory system. The size of
 *  the NVM area must be a multiple of the page size.
 *  @n This macro also allocates static NVM3 cache.
 *  @n Use this macro with @ref NVM3_DEFINE_SECTION_INIT_DATA() to create initialization
 *  data for @ref nvm3_open(). See @ref nvm3_example section for usage examples.
 ******************************************************************************/
#define NVM3_DEFINE_SECTION_STATIC_DATA(name, nvmSize, cacheSize) \
  static nvm3_CacheEntry_t name##_cache[cacheSize];               \
  static const uint8_t name##_nvm[nvmSize]                        \
  SL_ATTRIBUTE_SECTION(STRINGIZE(name##_section))

/***************************************************************************//**
 *  @brief NVM3 initialization data helper macro to be used with @ref
 *  NVM3_DEFINE_SECTION_STATIC_DATA(). The @p name parameter in both macros must
 *  match.
 *  @n Call @ref nvm3_open() after this macro to initialize NVM3. See @ref
 *  nvm3_example section for code examples.
 ******************************************************************************/
#define NVM3_DEFINE_SECTION_INIT_DATA(name)           \
  nvm3_Init_t name =                                  \
  {                                                   \
    (nvm3_HalPtr_t)name##_nvm,                        \
    sizeof(name##_nvm),                               \
    name##_cache,                                     \
    sizeof(name##_cache) / sizeof(nvm3_CacheEntry_t), \
    NVM3_DEFAULT_MAX_OBJECT_SIZE,                     \
  }

#define NVM3_KEY_INVALID            0xFFFFFFFFU                   ///< Invalid key identifier
#define NVM3_KEY_SIZE               20U                           ///< Unique object key identifier size
#define NVM3_KEY_MASK               ((1U << NVM3_KEY_SIZE) - 1U)  ///< Unique object key identifier mask
#define NVM3_KEY_MIN                0U                            ///< Minimum object key value
#define NVM3_KEY_MAX                NVM3_KEY_MASK                 ///< Maximum object key value

#define NVM3_OBJECTTYPE_DATA        0U                            ///< The object is data
#define NVM3_OBJECTTYPE_COUNTER     1U                            ///< The object is a counter

/// @brief The data type for object keys. Only the 20 least significant bits are used.
typedef uint32_t nvm3_ObjectKey_t;

/// @brief The datatype for each cache entry. The cache must be an array of these.
typedef struct nvm3_CacheEntry {
  nvm3_ObjectKey_t key;           ///< key
  void             *ptr;          ///< pointer
} nvm3_CacheEntry_t;

/// @cond DO_NOT_INCLUDE_WITH_DOXYGEN

typedef struct nvm3_Cache {
  nvm3_CacheEntry_t *entryPtr;
  size_t            entrySize;
  size_t            entryIdx;
  size_t            statMaxIdx;
  size_t            statCntHit;
  size_t            statCntMiss;
} nvm3_Cache_t;

typedef struct {
  nvm3_HalPtr_t nvmAdr;           // NVM address
  size_t nvmSize;                 // NVM size
  nvm3_Cache_t cache;             // Cache management data
  size_t maxObjectSize;           // The maximum object size supported
  size_t totalNvmPageCnt;         // The total number of NVM pages
  size_t validNvmPageCnt;         // The number of valid NVM pages
  size_t fifoFirstIdx;            // Fifo bottom page
  void *fifoFirstObj;             // First object location
  void *fifoNextObj;              // Next free object location
  size_t unusedNvmSize;           // The size of the unused NVM
  bool hasBeenOpened;             // Open information
} nvm3_Handle_t;

/// @endcond

/// @brief NVM3 initialization data.
typedef struct {
  nvm3_HalPtr_t nvmAdr;         ///< NVM memory area base address
  size_t nvmSize;               ///< NVM memory area size in bytes
  nvm3_CacheEntry_t *cachePtr;  ///< A pointer to cache
  size_t cacheSize;             ///< The size of the cache
  size_t maxObjectSize;         ///< The maximum object size supported
} nvm3_Init_t;

/***************************************************************************//**
 * @brief
 *  Open a NVM3 driver instance. A NVM3 instance is represented by a handle
 *  keeping information about the state. A successful open will initialize
 *  the cache with information about the objects already in the NVM-memory.
 *  @note A new call to the @ref nvm3_open will return @ref ECODE_NVM3_OK as
 *  long as the open parameters are identical to the parameters used in previous
 *  successfull open calls.
 *  Several NVM3 instances using different handles must NOT overlap NVM-memory.
 *  If the application wants to change some of the parameters, this can be done
 *  by first calling @ref nvm3_close and then @ref nvm3_open again.
 *
 * @param[out] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] i
 *   A pointer to an NVM3 driver initialization data.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success and a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_open(nvm3_Handle_t *h, const nvm3_Init_t *i);

/***************************************************************************//**
 * @brief
 *  Close the NVM3 driver instance.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @return
 *   @ref ECODE_NVM3_OK is always returned.
 ******************************************************************************/
Ecode_t nvm3_close(nvm3_Handle_t *h);

/***************************************************************************//**
 * @brief
 *  Write the object value identified with the key to NVM.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @param[in] value
 *   A pointer to the object data to write.
 *
 * @param[in] len
 *   The size of the object data in number of bytes.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_writeData(nvm3_Handle_t *h, nvm3_ObjectKey_t key, const void *value, size_t len);

/***************************************************************************//**
 * @brief
 *  Read the object data identified with a given key from NVM.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @param[out] value
 *   A pointer to the application data buffer. The read function will copy
 *   the data to this location.
 *
 * @param[in] maxLen
 *   The maximum object size in number of bytes. The @ref nvm3_findObject() function
 *   can be used to find the actual size.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_readData(nvm3_Handle_t *h, nvm3_ObjectKey_t key, void *value, size_t maxLen);

/***************************************************************************//**
 * @brief
 *  Find the type and size of an object in NVM.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @param[out] type
 *   A pointer to the location where NVM3 shall write the object type. The type can
 *   be either @ref NVM3_OBJECTTYPE_DATA or @ref NVM3_OBJECTTYPE_COUNTER.
 *
 * @param[out] len
 *   A pointer to the location where NVM3 shall write the object size.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_findObject(nvm3_Handle_t *h, nvm3_ObjectKey_t key,
                        uint32_t *type, size_t *len);

/***************************************************************************//**
 * @brief
 *  Create a list of object keys for valid objects in NVM.
 *
 * @note
 *  The function @ref nvm3_countObjects() is also provided to count the
 *  number of valid objects.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[out] keys
 *   A pointer to a buffer for the key list.
 *
 * @param[in] sizeKeys
 *   The size of the key list buffer.
 *
 * @param[in] keyMin
 *   The lower search key. Set to @ref NVM3_KEY_MIN to match all keys.
 *
 * @param[in] keyMax
 *   The upper search key. Set to @ref NVM3_KEY_MAX to match all keys.
 *
 * @return
 *   The number of keys written to the key list. This value is less than or equal
 *   to @p sizeKeys.
 ******************************************************************************/
size_t  nvm3_enumObjects(nvm3_Handle_t *h, nvm3_ObjectKey_t *keys,
                         size_t sizeKeys, nvm3_ObjectKey_t keyMin,
                         nvm3_ObjectKey_t keyMax);

/***************************************************************************//**
 * @brief
 *  Delete an object from NVM.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_deleteObject(nvm3_Handle_t *h, nvm3_ObjectKey_t key);

/***************************************************************************//**
 * @brief
 *  Store a counter in NVM.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @param[in] value
 *   The counter value to write.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_writeCounter(nvm3_Handle_t *h, nvm3_ObjectKey_t key, uint32_t value);

/***************************************************************************//**
 * @brief
 *  Read a counter value from NVM.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @param[out] value
 *   A pointer to the counter location. The read function will copy
 *   the counter value to this location.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_readCounter(nvm3_Handle_t *h, nvm3_ObjectKey_t key, uint32_t *value);

/***************************************************************************//**
 * @brief
 *  Increment a counter object value by 1 and read out optionally.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] key
 *   A 20-bit object identifier.
 *
 * @param[out] value
 *   A pointer to the counter readout location. The counter is incremented before the value
 *   is written to this location. Set this value to NULL to ignore readout.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_incrementCounter(nvm3_Handle_t *h, nvm3_ObjectKey_t key, uint32_t *value);

/***************************************************************************//**
 * @brief
 *  Delete all objects in NVM.
 *
 * @note
 *  It is not necessary to call this function to get NVM3 into an
 *  initial valid state.
 *
 * @warning
 *  Execution time depends on the configured NVM size and may therefore be
 *  significant.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_eraseAll(nvm3_Handle_t *h);

/***************************************************************************//**
 * @brief
 *  Get the number of page erases of the most erased page in the NVM area since
 *  the first initialization.
 *
 * @note
 *  Except for pages marked as bad, pages will have an erase count equal to the
 *  most erased or one less because of the wear levelling algorithm.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @param[in] eraseCnt
 *   A pointer to the location where the NVM3 shall place the page
 *   erasure counter value.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_getEraseCount(nvm3_Handle_t *h, uint32_t *eraseCnt);

/***************************************************************************//**
 * @brief
 *  Execute a repack operation. NVM3 will copy data or erase pages when repacking
 *  is needed. A call to @ref nvm3_repack() may block access to the non-volatile
 *  memory for up to one page erasure time plus an small execution overhead.
 *  Exact worst-case timing characteristics can be found in the data sheet for the
 *  part.
 *
 * @note
 *  It is not mandatory to call @ref nvm3_repack() because the functions that
 *  write data to NVM will trigger a repack if needed. Because a
 *  repack operation may be time consuming, the application may want to be
 *  in control of when repacking occures by calling this function.
 *
 *  More information about the repack operation can be found in the
 * @ref nvm3_repack section.
 *
 * @param[in] h
 *   Pointer to an NVM3 driver handle.
 *
 * @return
 *   @ref ECODE_NVM3_OK on success or a NVM3 @ref Ecode_t on failure.
 ******************************************************************************/
Ecode_t nvm3_repack(nvm3_Handle_t *h);

/***************************************************************************//**
 * @brief
 *   Check the internal status of NVM3 and return true if a repack
 *   operation is required. The application must call @ref nvm3_repack() to
 *   perform the actual repack operation.
 *
 * @param[in] h
 *   Pointer to NVM3 driver handle.
 *
 * @return
 *   true if repacking is needed, false if repacking is not needed.
 ******************************************************************************/
bool    nvm3_repackNeeded(nvm3_Handle_t *h);

/***************************************************************************//**
 * @brief
 *  Count valid objects.
 *
 * @param[in] h
 *   A pointer to an NVM3 driver handle.
 *
 * @return
 *   The number of valid objects.
 ******************************************************************************/
__STATIC_INLINE size_t nvm3_countObjects(nvm3_Handle_t *h)
{
  return nvm3_enumObjects(h, NULL, 0, NVM3_KEY_MIN, NVM3_KEY_MAX);
}

/** @} (end addtogroup NVM3) */
/** @} (end addtogroup emdrv) */

#ifdef __cplusplus
}
#endif

#include "nvm3_default.h"

/************ THIS SECTION IS FOR DOCUMENTATION ONLY !**********************//**
 * @addtogroup emdrv
 * @{
 * @addtogroup NVM3
 * @brief NVM3 Non-Volatile Memory Management driver
 * @{

   @note <em><strong> Quality Announcement -
   This driver is Beta tested only. Silicon Labs will NOT support any production
   deployments with this Beta release. Production deployments will only be supported
   with the GA version of NVM3. This version is intended for lab and evaluation purpose only.
   </strong></em>
   @n @n


   @details
   @li @ref nvm3_intro
   @li @ref nvm3_objects
   @li @ref nvm3_repack
   @li @ref nvm3_cache
   @li @ref nvm3_api
   @li @ref nvm3_memory_placement
   @li @ref nvm3_conf
   @li @ref nvm3_example

   @n @section nvm3_intro Introduction
   The NVM3 driver provides a way for an application to safely store and
   retrieve variable size objects in a page based non-volatile memory.
   Objects are identified with 20-bit object identifiers denoted as keys.

   The driver is designed to use pages in a sequential order to provide equal
   usage and wear. The driver is resilient to power loss or reset events,
   ensuring that objects retrieved from the driver are in a valid state. A
   valid object will always be the last successfully stored object. NVM3 can
   detect NVM defects and mark pages as unusable. NVM3 will continue to operate
   on good pages after defect pages are detected.

   @n @section nvm3_objects Objects
   A NVM3 object is a piece of data that can be stored in NVM. The object
   is handled as an array of bytes up to @ref NVM3_MAX_OBJECT_SIZE in size.
   NVM3 can handle two types of objects.
   -# Regular data objects. Data objects can store information of
   any size up to maximum @ref NVM3_MAX_OBJECT_SIZE bytes.
   -# 32-bit counter objects. Counter objects can store 32-bit counters that are
   accessed with a separate set of API functions. The counter object is designed
   to be compact while minimizing memory wear in applications that require
   frequent persistent counter increments.

   See @ref nvm3_api for more details on the API.

   @n @section nvm3_repack Repacking
   As the NVM fills up, there will be a point where it can no longer store
   additional objects. A repacking operation is required to release out-of-date
   objects to free up NVM. Because erasing pages takes a long time,
   the NVM3 driver does not trigger the process by itself unless free memory
   reaches a critical low level. Instead, the application must trigger the
   repacking process by calling the @ref nvm3_repack() function.
   During the call, the NVM3 will either move data to a new page or erase an
   obsolete page. At most, the call will block for a period equal to a page
   erasure time plus a small execution overhead. Page erasure time for the
   EFM32 or EFR32 parts can be found in the data sheet.

   The application can also use @ref nvm3_repackNeeded() to determine when to
   execute repacking. The function @ref nvm3_repack() will only perform a
   repack operation if needed.

   @note Any NVM3 function that modifies a data or counter object may trigger
   an automatic repacking operation if free memory has reached a critical low level.

   NVM3 uses two internal thresholds for repacking:
   -# Soft low memory threshold. This is the threshold used by @ref nvm3_repackNeeded().
     The soft threshold is set to reduce memory wear to a minimum. @ref nvm3_repack()
     will not perform repacking unless free memory is below this threshold.
   -# Hard low memory threshold. This is the threshold used to force repacking when
     free memory reaches a critical low level.

   Soft and hard low memory thresholds are not configurable.

   @n @section nvm3_cache Caching
   Caching is an optional feature. The NVM3 cache is an object location lookup
   cache, data is not stored in the cache. Using the cache will speed up accesses
   to the NVM3, and the performance will very much depend on objects beeing
   available in the cache. To ensure that the cache can hold all neccesary
   information, it must be configured to a size equivalent or larger than the
   number of objects stored in NVM. If the cache is available,
   the driver will first look in the cache to find the position of the object in NVM.
   If the object position is not found in the cache, the object position will be
   found by searching the NVM. The search will start at the last stored object
   and search all the way to the oldest object. If the object is found, the cache
   is updated accordingly.

   It is the application that must allocate and support the data for the cache,
   see the @ref nvm3_open function for more details.
   @note The cache is fully initialized by @ref nvm3_open() and automatically
   updated by any subsequent write, read, or delete function call.

   @n @section nvm3_api The API
   This section contains brief descriptions of the API functions. For
   more information about parameters and return values see the Function
   Documentation section. Most functions return an @ref Ecode_t that has the
   value @ref ECODE_NVM3_OK on success or see @ref nvm3.h for other values.

   The application code must include the @ref nvm3.h header file.

   @ref nvm3_open() and @ref nvm3_close().
   @n Functions to open and close an NVM3 instance. @ref nvm3_open() takes a handle
   of type nvm3_Handle_t and initialization data of type @ref nvm3_Init_t.
   The helper macro pair @ref NVM3_DEFINE_SECTION_STATIC_DATA() and
   @ref NVM3_DEFINE_SECTION_INIT_DATA() are provided to simplify initialization
   data definition. For usage examples, see the @ref nvm3_example section.

   @ref nvm3_findObject(),
   @ref nvm3_enumObjects(), @ref nvm3_deleteObject() and nvm3_countObjects()
   @n Functions for regular objects. @ref nvm3_enumObjects() provides a way to get a
   list of keys to valid objects in the NVM. The search can also be constrained.
   @ref nvm3_countObjects() can be useful at startup to distinguish between a
   first startup without any valid objects present and later reboots with valid
   objects persistently stored in NVM.

   @ref nvm3_writeData() and @ref nvm3_readData()
   @n Functions to write and read data objects.

   @ref nvm3_writeCounter(),  @ref nvm3_readCounter() and @ref nvm3_incrementCounter()
   @n Functions to write, increment, and read 32-bit counter objects.

   @ref nvm3_eraseAll()
   @n Erase all objects in NVM.

   @ref nvm3_getEraseCount()
   @n Return the erasure count for the most erased page in NVM.

   @ref nvm3_repack() and @ref nvm3_repackNeeded()
   @n Manage NVM3 repacking operation.

   @n @section nvm3_memory_placement Memory Placement
   The application is responsible for placing the NVM area correctly. Minimum
   requirements for memory placement are:
   -# NVM area start address must be aligned with the page size of the underlying
    memory system.
   -# NVM area size must be a multiple of the page size.
   -# Minimim required NVM area size:
     - For page size of 1kB: 10 pages
     - For page size of 2kB: 6 pages
     - For page size of 4kB: 4 pages

   Two macros are provided to support the creation of the NVM area and initialization
   data; @ref NVM3_DEFINE_SECTION_STATIC_DATA() and @ref NVM3_DEFINE_SECTION_INIT_DATA().
   A linker section called 'name'_section is defined by @ref NVM3_DEFINE_SECTION_STATIC_DATA().
   The NVM area is placed within the linker section. The application linker script
   must place the section according to the requirements above. An error is returned
   by @ref nvm3_open() on alignment or size violation.

   @n @section nvm3_conf Configuration Options
   There are no compile-time configuration options for NVM3. All configuration
   parameters are contained in @ref nvm3_Init_t.

   @n @section nvm3_example Examples

   Example 1 shows initialization, usage of data objects and repacking.

   @include nvm3_example_1.c

   Example 2 shows initialization and usage of counter objects. The
   counter object uses a compact way of storing a 32-bit counter value while minimizing
   NVM wear.

   @include nvm3_example_2.c

 * @} end group NVM3 ********************************************************
 * @} end group emdrv ****************************************************/

#endif /* NVM3_H */
