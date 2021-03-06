from . import halconfig_types as types
from . import halconfig_dependency as dep

name = "COEX"
displayname = "Coexistence"
description = "Coexistence between multiple radios. Radio hold-off, request, grant."
compatibility = dep.Dependency(mcu_type=dep.McuType.RADIO)  # = all
category = " Radio"
studio_module = {
    "basename" : "SDK.HAL.COEX",
    "modules" : [types.StudioFrameworkModule("BASE", [types.Framework.ZNET, types.Framework.THREAD, types.Framework.CONNECT]),
                 types.StudioFrameworkModule("BLE", types.Framework.BLE)],
    }
enable = {
    "define": "HAL_COEX_ENABLE",
    "description": "Enable radio coexistence",
}
options = {
    "BSP_COEX_REQ": {
        "type": types.Pin(),
        "description": "REQUEST signal",
        "subcategory": "REQUEST",
        "longdescription": "Pin used for REQUEST signal",
    },
    # depends on BSP_COEX_REQ
    "BSP_COEX_REQ_ASSERT_LEVEL": {
        "type": "enum",
        "description": "REQUEST assert signal level",
        "values": [types.EnumValue('1', 'High'),
                   types.EnumValue('0', 'Low')],
        "subcategory": "REQUEST",
        "longdescription": "Polarity of REQUEST signal",
    },
    # depends on BSP_COEX_REQ
    "HAL_COEX_REQ_SHARED": {
        "type": "boolean",
        "description": "Enable REQUEST shared mode",
        "defaultValue": "False",
        "subcategory": "REQUEST",
        "longdescription": "Configure the REQUEST signal for shared mode",
    },
    # depends on HAL_COEX_REQ_SHARED
    "HAL_COEX_REQ_BACKOFF":{
        "type": "uint8_t",
        "description": "Max REQUEST backoff mask [0-255]",
        "min": "0",
        "max": "255",
        "defaultValue": "15",
        "subcategory": "REQUEST",
        "longdescription": "Maximum backoff time in microseconds after REQUEST was deasserted",
    },
    # depends on BSP_COEX_REQ
    "HAL_COEX_REQ_WINDOW":{
        "type": "uint16_t",
        "description": "Assert time between REQUEST and RX/TX start (us) [BLE only]",
        "min": "0",
        "max": "5000",
        "defaultValue": "500",
        "subcategory": "REQUEST",
        "longdescription": "Specify the number of microseconds between asserting REQUEST and starting RX/TX (BLE only)",
    },
    # depends on BSP_COEX_REQ
    "HAL_COEX_RETRYRX_ENABLE": {
        "type": "boolean",
        "description": "Enable REQUEST receive retry",
        "defaultValue": "False",
        "subcategory": "REQUEST",
        "longdescription": "Enable the receive retry",
    },
    # depends on HAL_COEX_RETRYRX_ENABLE
    "HAL_COEX_RETRYRX_TIMEOUT": {
        "type": "uint8_t",
        "description": "REQUEST receive retry timeout(ms)",
        "min": "0",
        "max": "255",
        "defaultValue": "16",
        "subcategory": "REQUEST",
        "longdescription": "Receive retry REQ timeout in milliseconds",
    },
    # depends on BSP_COEX_PRI and HAL_COEX_RETRYRX_ENABLE
    "HAL_COEX_RETRYRX_HIPRI": {
        "type": "boolean",
        "description": "REQUEST receive retry assert PRIORITY",
        "defaultValue": "True",
        "subcategory": "REQUEST",
        "longdescription": "Enable the receive retry high priority",
    },
    "BSP_COEX_GNT": {
        "type": types.Pin(),
        "description": "GRANT signal",
        "subcategory": "GRANT",
        "longdescription": "Pin used for grant (GNT) signal",
    },
    "BSP_COEX_GNT_ASSERT_LEVEL": {
        "type": "enum",
        "description": "GRANT assert signal level",
        "values": [types.EnumValue('1', 'High'),
                   types.EnumValue('0', 'Low')],
        "subcategory": "GRANT",
        "longdescription": "Polarity of grant (GNT) signal",
    },
    "HAL_COEX_TX_ABORT": {
        "type": "boolean",
        "description": "Abort transmission mid-packet if GRANT is lost",
        "defaultValue": "False",
        "subcategory": "GRANT",
        "longdescription": "If grant signal is deasserted, local device aborts transmission",
    },
    "HAL_COEX_ACKHOLDOFF": {
        "type": "boolean",
        "description": "Disable ACKing when GRANT deasserted, RHO asserted, or REQUEST not secured (shared REQUEST only)",
        "defaultValue": "True",
        "subcategory": "GRANT",
        "longdescription": "Disable ACKing when GNT deasserted, RHO asserted, or REQ not secured (shared REQ only)",
    },
    "BSP_COEX_PRI": {
        "type": types.Pin(),
        "description": "PRIORITY signal",
        "subcategory": "PRIORITY",
        "longdescription": "Pin used for PRIORITY signal",
    },
    "BSP_COEX_PRI_ASSERT_LEVEL": {
        "type": "enum",
        "description": "PRIORITY assert signal level",
        "values": [types.EnumValue('1', 'High'),
                   types.EnumValue('0', 'Low')],
        "subcategory": "PRIORITY",
        "longdescription": "Polarity of PRIORITY signal",
    },
    # depends on BSP_COEX_PRI
    "HAL_COEX_PRI_SHARED": {
        "type": "boolean",
        "description": "Enable PRIORITY shared mode",
        "defaultValue": "False",
        "subcategory": "PRIORITY",
    },
    # depends on BSP_COEX_PRI
    "HAL_COEX_TX_HIPRI": {
        "type": "boolean",
        "description": "Assert PRIORITY when transmitting packet",
        "defaultValue": "True",
        "subcategory": "PRIORITY",
        "longdescription": "Assert a high priority when the local device is transmitting a packet",
    },
    # depends on BSP_COEX_PRI
    "HAL_COEX_RX_HIPRI": {
        "type": "boolean",
        "description": "Assert PRIORITY when receiving packet",
        "defaultValue": "True",
        "subcategory": "PRIORITY",
        "longdescription": "Assert a high priority when the local device is receiving a packet",
    },
    "BSP_COEX_RHO": {
        "type": types.Pin(),
        "description": "RHO signal",
        "subcategory": "Radio Hold Off",
        "longdescription": "Pin used for RHO signal",
    },
    "BSP_COEX_RHO_ASSERT_LEVEL": {
        "type": "enum",
        "description": "RHO assert signal level",
        "values": [types.EnumValue('1', 'High'),
                   types.EnumValue('0', 'Low')],
        "subcategory": "Radio Hold Off",
        "longdescription": "Polarity of the RHO signal level",
    },
}
