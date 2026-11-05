"""Constants for the GermGuardian BLE integration."""

DOMAIN = "germguardian"

CONF_MASTER_UUID = "master_uuid"
CONF_KEY = "local_key"
CONF_MODEL = "model"
CONF_PROTOCOL = "protocol_number"

# Retail model -> internal unit name (both speak the same protocol).
MODELS = {
    "CDAP4500BCA": "APZ-451",
    "CDAP5500BCA": "APZ-453",
}

# 0xEEF3C48D is the only protocol number seen on real hardware (an APZ-451).
DEFAULT_PROTOCOL = 0xEEF3C48D

FEF8_UUID = "0000fef8-0000-1000-8000-00805f9b34fb"
MASTER_PREFIX = "00000000-24f6-4000-a000-"

# How often Home Assistant connects to read the purifier's state (an option). Each check is a
# full Bluetooth connection, so fewer checks mean less work for the Bluetooth adapter.
# 0 = never on its own: only when you send a command (and once at startup).
CONF_UPDATE_INTERVAL = "update_interval"
DEFAULT_UPDATE_INTERVAL = 60
UPDATE_INTERVAL_CHOICES = {
    "30": "Every 30 seconds",
    "60": "Every minute (default)",
    "120": "Every 2 minutes",
    "300": "Every 5 minutes",
    "900": "Every 15 minutes",
    "0": "Only when I send a command",
}

# Replacement intervals (hours) for current firmware.
FILTER_LIFE_HOURS = 4380
BULB_LIFE_HOURS = 7300
