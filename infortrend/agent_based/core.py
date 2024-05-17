#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Some basic code for the Infortrend plugin.

# Copyright (C) 2024 Max Planck Institute for Multidisciplinary Sciences
# Author: Marco Roose <marco.roose@mpinat.mpg.de>
# checks using CheckMK API version v2
# Credits: Heinlein Support (Infortrend plugin from https://github.com/HeinleinSupport/check_mk_extensions)
# License: GNU General Public License v2
"""

import dataclasses
import re
from enum import IntEnum
from typing import Any, Literal


def saveint(some_value: Any) -> int | Literal['']:
    """Try to convert to integer or return an empty string."""
    try:
        return int(some_value)
    except ValueError:
        return ''


class InfortrendChassisSensorTypeEnum(IntEnum):
    """Enum to "translate" OID .1.3.6.1.4.1.1714.1.1.9.1.6 sensor types."""

    POWER_SUPPLY = 1
    FAN = 2
    TEMPERATURE = 3
    UPS = 4
    VOLTAGE = 5
    CURRENT = 6
    DOOR = 9
    SPEAKER = 10
    BATTERY = 11
    LED = 12
    CBU = 13
    NET_IF = 14
    BACKPLANE = 15
    SLOT = 17
    ENCLOSURE_DRAWER = 18
    ENCLOSURE_MGMNT = 31


@dataclasses.dataclass
class InfortrendChassisSensorSection:
    """Section for the representation fo IFT chassis sensor data from SNMP."""

    sensor_status: int | Literal['']
    sensor_type: int | Literal['']
    metric_value_raw: int | Literal['']
    metric_unit_raw: Any
