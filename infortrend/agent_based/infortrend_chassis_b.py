#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Infortrend SNMP based check for chassis sensor status using CheckMK API version v2.

Copyright (C) 2024 Max Planck Institute for Multidisciplinary Sciences
Author: Marco Roose <marco.roose@mpinat.mpg.de>

Credits: Heinlein Support (Infortrend plugin from https://github.com/HeinleinSupport/check_mk_extensions)
License: GNU General Public License v2
"""

from types import MappingProxyType
from typing import Dict, Iterator

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    SimpleSNMPSection,
    SNMPTree,
    State,
    StringTable,
    all_of,
    contains,
    not_startswith,
)

from .core import (  # noqa: WPS300
    InfortrendChassisSensorSection,
    InfortrendChassisSensorTypeEnum,
    saveint,
)

# map used for conversion of SNMP values to readable output
STATUS_INFO_MAP = MappingProxyType({
    InfortrendChassisSensorTypeEnum.POWER_SUPPLY: {
        'bits': {
            0: (
                'Power supply functioning normally',
                'Power supply malfunctioning',
            ),
            6: (
                'Power supply is ON',
                'Power supply is OFF',
            ),
            7: (
                'Power supply IS present',
                'Power supply is NOT present',
            ),
        },
    },
    InfortrendChassisSensorTypeEnum.FAN: {
        'bits': {
            0: (
                'Fan functioning normally',
                'Fan malfunctioning',
            ),
            6: (
                'Fan is ON',
                'Fan is OFF',
            ),
            7: (
                'Fan IS present',
                'Fan is NOT present',
            ),
        },
    },
    InfortrendChassisSensorTypeEnum.TEMPERATURE: {
        'bits': {
            0: (
                'Temp. sensor functioning normally',
                'Temp. sensor malfunctioning',
            ),
            6: (
                'Temp. Sensor is Activated',
                'Temp. Sensor is NOT Activated',
            ),
            7: (
                'Temperature sensor IS present',
                'Temperature sensor is NOT present',
            ),
        },
        'adtl_info': {
            0: 'Temp. within safe range',
            2: 'Cold Temp. Warning',
            3: 'Hot Temp. Warning',
            4: 'Cold Temp. Limit Exceeded',
            5: 'Hot Temp. Limit Exceeded',
        },
        'adtl_func': lambda status: status >> 1 & 7,
    },
    InfortrendChassisSensorTypeEnum.UPS: {
        'bits': {
            0: (
                'Unit functioning normally',
                'Unit malfunctioning',
            ),
            1: (
                'AC Power present',
                'AC Power NOT present',
            ),
            6: (
                'UPS is ON',
                'UPS is OFF',
            ),
            7: (
                'UPS IS present',
                'UPS is NOT present',
            ),
        },
        'adtl_info': {
            0: 'battery fully charged',
            1: 'battery not fully charged',
            2: 'battery charge critically low',
            3: 'battery completely drained',
        },
        'adtl_func': lambda status: status >> 2 & 3,
    },
    InfortrendChassisSensorTypeEnum.VOLTAGE: {
        'bits': {
            0: (
                'Voltage sensor functioning normally',
                'Voltage sensor malfunctioning',
            ),
            6: (
                'Voltage Sensor is Activated',
                'Voltage Sensor is NOT Activated',
            ),
            7: (
                'Voltage sensor IS present',
                'Voltage sensor is NOT present',
            ),
        },
        'adtl_info': {
            0: 'Voltage within acceptable range',
            2: 'Low Voltage Warning',
            3: 'High Voltage Warning',
            4: 'Low Voltage Limit Exceeded',
            5: 'High Voltage Limit Exceeded',
        },
        'adtl_func': lambda status: status >> 1 & 7,
    },
    InfortrendChassisSensorTypeEnum.CURRENT: {
        'bits': {
            0: (
                'Current sensor functioning normally',
                'Current sensor malfunctioning',
            ),
            6: (
                'Current Sensor is Activated',
                'Current Sensor is NOT Activated',
            ),
            7: (
                'Current sensor IS present',
                'Current sensor is NOT present',
            ),
        },
        'adtl_info': {
            0: 'Current within acceptable range',
            3: 'Over Current Warning',
            5: 'Over Current Limit Exceeded',
        },
        'adtl_func': lambda status: status >> 1 & 7,
    },
    # Temperature Out-of-Range Flags
    8: {},
    InfortrendChassisSensorTypeEnum.DOOR: {
        'bits': {
            0: (
                'Door OK',
                'Door, door lock, or door sensor malfunctioning',
            ),
            1: (
                'Door is shut',
                'Door is open',
            ),
            6: (
                'Door lock engaged',
                'Door lock NOT engaged',
            ),
            7: (
                'Door IS present',
                'Door is NOT present',
            ),
        },
    },
    InfortrendChassisSensorTypeEnum.SPEAKER: {
        'bits': {
            0: (
                'Speaker functioning normally',
                'Speaker malfunctioning',
            ),
            6: (
                'Speaker is ON',
                'Speaker is OFF',
            ),
            7: (
                'Speaker IS present',
                'Speaker is NOT present',
            ),
        },
    },
    InfortrendChassisSensorTypeEnum.BATTERY: {
        'bits': {
            0: (
                'Battery functioning normally',
                'Battery malfunctioning',
            ),
            1: (
                'Battery charging OFF (or trickle)',
                'Battery charging ON',
            ),
            6: (
                'Battery-backup is enabled',
                'Battery-backup is disabled',
            ),
            7: (
                'Battery IS present',
                'Battery is NOT present',
            ),
        },
        'adtl_info': {
            0: 'battery fully charged',
            1: 'battery not fully charged',
            2: 'battery charge critically low',
            3: 'battery completely drained',
        },
        'adtl_func': lambda status: status >> 2 & 3,
    },
    InfortrendChassisSensorTypeEnum.LED: {
        'bits': {
            0: ('', ''),
            6: (
                'LED is active',
                'LED is inactive',
            ),
            7: (
                'LED is present',
                'LED is NOT present',
            ),
        },
    },
    InfortrendChassisSensorTypeEnum.CBU: {
        'bits': {
            0: (
                'Flash Device functioning normally',
                'Flash Device malfunctioning',
            ),
            6: (
                'Flash Device is enabled',
                'Flash Device is disabled',
            ),
            7: (
                'Flash Device is present',
                'Flash Device is NOT present',
            ),
        },
    },
    # Host Board
    InfortrendChassisSensorTypeEnum.NET_IF: {
        'bits': {
            0: (
                'Host Board IS present',
                '',
            ),
            7: (
                'Host Board IS present',
                'Host Board is NOT present',
            ),
        },
    },
    # Midplane/Backplane
    InfortrendChassisSensorTypeEnum.BACKPLANE: {
        'bits': {
            0: (
                'Midplane/Backplane',
                '',
            ),
        },
    },
    # Slot states
    InfortrendChassisSensorTypeEnum.SLOT: {
        'bits': {
            0: (
                'Slot sense circuitry functioning normally',
                'Slot sense circuitry malfunctioning',
            ),
            1: (
                'Device in slot has not been marked "needing replacement" or a replacement drive has been inserted',
                'Device in slot has been marked BAD and is awaiting replacement',
            ),
            2: (
                'Slot is activated so that drive can be accessed',
                'Slot NOT activated',
            ),
            6: (
                'Slot is NOT ready for insertion/removal',
                'Slot is ready for insertion/removal',
            ),
            7: (
                'Device inserted in slot',
                'Slot is empty',
            ),
        },
    },
    InfortrendChassisSensorTypeEnum.ENCLOSURE_DRAWER: {
        'bits': {
            0: (
                'Enclosure Drawer functioning normally',
                'Enclosure Drawer malfunctioning',
            ),
            6: (
                'Enclosure Drawer is closed',
                'Enclosure Drawer is opened',
            ),
            7: (
                'Enclosure Drawer is present',
                'Enclosure Drawer is NOT present',
            ),
        },
    },
    # Enclosure Management Services Controller
    InfortrendChassisSensorTypeEnum.ENCLOSURE_MGMNT: {
        'bits': {
            0: (
                'Enclosure Management Services Controller functioning normally',
                'Enclosure Management Services Controller malfunctioning',
            ),
            6: (
                'Enclosure Management Services Controller is closed',
                'Enclosure Management Services Controller is opened',
            ),
            7: (
                'Enclosure Management Services Controller is present',
                'Enclosure Management Services Controller is NOT present',
            ),
        },
    },
})

# define name and divider for conversion for metrics
SENSORS_WITH_METRIC = MappingProxyType({
    InfortrendChassisSensorTypeEnum.TEMPERATURE: {
        'divider': 10,
        'name': 'temp',
    },
    InfortrendChassisSensorTypeEnum.VOLTAGE: {
        'divider': 1000,
        'name': 'voltage',
    },
})


def parse_infortrend_chassis_sensors_b(string_table: StringTable) -> Dict[str, InfortrendChassisSensorSection]:
    """Parse SNMP data to a dict of InfortrendChassisSensorSection objects."""
    parsed = {}

    for line in string_table:
        name = line[0]
        parsed.setdefault(
            name,
            InfortrendChassisSensorSection(
                sensor_status=saveint(line[1]),
                sensor_type=saveint(line[2]),
                metric_value_raw=saveint(line[3]),
                metric_unit_raw=line[4],
            ),
        )

    return parsed


def discover_infortrend_chassis_sensors_b(section: Dict[str, InfortrendChassisSensorSection]) -> DiscoveryResult:
    """Discover sensors from parsed SNMP data."""
    for chassis_sensor_name in section.keys():
        if not chassis_sensor_name:
            continue
        yield Service(item=chassis_sensor_name)


def check_infortrend_chassis_sensors_b(
    item: str,
    section: Dict[str, InfortrendChassisSensorSection],
) -> Iterator[CheckResult | Metric]:
    """Perform checks and submit metrics."""
    sensor_data = section.get(item)

    if isinstance(sensor_data, InfortrendChassisSensorSection):
        sensor_type = sensor_data.sensor_type

        # submit metrics for sensors where this makes sense
        if sensor_type in SENSORS_WITH_METRIC.keys():
            name = SENSORS_WITH_METRIC[sensor_type]['name']
            value = sensor_data.metric_value_raw / SENSORS_WITH_METRIC[sensor_type]['divider']

            yield Metric(
                name,
                value,
            )

        # submit check results
        if sensor_data.sensor_status == 0:
            yield Result(
                state=State.OK,
                summary=f"{STATUS_INFO_MAP[sensor_data.sensor_type]['bits'][0][0]}",
            )
        elif sensor_data.sensor_status == 255:
            yield Result(
                state=State.UNKNOWN,
                summary='Status unknown',
            )
        else:
            for bit in STATUS_INFO_MAP[sensor_data.sensor_type]['bits'].keys():
                bit_set = (sensor_data.sensor_status & 1 << bit) >> bit
                if bit_set:
                    extended_status, status_info_text = (
                        State.CRIT,
                        f"{STATUS_INFO_MAP[sensor_data.sensor_type]['bits'][bit][bit_set]} (!)",
                    )
                else:
                    extended_status, status_info_text = (
                        State.OK,
                        STATUS_INFO_MAP[sensor_data.sensor_type]['bits'][bit][bit_set],
                    )

                if sensor_data.sensor_status == 64:
                    if sensor_data.sensor_type == InfortrendChassisSensorTypeEnum.LED:
                        extended_status, status_info_text = (
                            State.OK,
                            f'{status_info_text}, ',
                        )
                    else:
                        extended_status, status_info_text = (
                            State.CRIT,
                            f'{sensor_data.sensor_status} {status_info_text}',
                        )

                yield Result(
                    state=extended_status,
                    summary=status_info_text,
                )

    # fallback
    else:
        yield Result(
            state=State.UNKNOWN,
            summary=f'cannot parse: {sensor_data}',
        )


snmp_section_infortrend_chassis_b = SimpleSNMPSection(
    name='infortrend_chassis_b',
    detect=all_of(
        contains(oidstr='.1.3.6.1.2.1.1.1.0', value='nfortrend'),
        not_startswith(oidstr='.1.3.6.1.2.1.1.2.0', value='.1.3.6.1.4.1.1714.1.1'),
    ),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.1714.1.1.9.1',
        oids=[
            '8',  # name
            '13',  # status
            '6',  # type
            '9',  # value
            '10',  # unit
        ],
    ),
    parse_function=parse_infortrend_chassis_sensors_b,
)


check_plugin_infortrend_chassis_b = CheckPlugin(
    name='infortrend_chassis_b',
    sections=['infortrend_chassis_b'],
    service_name='IFT %s',
    discovery_function=discover_infortrend_chassis_sensors_b,
    check_function=check_infortrend_chassis_sensors_b,
)
