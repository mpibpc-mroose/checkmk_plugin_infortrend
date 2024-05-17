#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Infortrend SNMP based check for status of the logical drives using CheckMK API version v2.

Copyright (C) 2024 Max Planck Institute for Multidisciplinary Sciences
Author: Marco Roose <marco.roose@mpinat.mpg.de>

Credits: Heinlein Support (Infortrend plugin from https://github.com/HeinleinSupport/check_mk_extensions)
License: GNU General Public License v2
"""

import dataclasses
from types import MappingProxyType
from typing import Dict, Iterator, Literal

from cmk.agent_based.v1 import Service
from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    SimpleSNMPSection,
    SNMPTree,
    State,
    StringTable,
    all_of,
    contains,
    not_exists,
)

from .core import saveint  # noqa: WPS300

DRIVE_STATE_INFO_MAP = MappingProxyType({
    0: 'Good',
    1: 'Rebuilding',
    2: 'Initializing',
    3: 'Degraded',
    4: 'Dead',
    5: 'Invalid',
    6: 'Incomplete',
    7: 'Drive Missing',
    64: 'Good',
})


@dataclasses.dataclass
class InfortrendLogicalDriveSection:
    """Section for the representation fo IFT logical drive states."""

    sensor_state: int | Literal['']


def parse_infortrend_logical_drives_b(string_table: StringTable) -> Dict[str, InfortrendLogicalDriveSection]:
    """Parse SNMP data to a dict of InfortrendLogicalDriveSection objects."""
    parsed = {}

    for line in string_table:
        slot = line[0]
        state = saveint(line[1])
        parsed.setdefault(
            slot,
            InfortrendLogicalDriveSection(sensor_state=state),
        )

    return parsed


def discover_infortrend_logical_drives_b(section: Dict[str, InfortrendLogicalDriveSection]) -> DiscoveryResult:
    """Discover logical drives from parsed SNMP data."""
    for logical_drive_slot in section.keys():
        if not logical_drive_slot:
            continue
        yield Service(item=logical_drive_slot)


def discover_infortrend_logical_drives_a(section: Dict[str, InfortrendLogicalDriveSection]) -> DiscoveryResult:
    """Discover logical drives from parsed SNMP data."""
    for logical_drive_slot in section.keys():
        if not logical_drive_slot:
            continue
        yield Service(item=logical_drive_slot)


def check_infortrend_logical_drives_b(
    item: str,
    section: Dict[str, InfortrendLogicalDriveSection],
) -> Iterator[CheckResult | Metric]:
    """Perform checks."""
    ld_section = section.get(item)

    if isinstance(ld_section, InfortrendLogicalDriveSection):
        ld_state = ld_section.sensor_state
        result_summary = ''
        result_state = State.UNKNOWN

        if ld_state & 128 == 128:
            result_summary = 'Logical Drive Off-line (RW)'
            ld_state = ld_state & 127

        if ld_state not in DRIVE_STATE_INFO_MAP.keys():
            yield Result(
                state=State.UNKNOWN,
                summary=f'Status is {ld_state}',
            )

        if result_summary:
            result_summary = f'{result_summary}, {DRIVE_STATE_INFO_MAP[ld_state]}'
        else:
            result_summary = DRIVE_STATE_INFO_MAP[ld_state]

        if ld_state in {0, 64}:
            result_state = State.OK
        elif ld_state in {1, 2}:
            result_state = State.WARN
        elif ld_state in {3, 4, 5, 6, 7}:
            result_state = State.CRIT
        yield Result(
            state=result_state,
            summary=result_summary,
        )
    else:
        yield Result(
            state=State.UNKNOWN,
            summary=f'cannot parse: {ld_section}',
        )


snmp_section_infortrend_logical_drives_b = SimpleSNMPSection(
    name='infortrend_logical_drives_b',
    detect=all_of(
        contains('.1.3.6.1.2.1.1.1.0', 'infortrend'),
        not_exists(oidstr='.1.3.6.1.4.1.1714.1.1.1.1.0'),
    ),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.1714.1.1.2.1',
        oids=[
            '2',  # slot
            '6',  # state
        ],
    ),
    parse_function=parse_infortrend_logical_drives_b,
)

check_plugin_infortrend_logical_drives_b = CheckPlugin(
    name='infortrend_logical_drives_b',
    sections=['infortrend_logical_drives_b'],
    service_name='IFT Logical Drive %s',
    discovery_function=discover_infortrend_logical_drives_b,
    check_function=check_infortrend_logical_drives_b,
)
