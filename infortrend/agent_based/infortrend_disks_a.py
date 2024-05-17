#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Infortrend SNMP based check for disk status using CheckMK API version v2.

Copyright (C) 2024 Max Planck Institute for Multidisciplinary Sciences
Author: Marco Roose <marco.roose@mpinat.mpg.de>

Credits: Heinlein Support (Infortrend plugin from https://github.com/HeinleinSupport/check_mk_extensions)
License: GNU General Public License v2
"""

import dataclasses
from types import MappingProxyType
from typing import Dict, Iterator, Literal

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
    exists,
)
from cmk.agent_based.v2.render import disksize

from .core import saveint  # noqa: WPS300

# Map of SNMP status value to description
DISK_STATUS_MAP = MappingProxyType({
    0: 'New Drive',
    1: 'On-Line Drive',
    2: 'Used Drive',
    3: 'Spare Drive',
    4: 'Drive Initialization in Progress',
    5: 'Drive Rebuild in Progress',
    6: 'Add Drive to Logical Drive in Progress',
    9: 'Global Spare Drive',
    17: 'Drive is in process of Cloning another Drive',
    18: 'Drive is a valid Clone of another Drive',
    19: 'Drive is in process of Copying from another Drive (for Copy/Replace LD Expansion function)',
    63: 'Drive Absent',
    128: 'SCSI Device (Type 0)',
    129: 'SCSI Device (Type 1)',
    130: 'SCSI Device (Type 2)',
    131: 'SCSI Device (Type 3)',
    132: 'SCSI Device (Type 4)',
    133: 'SCSI Device (Type 5)',
    134: 'SCSI Device (Type 6)',
    135: 'SCSI Device (Type 7)',
    136: 'SCSI Device (Type 8)',
    137: 'SCSI Device (Type 9)',
    138: 'SCSI Device (Type 10)',
    139: 'SCSI Device (Type 11)',
    140: 'SCSI Device (Type 12)',
    141: 'SCSI Device (Type 13)',
    142: 'SCSI Device (Type 14)',
    143: 'SCSI Device (Type 15)',
    252: 'Missing Global Spare Drive',
    253: 'Missing Spare Drive',
    254: 'Missing Drive',
    255: 'Failed Drive',
})


@dataclasses.dataclass
class InfortrendDiskSection:
    """Section for SNMP values for Infortrend disks."""

    slot: str
    state: int | Literal['']
    description: str


def parse_infortrend_disks(string_table: StringTable) -> Dict[str, InfortrendDiskSection]:  # noqa: WPS210
    """Parse SNMP data to a dict of InfortrendDiskSection objects."""
    parsed = {}

    for line in string_table:
        slot = line[0]
        state = saveint(line[1])
        model = line[2]
        version = line[3]
        serial = line[4]
        size = int(line[5])
        blocksize = int(line[6])
        disksize_bytes = size * 2 ** blocksize
        parsed.setdefault(
            slot,
            InfortrendDiskSection(
                slot=slot,
                state=state,
                description=f'{model} {version} {serial}, {disksize(disksize_bytes)}, ',  # noqa: WPS221
            ),
        )

    return parsed


def discover_infortrend_disks(section: Dict[str, InfortrendDiskSection]) -> DiscoveryResult:
    """Discover disks from parsed SNMP data."""
    for slot in section.keys():
        if not slot:
            continue
        yield Service(item=slot)


def check_infortrend_disks(
    item: str,
    section: Dict[str, InfortrendDiskSection],
) -> Iterator[CheckResult | Metric]:
    """Perform checks and submit metrics."""
    disk_data = section.get(item)

    if isinstance(disk_data, InfortrendDiskSection):
        state = disk_data.state
        state_description = disk_data.description
        if state not in DISK_STATUS_MAP.keys():
            yield Result(
                state=State.UNKNOWN,
                summary=f'{state_description}Status is {state}',
            )
        elif state in {1, 3, 9}:
            yield Result(
                state=State.OK,
                summary=f'{state_description}{DISK_STATUS_MAP[state]}',
            )
        elif state > 63:
            yield Result(
                state=State.CRIT,
                summary=f'{state_description}{DISK_STATUS_MAP[state]}',
            )
        else:
            yield Result(
                state=State.WARN,
                summary=f'{state_description}{DISK_STATUS_MAP[state]}',
            )
    else:
        yield Result(
            state=State.UNKNOWN,
            summary=f'{disk_data} is not valid',
        )


snmp_section_infortrend_disks_a = SimpleSNMPSection(
    name='infortrend_disks_a',
    detect=exists(oidstr='.1.3.6.1.4.1.1714.1.1.1.1.0'),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.1714.1.6.1',
        oids=[
            '13',  # slot
            '11',  # status
            '15',  # model
            '16',  # version
            '17',  # serial
            '7',  # size
            '8',  # blocksize
        ],
    ),
    parse_function=parse_infortrend_disks,
)

check_plugin_infortrend_disks_a = CheckPlugin(
    name='infortrend_disks_a',
    sections=['infortrend_disks_a'],
    service_name='IFT Disk Slot %s',
    discovery_function=discover_infortrend_disks,
    check_function=check_infortrend_disks,
)
