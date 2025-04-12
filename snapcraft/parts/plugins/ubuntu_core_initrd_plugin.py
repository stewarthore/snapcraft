# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
# pylint: disable=line-too-long,too-many-lines,attribute-defined-outside-init
#
# Copyright 2020-2022 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""The plugin for building Ubuntu Core initrd."""

import logging
from typing import Literal, cast

from craft_parts import infos, plugins
from overrides import overrides

from snapcraft import errors

logger = logging.getLogger(__name__)


class UbuntuCoreInitrdPluginProperties(
    plugins.properties.PluginProperties, frozen=True
):
    """The part properties used by the Ubuntu Core initrd plugin."""

    plugin: Literal["ubuntu-core-initrd"] = "ubuntu-core-initrd"
    ubuntu_core_initrd_compression: Literal[
        "bzip2",
        "gzip",
        "lz4",
        "lzma",
        "xz",
        "uncompressed",
    ] = "uncompressed"


class UbuntuCoreInitrdPlugin(plugins.Plugin):
    """Plugin for the Ubuntu Core initrd build."""

    properties_class = UbuntuCoreInitrdPluginProperties

    def __init__(
        self, *, properties: plugins.PluginProperties, part_info: infos.PartInfo
    ) -> None:
        super().__init__(properties=properties, part_info=part_info)
        self.options = cast(UbuntuCoreInitrdPluginProperties, self._options)
        self.part_info = part_info
        if part_info.base not in ("core22", "core24"):
            raise errors.SnapcraftError("only core22 and core24 bases are supported")

    @overrides
    def get_build_snaps(self) -> set[str]:
        return set()

    @overrides
    def get_build_packages(self) -> set[str]:
        # hardcoded for now
        build_packages = {
            "bzip2",
            "gzip",
            "lz4",
            "lzma",
            "lzop",
            "ubuntu-core-initramfs",
            "xz-utils",
            "zstd",
        }
        return build_packages

    @overrides
    def get_build_environment(self) -> dict[str, str]:
        return dict()

    @overrides
    def get_build_commands(self) -> list[str]:
        logger.info("Setting build commands...")
        # If we have

        cmds = [
            "KERNEL_ABI=$(ls ${CRAFT_STAGE}/lib/modules | head -n1)",
            "TEMPLATE=${CRAFT_PART_BUILD}/template",
            "SRC=${CRAFT_PART_SRC}/usr/lib/ubuntu-core-initramfs",
            "FIRMWARE_DIR=${CRAFT_STAGE}/lib/firmware/${KERNEL_ABI}",
        ]
        if not self.options.source:
            # Use the target architecture package and unpack to CRADT_PART_SRC
            cmds += [
                "apt download ubuntu-core-initramfs:${CRAFT_TARGET_ARCH}",
                "dpkg-deb -x ubuntu-core-initramfs*deb ${CRAFT_PART_SRC}",
            ]
        cmds += [
            # Copy the target ubuntu-core-initramfs to $template/main
            "cp -a ${SRC} ${TEMPLATE}",
        ]
        # Not all kernels provide a firmware.
        # ubuntu-core-initramfs create-initrd fails if --firmwaredir is given
        # an empty directory or non-existent path.
        cmds += [
            'if [ -d "${FIRMWARE_DIR}" ] && '
            '[ -n "$(find ${FIRMWARE_DIR} -mindepth 1 -maxdepth 1 -print -quit)" ]; '
            "then",
            "ubuntu-core-initramfs create-initrd "
            "--output ${CRAFT_PART_BUILD}/initrd.img "
            "--skeleton ${TEMPLATE} "
            "--kernelver ${KERNEL_ABI} "
            "--kerneldir ${CRAFT_STAGE}/lib/modules/${KERNEL_ABI} ",
            "--firmwaredir ${FIRMWARE_DIR}",
            "else",
            "ubuntu-core-initramfs create-initrd "
            "--output ${CRAFT_PART_BUILD}/initrd.img "
            "--skeleton ${TEMPLATE} "
            "--kernelver ${KERNEL_ABI} "
            "--kerneldir ${CRAFT_STAGE}/lib/modules/${KERNEL_ABI} ",
            "fi",
        ]
        cmds += [
            "mv ${CRAFT_PART_BUILD}/initrd.img-${KERNEL_ABI} \
                ${CRAFT_PART_INSTALL}/initrd.img",
        ]

        return cmds

    @classmethod
    def get_out_of_source_build(cls) -> bool:
        """Return whether the plugin performs out-of-source-tree builds."""
        return True
