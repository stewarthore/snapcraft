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
import os
import pathlib
import re
from typing import Literal, cast

import jinja2
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
    ubuntu_core_initrd_build_efi_image: bool = False


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
        logger.info("*****************************")
        logger.info("self.options.source = %", self.options.source)
        craft_stage_dir = self.part_info.project_info.stage_dir
        try:
            kernel_package = next(
                entry.name
                for entry in pathlib.Path(f"{craft_stage_dir}/modules").iterdir()
                if entry.is_dir()
            )
        except StopIteration:
            raise RuntimeError(f"The kernel package '{kernel_package}' was not found.")
        print(f"KERNPKG = {kernel_package}")
        m = re.match(r"(\d+\.\d+\.\d+-\d+)-(.+)", kernel_package)
        if not m:
            raise RuntimeError(
                f"The kernel package name '{kernel_package}' does not match "
                "the expected format."
            )
        kernel_abi = m.group(1)
        kernel_flavour = m.group(2)
        kernel_module_dir = f"{craft_stage_dir}/modules/{kernel_abi}-{kernel_flavour}"
        template_dir = f"{self.part_info.part_build_dir}/template"
        initramfs_source_dir = (
            f"{self.part_info.part_src_dir}/usr/lib/ubuntu-core-initramfs"
        )
        firmware_dir = f"{craft_stage_dir}/lib/firmware/{kernel_abi}"

        script_template_file = "kernel/ubuntu_core_initrd_build.sh.j2"
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("snapcraft", "templates"), autoescape=True
        )
        script_template = env.get_template(script_template_file)

        signing_key_path = (
            "/usr/lib/ubuntu-core-initramfs/snakeoil/PkKek-1-snakeoil.key"
        )
        signing_cert_path = (
            "/usr/lib/ubuntu-core-initramfs/snakeoil/PkKek-1-snakeoil.pem"
        )
        if self.options.ubuntu_core_initrd_build_efi_image:
            signing_key_path = f"{self.part_info.part_build_dir}/efi-signing-key.pem"
            signing_cert_path = f"{self.part_info.part_build_dir}/efi-certificate.pem"

        script = script_template.render(
            {
                "craft_arch_build_for": self.part_info.arch_build_for,
                "craft_arch_build_on": self.part_info.arch_build_on,
                "craft_part_build_dir": self.part_info.part_build_dir,
                "craft_part_install_dir": self.part_info.part_install_dir,
                "craft_part_project_dir": self.part_info.project_info.dirs.project_dir,
                "craft_part_src_dir": self.part_info.part_src_dir,
                "craft_stage_dir": self.part_info.stage_dir,
                "firmware_dir": firmware_dir,
                "has_ubuntu_core_initrd_source_url": bool(self.options.source),
                "initramfs_source_dir": initramfs_source_dir,
                "is_cross_compiling": self.part_info.is_cross_compiling,
                "kernel_abi": kernel_abi,
                "kernel_flavour": kernel_flavour,
                "kernel_module_dir": kernel_module_dir,
                "snap_context": os.environ["SNAP_CONTEXT"],
                "snap_data_path": os.environ["SNAP"],
                "signing_key_path": signing_key_path,
                "signing_cert_path": signing_cert_path,
                "snap_version": os.environ["SNAP_VERSION"],
                "target_arch": self.part_info.target_arch,
                "template_dir": template_dir,
                "ubuntu_core_base": self.part_info.base,
            }
        )
        return [script]

    @classmethod
    def get_out_of_source_build(cls) -> bool:
        """Return whether the plugin performs out-of-source-tree builds."""
        return True
