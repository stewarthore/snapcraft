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

"""The kernel plugin for building Ubuntu Core kernel snaps."""

import logging
from typing import Literal, Self, cast

import pydantic
from craft_parts import infos, plugins
from overrides import overrides

from snapcraft import errors

logger = logging.getLogger(__name__)

KERNEL_REPO_STEM = "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/"
DEFAULT_RELEASE_NAME = {"core22": "jammy", "core24": "noble"}

_DEFAULT_KERNEL_IMAGE_TARGET = {
    "amd64": "bzImage",
    "i386": "bzImage",
    "armhf": "zImage",
    "arm64": "Image.gz",
    "powerpc": "uImage",
    "ppc64el": "vmlinux.strip",
    "s390x": "bzImage",
    "riscv64": "Image",
}

## These are set in the debian.masters/rules.d/<arch>.mk

_AVAILABLE_TOOLS = [
    "cpupower",
    "perf",
    "bpftool",
]


def kernel_launchpad_repository(release_name: str) -> str:
    """Get the kenrel launchpad repository."""
    return KERNEL_REPO_STEM + release_name


class UbuntuKernelPluginProperties(plugins.properties.PluginProperties, frozen=True):
    """The part properties used by the Kernel plugin.

    plugin: Name of the plugin
    ubuntu_kernel_release_name: str The name of the Ubuntu kernel release.
    This is validated against the kernel source if both are proided, otherwise
    the source is derived from the Ubuntu release name.
    ubuntu_kernel_flavour: The kernel variant, e.g. "generic" (default), "rpi"
    ubuntu_kernel_dkms: List of dynamic kernel modules to include in the kernel package
    source: Ubuntu kernel source repository URL.

    If release and source are not provided the LTS kernel matching the snap base
    will be used. E.g. core22 will select jammy, core24 will select noble.

    """

    plugin: Literal["ubuntu-kernel"] = "ubuntu-kernel"
    """Plugin name."""
    ubuntu_kernel_flavour: str = "generic"
    """The ubuntu kernel flavour, will be ignored if defconfig provided."""
    ubuntu_kernel_dkms: list[str] = []
    """Additional dkms."""
    ubuntu_kernel_release_name: str | None = None
    """Ubuntu release to build. Mutually exclusive with `source`."""
    ubuntu_kernel_defconfig: str | None = None
    """Path to custom defconfig, relative to the project directory."""
    ubuntu_kernel_config: list[str] = []
    """Custom set of kenel configuration parameters."""
    ubuntu_kernel_image_target: str | None = None
    """Kernel image target type."""
    ubuntu_kernel_tools: list[str] = []
    """Kernel tools to include, e.g. perf."""
    ubuntu_kernel_use_prebuilt_image: bool = False
    """Flag to use prebuilt kernel packages. Only valid with ubuntu-kerne-release-name."""

    # Validate so that release_name and source are mutually exclusive
    @pydantic.model_validator(mode="after")
    def validate_release_name_and_source_exclusive(self) -> Self:
        """Enforce release_name and source options are mutually exclusive."""
        if self.ubuntu_kernel_release_name and self.source:
            raise errors.SnapcraftError(
                "`ubuntu-kernel-release-name` and `source` are mutually exclusive"
            )
        if not self.ubuntu_kernel_release_name and not self.source:
            raise errors.SnapcraftError(
                "must provide either `ubuntu-kernel-release-name` or `source`"
            )
        if self.source and self.ubuntu_kernel_use_prebuilt_image:
            raise errors.SnapcraftError(
                "`ubuntu-kernel-use-prebuilt-image only available with `ubuntu-kernel-release-name`"
            )
        return self

    @pydantic.field_validator("ubuntu_kernel_tools")
    @classmethod
    def validate_tool_list(cls, value: list[str]) -> list[str]:
        """Check the list of tools is in the available list."""
        if any(x not in _AVAILABLE_TOOLS for x in value):
            raise errors.SnapcraftError(
                f"unknown tool provided, available tools: {_AVAILABLE_TOOLS}"
            )
        return value


class BuildCommandGenerator:
    """Build commands variations for the Linux kernel."""

    def __init__(
        self, options: UbuntuKernelPluginProperties, part_info: infos.PartInfo
    ) -> None:
        self.options = options
        self.part_info = part_info

    def get_config_fragment_header(self) -> list[str]:
        """Get the command set to write the kernel config fragment header."""
        return [
            'echo "# Ubuntu kernel configuration fragment." > $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Generated by snapcraft ubuntu-kernel plugin." >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# ----" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Kernel ABI: $KERNEL_ABI" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Build on: $CRAFT_ARCH_TRIPLET_BUILD_ON" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Build for: $CRAFT_ARCH_TRIPLET_BUILD_FOR" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Snap version: $SNAP_VERSION" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Snap data: $SNAP" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# Snap context: $SNAP_CONTEXT" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "# ----" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
            'echo "" >> $CRAFT_PROJECT_DIR/custom_config_fragment',
        ]

    def ubuntu_source_tree(self) -> list[str]:
        """Get the build commands given Ubuntu kernel source tree."""
        cmds = [
            "env",
            "rsync -aH $CRAFT_PART_SRC/ $CRAFT_PART_BUILD/kernel",
            "cd $CRAFT_PART_BUILD/kernel",
            ". debian/debian.env",
            "deb_ver=$(dpkg-parsechangelog -l ${DEBIAN}/changelog -S version)",
            "KERNEL_ABI=$(echo ${deb_ver} | cut -d. -f1-3)-${FLAVOUR}",
        ]
        if self.options.ubuntu_kernel_tools:
            cmds += [
                # Tools list provided, not using defaults so set all to false
                # and only enable the tools listed in the properties
                (
                    "sed -i 's/^\\s*do_tools_\\(.*\\)\\s*=.*/do_tools_\\1 = false/g' "
                    "debian.master/rules.d/${CRAFT_TARGET_ARCH}.mk"
                ),
            ]
            for tool in self.options.ubuntu_kernel_tools:
                cmds += [
                    (
                        "sed -i "
                        rf"'s/^\s*do_tools_{tool}\s*=.*/do_tools_{tool} = true/g' "
                        "debian.master/rules.d/${CRAFT_TARGET_ARCH}.mk"
                    ),
                ]

        if self.options.ubuntu_kernel_image_target:
            target_image = self.options.ubuntu_kernel_image_target
            cmds += [
                (
                    f"sed -i 's/build_image.*/build_image = {target_image}/g' "
                    "debian.master/rules.d/${CRAFT_TARGET_ARCH}.mk"
                ),
                (
                    "sed -i "
                    "'s|kernel_file.*|"
                    f"kernel_file = arch/$(build_arch)/boot/{target_image}|g' "
                    "debian.master/rules.d/${CRAFT_TARGET_ARCH}.mk"
                ),
            ]

        if self.part_info.is_cross_compiling:
            cmds += [
                "export $(dpkg-architecture -a${CRAFT_TARGET_ARCH})",
            ]
        if self.options.ubuntu_kernel_config:
            cmds += self.get_config_fragment_header()
            for config in self.options.ubuntu_kernel_config:
                cmds += [
                    f"echo {config} >> $CRAFT_PROJECT_DIR/custom_config_fragment",
                ]
            cmds += [
                """
                ./debian/scripts/misc/annotations \
                        --arch $CRAFT_TARGET_ARCH \
                        --flavour $FLAVOUR \
                        --update $CRAFT_PROJECT_DIR/custom_config_fragment
                """,
            ]

        if self.options.ubuntu_kernel_defconfig:
            cmds += [
                """
                ./debian/scripts/misc/annotations \
                        --arch $CRAFT_TARGET_ARCH \
                        --flavour $FLAVOUR \
                        --import $CRAFT_PROJECT_DIR/{self.options.ubuntu_kernel_defconfig},
                """
            ]

        cmds += [
            "fakeroot debian/rules clean",
            "fakeroot debian/rules printenv",
            "debian/rules build-$FLAVOUR",
            """
            if [ -d debian/linux-image-unsigned-${KERNEL_ABI} ]; then
                IMAGE_PKG=linux-image-unsigned
            else
                IMAGE_PKG=linux-image
            fi

            for pkg in $IMAGE_PKG linux-modules linux-buildinfo; do
                cp -lr debian/${pkg}-${KERNEL_ABI}/* ${CRAFT_PART_INSTALL}/
            done
            mv ${CRAFT_PART_INSTALL}/boot/* ${CRAFT_PART_INSTALL}
            ln -s ./vmlinuz-${KERNEL_ABI} ${CRAFT_PART_INSTALL}/kernel.img

            depmod -b ${CRAFT_PART_INSTALL} ${KERNEL_ABI}
            mv ${CRAFT_PART_INSTALL}/lib/modules ${CRAFT_PART_INSTALL}/modules
            DTBS=${CRAFT_PART_INSTALL}/lib/firmware/${KERNEL_ABI}/device-tree
            if [ -d ${DTBS} ]; then
                mv ${DTBS} ${CRAFT_PART_INSTALL}/dtbs
            fi
            FIRMWARE=${CRAFT_PART_INSTALL}/lib/firmware/${KERNEL_ABI}
            if [ -d ${FIRMWARE} ]; then
                mv ${FIRMWARE}/ ${CRAFT_PART_INSTALL}/firmware/
            fi
            cp LICENSES/preferred/GPL-2.0 ${CRAFT_PART_INSTALL}/GPL-2
            """,
        ]
        return cmds


class UbuntuKernelPlugin(plugins.Plugin):
    """Plugin for the Ubuntu kernel snap build."""

    properties_class = UbuntuKernelPluginProperties

    def __init__(
        self, *, properties: plugins.PluginProperties, part_info: infos.PartInfo
    ) -> None:
        super().__init__(properties=properties, part_info=part_info)
        self.options = cast(UbuntuKernelPluginProperties, self._options)
        self.part_info = part_info
        if part_info.base not in ("core22", "core24"):
            raise errors.SnapcraftError("only core22 and core24 bases are supported")
        self.release_name = (
            self.options.ubuntu_kernel_release_name
            if self.options.ubuntu_kernel_release_name is not None
            else None
        )
        self.image_target = (
            self.options.ubuntu_kernel_image_target
            if self.options.ubuntu_kernel_image_target is not None
            else _DEFAULT_KERNEL_IMAGE_TARGET[part_info.arch_build_for]
        )

        self.build_commands = BuildCommandGenerator(self.options, self.part_info)

    @overrides
    def get_build_snaps(self) -> set[str]:
        return set()

    @overrides
    def get_build_packages(self) -> set[str]:
        # hardcoded for now
        build_packages = {
            "debhelper-compat",
            "cpio",
            "kmod",
            "makedumpfile",
            "libcap-dev",
            "libelf-dev",
            "libnewt-dev",
            "libiberty-dev",
            "default-jdk-headless",
            "java-common",
            "rsync",
            "libdw-dev",
            "libpci-dev",
            "pkg-config",
            "python3-dev",
            "flex",
            "bison",
            "libunwind8-dev",
            "liblzma-dev",
            "openssl",
            "libssl-dev",
            "libaudit-dev",
            "bc",
            "gawk",
            "libudev-dev",
            "autoconf",
            "automake",
            "libtool",
            "uuid-dev",
            "libnuma-dev",
            "dkms",
            "curl",
            "zstd",
            "pahole",  # not in control file
            "bzip2",
            "debhelper",
            "fakeroot",
            "lz4",
            "python3",
            "dwarfdump",
        }

        if self.part_info.base == "core24":
            build_packages |= {
                "python3-setuptools",
                "libtraceevent-dev",
                "libtracefs-dev",
                "clang-18",
                "rustc",
                "rust-src",
                "rustfmt",
                "bindgen-0.65",
                "libstdc++-13-dev",
            }

        if self.part_info.is_cross_compiling:
            build_packages |= {
                f"binutils-{self.part_info.arch_triplet_build_for}",
                f"gcc-{self.part_info.arch_triplet_build_for}",
                f"libc6-dev-{self.part_info.target_arch}-cross",
            }
            if self.part_info.base == "core24":
                build_packages |= {
                    f"libstdc++-13-dev-{self.part_info.target_arch}-cross",
                }

        return build_packages

    @overrides
    def get_build_environment(self) -> dict[str, str]:
        env = {
            "FLAVOUR": self.options.ubuntu_kernel_flavour,
        }
        if self.part_info.is_cross_compiling:
            logger.info("Setting cross build env...")
            env |= {
                "ARCH": self.part_info.arch_build_for,
                # generated with self.part_info.target_arch,
                "CROSS_COMPILE": f"{self.part_info.arch_triplet_build_for}-",
            }
        return env

    def get_pull_commands(self) -> list[str]:
        """Clone the repository when no source is provided."""
        if self.options.source:
            return super().get_pull_commands()
        repo_url = kernel_launchpad_repository(self.release_name)
        # '.' is $CRAFT_PART_SRC. The env. var. is not defined when pull runs
        cmds = [
            f"git clone --depth=1 --branch=master-next {repo_url} .",
        ]
        return cmds

    @overrides
    def get_build_commands(self) -> list[str]:
        logger.info("Setting build commands...")
        logger.info("*****************************")
        logger.info("self.options.source = %", self.options.source)
        cmds = self.build_commands.ubuntu_source_tree()
        logger.info("COMMANDS:\n%s", cmds)
        logger.info("===============================")
        return cmds
        # return self._get_from_source_build_commands()

    @classmethod
    def get_out_of_source_build(cls) -> bool:
        """Return whether the plugin performs out-of-source-tree builds."""
        return True
