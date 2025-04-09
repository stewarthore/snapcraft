# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright 2025 Canonical Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License version 3 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import functools
import pathlib
from typing import Any

import pydantic
import pytest
from craft_parts import Part, PartInfo, ProjectInfo

from snapcraft.parts.plugins import UbuntuCoreInitrdPlugin


def _sub_range_count(haystack: list[Any], needle: list[Any]) -> bool:
    """Check if needle range is in the haystack range."""
    hlen = len(haystack)
    nlen = len(needle)
    num_matches = 0
    for idx in range(hlen - nlen + 1):
        if haystack[idx : idx + nlen] == needle:
            num_matches += 1
    return num_matches


def _is_sub_range(haystack: list[Any], needle: list[Any], match_count: int = 1) -> bool:
    """Check if needle range is in the haystack range."""
    return _sub_range_count(haystack, needle) == match_count


@functools.lru_cache
def get_project_info_parameters() -> list[(str, str)]:
    """Generate a ProjectInfo object."""
    return [
        (base, arch) for base in ["core22", "core24"] for arch in ["amd64", "arm64"]
    ]


def get_test_fixture_ids() -> list[str]:
    """Generate fixture ids."""
    parms = get_project_info_parameters()
    return [f"{x[0]}, {x[1]}" for x in parms]


@pytest.fixture
def setup_method_fixture():
    def _setup_method_fixture(
        new_dir: pathlib.Path,
        project_base: str,
        project_build_for_arch: str,
        properties: dict[str, str] | None = None,
    ) -> UbuntuCoreInitrdPlugin:
        if not properties:
            properties = {}

        part = Part("ubuntu-kernel", {})

        project_info = ProjectInfo(
            application_name="test",
            cache_dir=new_dir,
            arch=project_build_for_arch,
            base=project_base,
        )

        part_info = PartInfo(project_info=project_info, part=part)

        return UbuntuCoreInitrdPlugin(
            properties=UbuntuCoreInitrdPlugin.properties_class.unmarshal(properties),
            part_info=part_info,
        )

    yield _setup_method_fixture


class TestPluginUbuntuCoreInitrd:
    """UbuntuCoreInitrdPluginTest."""

    @pytest.mark.parametrize(
        "compression_type",
        [
            "bzip2",
            "gzip",
            "lz4",
            "lzma",
            "xz",
            "uncompressed",
        ],
    )
    def test_property_valid_compression_type_does_not_throw(
        self, compression_type, new_dir
    ):
        """Test the property validates the compression type."""
        properties = {
            "plugin-name": "ubuntu-core-initrd",
            "ubuntu-core-initrd-compression": f"{compression_type}",
        }
        UbuntuCoreInitrdPlugin.properties_class.unmarshal(properties)

    def test_property_invalid_compression_type_throws(self, new_dir):
        """Test the property validates the compression type."""
        properties = {
            "plugin-name": "ubuntu-core-initrd",
            "ubuntu-core-initrd-compression": "bad_type",
        }
        with pytest.raises(pydantic.ValidationError):
            UbuntuCoreInitrdPlugin.properties_class.unmarshal(properties)

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_snaps(self, base, build_for_arch, new_dir, setup_method_fixture):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(
            new_dir, project_base=base, project_build_for_arch=build_for_arch
        )
        assert plugin.get_build_snaps() == set()

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_packages(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(
            new_dir, project_base=base, project_build_for_arch=build_for_arch
        )
        expected_common_packages = {
            "bzip2",
            "gzip",
            "lz4",
            "lzma",
            "lzop",
            "ubuntu-core-initramfs",
            "xz-utils",
            "zstd",
        }
        assert expected_common_packages == plugin.get_build_packages()

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_environment(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(
            new_dir, project_base=base, project_build_for_arch=build_for_arch
        )
        assert plugin.get_build_environment() == {}

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_without_options_source(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(
            new_dir, project_base=base, project_build_for_arch=build_for_arch
        )
        expected_cmds = [
            "KERNEL_ABI=$(ls ${CRAFT_STAGE}/modules | head -n1)",
            "TEMPLATE=${CRAFT_PART_BUILD}/template",
            "SRC=${CRAFT_PART_SRC}/usr/lib/ubuntu-core-initramfs",
            "FIRMWARE_DIR=${CRAFT_STAGE}/lib/firmware/${KERNEL_ABI}",
        ]
        expected_cmds += [
            "apt download ubuntu-core-initramfs:${CRAFT_TARGET_ARCH}",
            "dpkg-deb -x ubuntu-core-initramfs*deb ${CRAFT_PART_SRC}",
        ]
        expected_cmds += [
            # Copy the target ubuntu-core-initramfs to $template/main
            "cp -a ${SRC} ${TEMPLATE}",
        ]
        expected_cmds += [
            'if [ -d "${FIRMWARE_DIR}" ] && '
            '[ -n "$(find ${FIRMWARE_DIR} -mindepth 1 -maxdepth 1 -print -quit)" ]; '
            "then",
            'FIRWARE_OPTION="--firmwaredir ${CRAFT_STAGE}/lib/firmware/${KERNEL_ABI}"',
        ]
        # TODO(esh) do we need to check for the existence of `firmware`. Not
        # all kernel builds will have explicit firmware files.
        expected_cmds += [
            "ubuntu-core-initramfs create-initrd "
            "--output ${CRAFT_PART_BUILD}/initrd.img "
            "--skeleton ${TEMPLATE} "
            "--kernelver ${KERNEL_ABI} "
            "--kerneldir ${CRAFT_STAGE}/modules/${KERNEL_ABI}"
            "${FIRMWARE_OPTION}",
            "mv ${CRAFT_PART_BUILD}/initrd.img-${KERNEL_ABI} \
                ${CRAFT_PART_INSTALL}/initrd.img",
        ]

        assert expected_cmds == plugin.get_build_commands()

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_with_options_source(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected build packages for building the Ubuntu kernel."""
        properties = {
            "plugin-name": "ubuntu-core-initrd",
            "ubuntu-core-initrd-compression": "gzip",
            "source": "source-url",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        expected_cmds = [
            "KERNEL_ABI=$(ls ${CRAFT_STAGE}/modules | head -n1)",
            "TEMPLATE=${CRAFT_PART_BUILD}/template",
            "SRC=${CRAFT_PART_SRC}/usr/lib/ubuntu-core-initramfs",
            "FIRMWARE_DIR=${CRAFT_STAGE}/lib/firmware/${KERNEL_ABI}",
        ]
        expected_cmds += [
            # Copy the target ubuntu-core-initramfs to $template/main
            "cp -a ${SRC} ${TEMPLATE}",
        ]
        expected_cmds += [
            'if [ -d "${FIRMWARE_DIR}" ] && '
            '[ -n "$(find ${FIRMWARE_DIR} -mindepth 1 -maxdepth 1 -print -quit)" ]; '
            "then",
            'FIRWARE_OPTION="--firmwaredir ${CRAFT_STAGE}/lib/firmware/${KERNEL_ABI}"',
        ]
        # TODO(esh) do we need to check for the existence of `firmware`. Not
        # all kernel builds will have explicit firmware files.
        expected_cmds += [
            "ubuntu-core-initramfs create-initrd "
            "--output ${CRAFT_PART_BUILD}/initrd.img "
            "--skeleton ${TEMPLATE} "
            "--kernelver ${KERNEL_ABI} "
            "--kerneldir ${CRAFT_STAGE}/modules/${KERNEL_ABI}"
            "${FIRMWARE_OPTION}",
            "mv ${CRAFT_PART_BUILD}/initrd.img-${KERNEL_ABI} \
                ${CRAFT_PART_INSTALL}/initrd.img",
        ]

        assert expected_cmds == plugin.get_build_commands()
