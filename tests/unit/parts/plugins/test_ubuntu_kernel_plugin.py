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
import re
from typing import Any

import pytest
from craft_parts import Part, PartInfo, ProjectInfo

from snapcraft import errors
from snapcraft.parts.plugins import UbuntuKernelPlugin


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
    ) -> UbuntuKernelPlugin:
        if not properties:
            properties = {"ubuntu-kernel-release-name": "jammy"}

        part = Part("ubuntu-kernel", {})

        project_info = ProjectInfo(
            application_name="test",
            cache_dir=new_dir,
            arch=project_build_for_arch,
            base=project_base,
        )

        part_info = PartInfo(project_info=project_info, part=part)
        properties_class = UbuntuKernelPlugin.properties_class.unmarshal(properties)
        return UbuntuKernelPlugin(
            properties=properties_class,
            part_info=part_info,
        )

    yield _setup_method_fixture


class TestPluginUbuntuKenrel:
    """UbuntuKernel plugin tests."""

    def test_property_requires_source_or_release_name(self, new_dir):
        """Test the property validates source and release name."""
        properties = {
            "plugin-name": "ubuntu-kernel",
        }
        with pytest.raises(errors.SnapcraftError):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

        properties["ubuntu-kernel-release-name"] = "hello"
        # Should not raise
        _ = UbuntuKernelPlugin.properties_class.unmarshal(properties)

        properties["source"] = "git://git-repo.git"
        with pytest.raises(errors.SnapcraftError):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

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
        additional_cross_compile_packages = {
            f"binutils-{plugin.part_info.arch_triplet_build_for}",
            f"gcc-{plugin.part_info.arch_triplet_build_for}",
            f"libc6-dev-{plugin.part_info.target_arch}-cross",
        }
        expected_packages = {"core22": {}, "core24": {}}
        expected_packages["core22"]["amd64"] = expected_common_packages
        expected_packages["core22"]["arm64"] = (
            expected_common_packages | additional_cross_compile_packages
        )

        expected_packages["core24"]["amd64"] = expected_common_packages | {
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
        expected_packages["core24"]["arm64"] = (
            expected_packages["core24"]["amd64"]
            | additional_cross_compile_packages
            | {
                f"libstdc++-13-dev-{plugin.part_info.target_arch}-cross",
            }
        )
        assert expected_packages[base][build_for_arch] == plugin.get_build_packages()

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
        common_build_env = {"FLAVOUR": "generic"}
        cross_compile_build_env = {
            "CROSS_COMPILE": f"{plugin.part_info.arch_triplet_build_for}-",
            "ARCH": f"{build_for_arch}",
        }
        expected_build_env = {
            "core22": {
                "amd64": common_build_env.copy(),
                "arm64": {**common_build_env, **cross_compile_build_env},
            },
            "core24": {
                "amd64": common_build_env.copy(),
                "arm64": {**common_build_env, **cross_compile_build_env},
            },
        }
        assert (
            expected_build_env[base][build_for_arch] == plugin.get_build_environment()
        )

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_source(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected pull commands when source provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "source": "git://git-repo.git",
            "source-type": "git",
            "source-depth": 1,
            "source-branch": "master-next",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        result = plugin.get_pull_commands()
        assert result == []

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_release_name_source_build(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        result = plugin.get_pull_commands()
        assert result == [
            "git clone "
            "--depth=1 "
            "--branch=master-next "
            "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy .",
        ]

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_release_name_debpkg_binary(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """Test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        result = plugin.get_pull_commands()
        assert result == [
            "git clone "
            "--depth=1 "
            "--branch=master-next "
            "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy .",
        ]

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_common(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )

        common_cmd_subset1 = [
            "env",
            "rsync -aH $CRAFT_PART_SRC/ $CRAFT_PART_BUILD/kernel",
            "cd $CRAFT_PART_BUILD/kernel",
            ". debian/debian.env",
            "deb_ver=$(dpkg-parsechangelog -l ${DEBIAN}/changelog -S version)",
            "KERNEL_ABI=$(echo ${deb_ver} | cut -d. -f1-3)-${FLAVOUR}",
        ]
        common_cmd_subset2 = [
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
            ln -f ./vmlinuz-${KERNEL_ABI} ${CRAFT_PART_INSTALL}/kernel.img

            depmod -b ${CRAFT_PART_INSTALL} ${KERNEL_ABI}
            #mv ${CRAFT_PART_INSTALL}/lib/modules ${CRAFT_PART_INSTALL}/modules
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
        assert _is_sub_range(
            haystack=plugin.get_build_commands(), needle=common_cmd_subset1
        )
        # first normalise whitespace and newlines because this is a multiline string
        expected_cmds_subset_normalised = [
            re.sub(r"\s+", " ", cmd.replace("\n", "").replace("\\", " "))
            for cmd in common_cmd_subset2
        ]
        actual_cmds_normalised = [
            # regex to replace whitespace with a single space
            # and remove newlines and backslashes
            re.sub(r"\s+", " ", cmd.replace("\n", "").replace("\\", " "))
            for cmd in plugin.get_build_commands()
        ]
        assert _is_sub_range(
            haystack=actual_cmds_normalised, needle=expected_cmds_subset_normalised
        )

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_with_custom_defconfig(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-defconfig": "my_defconfig",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        expected_cmds_subset = [
            """
            ./debian/scripts/misc/annotations \
                    --arch $CRAFT_TARGET_ARCH \
                    --flavour $FLAVOUR \
                    --import $CRAFT_PROJECT_DIR/{self.options.ubuntu_kernel_defconfig},
            """
        ]
        # first normalise whitespace and newlines because this is a multiline string
        expected_cmds_subset_normalised = [
            re.sub(r"\s+", " ", cmd.replace("\n", "").replace("\\", " "))
            for cmd in expected_cmds_subset
        ]
        actual_cmds_normalised = [
            # regex to replace whitespace with a single space
            # and remove newlines and backslashes
            re.sub(r"\s+", " ", cmd.replace("\n", "").replace("\\", " "))
            for cmd in plugin.get_build_commands()
        ]
        assert _is_sub_range(
            haystack=actual_cmds_normalised, needle=expected_cmds_subset_normalised
        )

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_with_custom_config_list(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-config": ["config1=y", "config2=n", "config3=m"],
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        expected_cmds_subset = [
            "echo config1=y >> $CRAFT_PROJECT_DIR/custom_config_fragment",
            "echo config2=n >> $CRAFT_PROJECT_DIR/custom_config_fragment",
            "echo config3=m >> $CRAFT_PROJECT_DIR/custom_config_fragment",
            """
            ./debian/scripts/misc/annotations \
                --arch $CRAFT_TARGET_ARCH \
                --flavour $FLAVOUR \
                --update $CRAFT_PROJECT_DIR/custom_config_fragment
            """,
        ]
        # first normalise whitespace and newlines because this is a multiline string
        expected_cmds_subset_normalised = [
            re.sub(r"\s+", " ", cmd.replace("\n", "").replace("\\", " "))
            for cmd in expected_cmds_subset
        ]
        actual_cmds_normalised = [
            re.sub(r"\s+", " ", cmd.replace("\n", "").replace("\\", " "))
            for cmd in plugin.get_build_commands()
        ]
        assert _is_sub_range(
            haystack=actual_cmds_normalised, needle=expected_cmds_subset_normalised
        )

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_with_cross_compile(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        expected_cmds_subset = [
            "export $(dpkg-architecture -a${CRAFT_TARGET_ARCH})",
        ]
        if build_for_arch == "arm64":
            assert _is_sub_range(
                haystack=plugin.get_build_commands(), needle=expected_cmds_subset
            )
        else:
            assert not _is_sub_range(
                haystack=plugin.get_build_commands(), needle=expected_cmds_subset
            )

    @pytest.mark.parametrize(
        "base, build_for_arch",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_with_custom_image_target(
        self, base, build_for_arch, new_dir, setup_method_fixture
    ):
        """test the expected pull commands when release-name provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-image-target": "bzImage",
        }
        plugin = setup_method_fixture(
            new_dir,
            project_base=base,
            project_build_for_arch=build_for_arch,
            properties=properties,
        )
        expected_cmds_subset = [
            (
                "sed -i 's/build_image.*/build_image = bzImage/g' "
                "debian.master/rules.d/${CRAFT_TARGET_ARCH}.mk"
            ),
            (
                "sed -i "
                "'s|kernel_file.*|"
                "kernel_file = arch/$(build_arch)/boot/bzImage|g' "
                "debian.master/rules.d/${CRAFT_TARGET_ARCH}.mk"
            ),
        ]
        assert _is_sub_range(
            haystack=plugin.get_build_commands(), needle=expected_cmds_subset
        )
