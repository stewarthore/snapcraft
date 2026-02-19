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
import dataclasses
import functools
import pathlib
import re
from unittest import mock

import pytest
from craft_parts import Part, PartInfo, ProjectInfo

from snapcraft import errors
from snapcraft.parts.plugins import UbuntuKernelPlugin, ubuntu_kernel_plugin

KERNEL_VERSION_MOCK_VALUE = ubuntu_kernel_plugin.KernelVersion(
    full_version="5.15.0-143.153",
    version="5.15.0",
    abi="143",
    spin="153",
)


def build_from_debpkg_cmds() -> list[str]:
    """Return build commands for building from deb packages.

    Note: All snapcraft root paths are normalised to for comparison ';parts'

    Returns:
        List of build commands for building from binary deb packages.
    """
    return [
        "rsync -aH ;parts/ubuntu-kernel/src/*.deb ;parts/ubuntu-kernel/build/kernel",
    ]


@pytest.fixture
def build_cmds_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the common build commands environment."""
    monkeypatch.setenv("SNAP_CONTEXT", "snap-context")
    monkeypatch.setenv("SNAP", "snap")
    monkeypatch.setenv("SNAP_VERSION", "1.0.0")


def normalise_actual_cmds(raw_cmds: list[str]) -> list[str]:
    """Normalise the actual commands for comparison.

    Removes empty lines, comments, and normalises paths to a common ';' root
    character.

    Args:
        raw_cmds: List of raw command strings.

    Returns:
        List of normalised command strings.
    """
    actual_cmds = [x.strip() for y in raw_cmds for x in y.split("\n")]
    actual_cmds = [re.sub(r"[^ ]*/parts", ";parts", x) for x in actual_cmds if x]
    actual_cmds = [re.sub(r"^\s*#.*$", "", x) for x in actual_cmds]
    actual_cmds = [x for x in actual_cmds if x]
    return actual_cmds


def get_cross_build_cmds(target_arch: str | None) -> list[str]:
    """Get the cross-build commands snippets.

    Args:
        target_arch: The target architecture for the build.
    Returns:
        Tuple of pre-debian environment and post-debian environment commands
        for cross-compilation.
    """
    cross_build_cmds_post_debenv = (
        []
        if target_arch == "amd64"
        else [
            'export "$(dpkg-architecture -aarm64)"',
        ]
    )
    return cross_build_cmds_post_debenv


def get_kernel_image_target_cmds(
    target_arch: str | None, kernel_image_target: str | None
) -> list[str]:
    """Get the kernel image target command snippet.

    Args:
        target_arch: The target architecture for the build.
        kernel_image_target: The kernel image target file name.

    Returns:
        List of command snippets to update the kernel image target for debian
        build rules.
    """
    kernel_image_target_cmds = []
    if kernel_image_target:
        kernel_image_target_cmds = [
            'echo "Updating build target image"',
            "sed -i \\",
            f"'s/^\\s*build_image.*/build_image = {kernel_image_target}/g' \\",
            f"debian.master/rules.d/{target_arch}.mk",
            "sed -i \\",
            f"'s|^\\s*kernel_file.*|kernel_file = arch/{target_arch}/boot/{kernel_image_target}|g' \\",
            f"debian.master/rules.d/{target_arch}.mk",
        ]
    return kernel_image_target_cmds


def get_kernel_tool_cmds(
    target_arch: str | None, kernel_tools: list[str] | None
) -> list[str]:
    """Get the kernel tools command snippets.

    Args:
        target_arch: The target architecture for the build.
        kernel_tools: List of kernel tools to enable in the build.
    Returns:
        List of command snippets to update the kernel tools selection in debian
        build rules.
    """
    kernel_tools_cmds = []
    if kernel_tools:
        kernel_tools_cmds = [
            'echo "Updating kernel tools selection"',
            r"sed -i 's/^\\s*do_tools_\\(.*\\)\\s*=.*/do_tools_\\1 = false/g' " + "\\",
            f"debian.master/rules.d/{target_arch}.mk",
        ]
        for tool in kernel_tools:
            kernel_tools_cmds += [
                f"sed -i 's/^\\s*do_tools_{tool}\\s*=.*/do_tools_{tool} = true/g' \\",
                f"debian.master/rules.d/{target_arch}.mk",
            ]
    return kernel_tools_cmds


def get_kernel_config_fragment_cmds(
    target_arch: str | None, kernel_config_fragments: list[str] | None
) -> list[str]:
    """Get the kernel config fragment command snippets.

    Args:
        target_arch: The target architecture for the build.
        kernel_config_fragments: List of kernel config fragments to apply.

    Returns:
        List of command snippets to update the kernel config fragments in the
        Ubuntu kernel annotations source.
    """
    kernel_config_fragment_cmds = []
    if kernel_config_fragments:
        kernel_config_fragment_cmds.append("{")
        for config in kernel_config_fragments:
            kernel_config_fragment_cmds.append(f'echo "{config}"')
        kernel_config_fragment_cmds.append("} > ;custom_config_fragment")
        kernel_config_fragment_cmds += [
            "./debian/scripts/misc/annotations \\",
            f"--arch {target_arch} \\",
            "--flavor generic \\",
            "--update ;custom_config_fragment",
        ]
    return kernel_config_fragment_cmds


def get_kernel_defconfig_cmds(
    target_arch: str | None, kernel_defconfig: str | None
) -> list[str]:
    """Get the kernel defconfig command snippets.

    Args:
        target_arch: The target architecture for the build.
        kernel_defconfig: The path to the kernel defconfig file.

    Returns:
        List of command snippets to update the kernel annotations from a
        defconfig file.
    """
    kernel_defconfig_cmds = []
    if kernel_defconfig:
        kernel_defconfig_cmds = [
            "./debian/scripts/misc/annotations \\",
            f"--arch {target_arch} \\",
            "--flavor generic \\",
            f"--import ;{kernel_defconfig}",
        ]
    return kernel_defconfig_cmds


def get_kernel_dkms_cmds(
    target_arch: str | None, kernel_dkms_modules: list[str] | None
) -> list[str]:
    """Get the kernel DKMS command snippets.

    Args:
        target_arch: The target architecture for the build.
        kernel_dkms_modules: List of DKMS modules to include in the build.
    Returns:
        List of command snippets to update the kernel DKMS modules debian build
        rules.
    """
    kernel_dkms_cmds = []
    if kernel_dkms_modules:
        for dkms in kernel_dkms_modules:
            kernel_dkms_cmds.append(f"apt show {dkms} > pkginfo")
            kernel_dkms_cmds.append(
                "source=$(grep \"Source:\" pkginfo | sed 's/Source: \\(.*\\)$/\\1/g')"
            )
            kernel_dkms_cmds.append(
                "version=$(grep \"Version:\" pkginfo | sed 's/Version: \\(.*\\)$/\\1/g')"
            )
            kernel_dkms_cmds.append(
                "repo=$(grep \"Section:\" pkginfo | sed 's/Section: \\(.*\\)\\/.*$/\\1/g')"
            )
            kernel_dkms_cmds.append('echo "${source} ${version} " \\')
            toks = dkms.split("-")
            kernel_dkms_cmds.append('"modulename=${source} " \\')
            kernel_dkms_cmds.append(
                f'"debpath=pool/${{repo}}/{dkms[0]}/%package%/{dkms}_%version%_all.deb arch={target_arch} " \\'
            )
            kernel_dkms_cmds.append(f'"rprovides={toks[0]}-modules " \\')
            kernel_dkms_cmds.append(
                f'"rprovides={dkms}" >> debian.master/dkms-versions'
            )
    return kernel_dkms_cmds


def build_from_source_cmds(
    target_arch: str,
    kernel_defconfig: str | None,
    kernel_config_fragments: list[str] | None,
    kernel_tools: list[str] | None,
    kernel_dkms_modules: list[str] | None,
    kernel_image_target: str | None,
) -> list[str]:
    """Return build commands for building from source.

    Note: All paths have been normalised to a common ';' root character.

    Args:
        target_arch: Optional target architecture for the build.
        kernel_defconfig: Optional path to the kernel defconfig file.
        kernel_config_fragments: Optional list of kernel config fragments to apply.
        kernel_tools: Optional list of kernel tools to enable in the build.
        kernel_dkms_modules: Optional list of DKMS modules to include in the build.
        kernel_image_target: Optional kernel image target file name.
    Returns:
        List of build commands for building from source.
    """
    cross_build_cmds_post_debenv = get_cross_build_cmds(target_arch)
    kernel_image_target_cmds = get_kernel_image_target_cmds(
        target_arch, kernel_image_target
    )
    kernel_tools_cmds = get_kernel_tool_cmds(target_arch, kernel_tools)
    kernel_config_fragment_cmds = get_kernel_config_fragment_cmds(
        target_arch, kernel_config_fragments
    )
    kernel_defconfig_cmds = get_kernel_defconfig_cmds(target_arch, kernel_defconfig)
    kernel_dkms_cmds = get_kernel_dkms_cmds(target_arch, kernel_dkms_modules)

    return (
        [
            "rsync -aH ;parts/ubuntu-kernel/src/ ;parts/ubuntu-kernel/build/kernel-src",
            "cd ;parts/ubuntu-kernel/build/kernel-src",
            ". debian/debian.env",
        ]
        + cross_build_cmds_post_debenv
        + kernel_tools_cmds
        + kernel_image_target_cmds
        + kernel_config_fragment_cmds
        + kernel_defconfig_cmds
        + kernel_dkms_cmds
        + [
            "fakeroot debian/rules clean",
            "fakeroot debian/rules updateconfigs || true",
            "fakeroot debian/rules printenv",
            "fakeroot debian/rules build-generic",
            "fakeroot debian/rules binary-generic",
            "fakeroot debian/rules binary-headers",
            "cd ;parts/ubuntu-kernel/build",
            "mv ;parts/ubuntu-kernel/build/*.deb ;parts/ubuntu-kernel/build/kernel",
        ]
    )


def build_cmds(
    build_from_binary_package: bool,
    target_arch: str,
    kernel_defconfig: str | None = None,
    kernel_config_fragments: list[str] | None = None,
    kernel_tools: list[str] | None = None,
    kernel_dkms_modules: list[str] | None = None,
    kernel_image_target: str | None = None,
) -> list[str]:
    """Return build commands for building the Ubuntu kernel from a binary
    debpkg or source.

    Note: All paths have been normalised to a common ';' root character.

    Args:
        build_from_binary_package: Whether to build from binary packages.
        target_arch: The target architecture for the build.
        kernel_defconfig: Optional path to the kernel defconfig file.
        kernel_config_fragments: Optional list of kernel config fragments to apply.
        kernel_tools: Optional list of kernel tools to enable in the build.
        kernel_dkms_modules: Optional list of DKMS modules to include in the build.
        kernel_image_target: Optional kernel image target file name.
    Returns:
        List of common build commands for building the Ubuntu kernel.
    """
    build_type_cmds = (
        build_from_debpkg_cmds()
        if build_from_binary_package
        else build_from_source_cmds(
            target_arch=target_arch,
            kernel_defconfig=kernel_defconfig,
            kernel_config_fragments=kernel_config_fragments,
            kernel_tools=kernel_tools,
            kernel_dkms_modules=kernel_dkms_modules,
            kernel_image_target=kernel_image_target,
        )
    )

    dpkg_deb_linux_image_cmd = (
        [
            f"dpkg-deb -R linux-image-5.15.0-143-generic_5.15.0-143.153_{target_arch}.deb unpacked-linux-image",
        ]
        if build_from_binary_package
        else [
            f"dpkg-deb -R linux-image-unsigned-5.15.0-143-generic_5.15.0-143.153_{target_arch}.deb unpacked-linux-image",
        ]
    )
    cmds = (
        [
            "env",
            "mkdir -p ;parts/ubuntu-kernel/build/kernel",
        ]
        + build_type_cmds
        + [
            "cd ;parts/ubuntu-kernel/build/kernel",
        ]
        + dpkg_deb_linux_image_cmd
        + [
            f"dpkg-deb -x linux-modules-5.15.0-143-generic_5.15.0-143.153_{target_arch}.deb unpacked-linux-modules",
            f'if [ -f "linux-modules-extra-5.15.0-143-generic_5.15.0-143.153_{target_arch}.deb" ]; then',
            f"dpkg-deb -x linux-modules-extra-5.15.0-143-generic_5.15.0-143.153_{target_arch}.deb unpacked-linux-modules",
            "fi",
            "mv unpacked-linux-image/* ;parts/ubuntu-kernel/install",
            "mkdir -p ;parts/ubuntu-kernel/install/lib",
            "mv unpacked-linux-modules/lib/modules ;parts/ubuntu-kernel/install/lib/",
            "mv unpacked-linux-modules/boot/* ;parts/ubuntu-kernel/install/boot/",
            "depmod -b ;parts/ubuntu-kernel/install 5.15.0-143-generic",
            "mv ;parts/ubuntu-kernel/install/boot/* ;parts/ubuntu-kernel/install/",
            "ln -f ;parts/ubuntu-kernel/install/vmlinuz-5.15.0-143-generic ;parts/ubuntu-kernel/install/kernel.img",
            "mv ;parts/ubuntu-kernel/install/lib/modules ;parts/ubuntu-kernel/install/",
            "DTBS=unpacked-linux-firmware/lib/firmware/5.15.0-143/device-tree",
            '[ -d "${DTBS}" ] && mv "${DTBS}" ;parts/ubuntu-kernel/install/dtbs',
            "FIRMWARE=unpacked-linux-firmware/lib/firmware/5.15.0-143",
            '[ -d "${FIRMWARE}" ] && mv "${FIRMWARE}" ;parts/ubuntu-kernel/install/firmware',
            "rm -rf ;parts/ubuntu-kernel/install/boot",
        ]
    )
    cmd_list = [x.strip() for x in cmds if x]
    return cmd_list


@dataclasses.dataclass
class BuildParameters:
    """Parameters for the build normally provided by snapcraft."""

    base: str
    arch_build_on: str
    arch_build_for: str
    arch_triplet_build_for: str


@functools.lru_cache
def get_project_info_parameters() -> list[BuildParameters]:
    """Generate a ProjectInfo object common to all tests."""
    return [
        BuildParameters(
            base=base,
            arch_build_on="amd64",
            arch_build_for=arch_build_for,
            arch_triplet_build_for=arch_triplet_build_for,
        )
        for base in ["core22", "core24"]
        for arch_build_for in ["amd64", "arm64"]
        for arch_triplet_build_for in [
            "x86_64-linux-gnu" if arch_build_for == "amd64" else "aarch64-linux-gnu"
        ]
    ]


def get_test_fixture_ids() -> list[str]:
    """Generate fixture ids to help identify tests in logs."""
    params = get_project_info_parameters()
    return [f"{x.base}, {x.arch_build_for}" for x in params]


@pytest.fixture
def setup_method_fixture():
    """Fixture to set up common UbuntuKernelPlugin elements for testing."""

    def _setup_method_fixture(
        build_params: BuildParameters,
        new_dir: pathlib.Path,
        properties: dict[str, str] | None = None,
    ) -> UbuntuKernelPlugin:
        if not properties:
            properties = {"ubuntu-kernel-release-name": "jammy"}

        part = Part("ubuntu-kernel", {})

        project_info = ProjectInfo(
            application_name="test",
            cache_dir=new_dir,
            arch=build_params.arch_build_for,
            base=build_params.base,
        )

        part_info = PartInfo(project_info=project_info, part=part)
        properties_class = UbuntuKernelPlugin.properties_class.unmarshal(properties)
        return UbuntuKernelPlugin(
            properties=properties_class,
            part_info=part_info,
        )

    yield _setup_method_fixture


class TestParseVersionComponents:
    """Tests for _parse_version_components()."""

    def test_dash_format(self):
        version = ubuntu_kernel_plugin._parse_version_components("5.15.0-143.153")
        assert version is not None
        assert version.full_version == "5.15.0-143.153"
        assert version.kernel_abi() == "5.15.0-143"

    def test_dot_format(self):
        version = ubuntu_kernel_plugin._parse_version_components("5.4.0.1041.1041")
        assert version is not None
        assert version.full_version == "5.4.0-1041.1041"
        assert version.kernel_abi() == "5.4.0-1041"

    def test_dot_format_different_spin(self):
        version = ubuntu_kernel_plugin._parse_version_components("5.4.0.1041.45")
        assert version is not None
        assert version.full_version == "5.4.0-1041.45"
        assert version.kernel_abi() == "5.4.0-1041"

    def test_invalid_format_returns_none(self):
        assert ubuntu_kernel_plugin._parse_version_components("notaversion") is None


class TestGetKernelInfoFromLaunchpad:
    """Tests for get_kernel_info_from_launchpad()."""

    def _make_lp_mock(
        self,
        binary_side_effects: list,
        source_side_effects: list | None = None,
    ) -> tuple[mock.MagicMock, mock.MagicMock]:
        """Create a mock _get_launchpad() return value and mock archive.

        Args:
            binary_side_effects: side effects for archive.getPublishedBinaries().
            source_side_effects: side effects for archive.getPublishedSources().

        Returns:
            Tuple of (mock_lp, mock_archive) for use in assertions.
        """
        mock_archive = mock.MagicMock()
        mock_archive.getPublishedBinaries.side_effect = binary_side_effects
        if source_side_effects is None:
            source_side_effects = [[mock.MagicMock()]]
        mock_archive.getPublishedSources.side_effect = source_side_effects

        mock_das = mock.MagicMock()
        mock_series = mock.MagicMock()
        mock_series.getDistroArchSeries.return_value = mock_das

        mock_ubuntu = mock.MagicMock()
        mock_ubuntu.main_archive = mock_archive
        mock_ubuntu.getSeries.return_value = mock_series

        mock_lp = mock.MagicMock()
        mock_lp.distributions.__getitem__.return_value = mock_ubuntu

        return mock_lp, mock_archive

    def _entry(self, version: str) -> mock.MagicMock:
        entry = mock.MagicMock()
        entry.binary_package_version = version
        return entry

    def test_updates_pocket_returns_kernel_info(self):
        mock_lp, mock_archive = self._make_lp_mock([[self._entry("5.15.0-143.153")]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            kernel_info = ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                "jammy",
                "generic",
                "amd64",
                pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
            )
        assert kernel_info.apt_suite == "jammy-updates"
        assert kernel_info.version.kernel_abi() == "5.15.0-143"
        assert kernel_info.git_url == "https://example.test/kernel.git"
        mock_archive.getPublishedBinaries.assert_called_once()
        call_kwargs = mock_archive.getPublishedBinaries.call_args[1]
        assert call_kwargs["pocket"] == "Updates"
        assert call_kwargs["binary_name"] == "linux-image-generic"

    def test_release_pocket_uses_release_suffix(self):
        mock_lp, _ = self._make_lp_mock([[self._entry("6.8.0-1.1")]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            kernel_info = ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                "oracular",
                "generic",
                "amd64",
                pocket=ubuntu_kernel_plugin.KernelAptPocket.RELEASE,
            )
        assert kernel_info.apt_suite == "oracular-release"
        assert kernel_info.version.kernel_abi() == "6.8.0-1"

    def test_empty_binary_results_raises(self):
        mock_lp, _ = self._make_lp_mock([[]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            with pytest.raises(
                errors.SnapcraftError,
                match="no published kernel packages found",
            ):
                ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                    "jammy",
                    "generic",
                    "amd64",
                    pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
                )

    def test_empty_source_results_raises(self):
        mock_lp, _ = self._make_lp_mock(
            [[self._entry("5.15.0-143.153")]],
            source_side_effects=[[]],
        )
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            with pytest.raises(
                errors.SnapcraftError,
                match="no published kernel packages found",
            ):
                ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                    "jammy",
                    "generic",
                    "amd64",
                    pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
                )

    def test_explicit_security_pocket_single_call(self):
        mock_lp, mock_archive = self._make_lp_mock([[self._entry("5.15.0-143.153")]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            kernel_info = ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                "jammy",
                "generic",
                "amd64",
                pocket=ubuntu_kernel_plugin.KernelAptPocket.SECURITY,
            )
        assert kernel_info.apt_suite == "jammy-security"
        assert kernel_info.version.kernel_abi() == "5.15.0-143"
        mock_archive.getPublishedBinaries.assert_called_once()
        call_kwargs = mock_archive.getPublishedBinaries.call_args[1]
        assert call_kwargs["pocket"] == "Security"

    def test_explicit_pocket_no_results_raises(self):
        """Raises when explicit pocket returns no results."""
        mock_lp, _ = self._make_lp_mock([[]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            with pytest.raises(
                errors.SnapcraftError,
                match="no published kernel packages found",
            ):
                ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                    "jammy",
                    "generic",
                    "amd64",
                    pocket=ubuntu_kernel_plugin.KernelAptPocket.PROPOSED,
                )

    def test_returns_updates_suite_with_dot_version_format(self):
        """Handles metapackage all-dots version (e.g. linux-image-xilinx on arm64)."""
        mock_lp, _ = self._make_lp_mock([[self._entry("5.4.0.1041.1041")]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            kernel_info = ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                "jammy",
                "xilinx",
                "arm64",
                pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
            )
        assert kernel_info.apt_suite == "jammy-updates"
        assert kernel_info.version.kernel_abi() == "5.4.0-1041"

    def test_noble_release_returns_noble_updates(self):
        """apt_suite uses the correct release name prefix."""
        mock_lp, _ = self._make_lp_mock([[self._entry("6.8.0-51.52")]])
        with (
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
                return_value=mock_lp,
            ),
            mock.patch(
                "snapcraft.parts.plugins.ubuntu_kernel_plugin._resolve_kernel_git_url",
                return_value="https://example.test/kernel.git",
            ),
        ):
            kernel_info = ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                "noble",
                "generic",
                "amd64",
                pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
            )
        assert kernel_info.apt_suite == "noble-updates"
        assert kernel_info.version.kernel_abi() == "6.8.0-51"

    def test_raises_on_launchpad_connection_error(self):
        """Raises SnapcraftError when the Launchpad connection fails."""
        with mock.patch(
            "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
            side_effect=RuntimeError("network error"),
        ):
            with pytest.raises(
                errors.SnapcraftError,
                match="failed to query Launchpad Archive API",
            ):
                ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                    "jammy",
                    "generic",
                    "amd64",
                    pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
                )

    def test_raises_on_launchpad_api_error(self):
        """Raises SnapcraftError when the Launchpad API call fails."""
        mock_lp, _ = self._make_lp_mock([RuntimeError("API error")])
        with mock.patch(
            "snapcraft.parts.plugins.ubuntu_kernel_plugin._get_launchpad",
            return_value=mock_lp,
        ):
            with pytest.raises(
                errors.SnapcraftError,
                match="failed to query Launchpad Archive API",
            ):
                ubuntu_kernel_plugin.get_kernel_info_from_launchpad(
                    "jammy",
                    "generic",
                    "amd64",
                    pocket=ubuntu_kernel_plugin.KernelAptPocket.UPDATES,
                )


class TestPluginUbuntuKenrel:
    """UbuntuKernel plugin tests."""

    def test_property_requires_source_or_release_name(self, new_dir):
        """Test the property validates source and release name."""
        properties = {
            "plugin-name": "ubuntu-kernel",
        }
        with pytest.raises(
            errors.SnapcraftError,
            match="missing either 'ubuntu-kernel-release-name' or 'source' key",
        ):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

        properties["ubuntu-kernel-release-name"] = "hello"
        # Should not raise
        _ = UbuntuKernelPlugin.properties_class.unmarshal(properties)

        properties["source"] = "git://git-repo.git"
        with pytest.raises(
            errors.SnapcraftError,
            match="cannot use 'ubuntu-kernel-release-name' and 'source' keys at same time",
        ):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

    @pytest.mark.parametrize(
        "invalid_property, invalid_property_value",
        [
            ("ubuntu-kernel-defconfig", "my-defconfig-file"),
            ("ubuntu-kernel-config", ["CONFIG_FOO=1", "CONFIG_BAR=2"]),
            ("ubuntu-kernel-tools", ["perf", "cpupower", "bpftool"]),
            ("ubuntu-kernel-dkms", ["vpoll-dkms", "r8125-dkms"]),
        ],
    )
    def test_property_validation_with_binary_package(
        self,
        invalid_property,
        invalid_property_value,
        new_dir,
    ):
        """Test validation of binary package and config."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            invalid_property: invalid_property_value,
        }
        with pytest.raises(
            errors.SnapcraftError,
            match="'ubuntu-kernel-use-binary-package' and "
            f"'{invalid_property}' keys are mutually exclusive",
        ):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

        properties["ubuntu-kernel-use-binary-package"] = False
        # Should not raise
        _ = UbuntuKernelPlugin.properties_class.unmarshal(properties)

    def test_pocket_without_binary_package_is_allowed(self, new_dir):
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-pocket": "security",
        }
        props = UbuntuKernelPlugin.properties_class.unmarshal(properties)
        assert props.ubuntu_kernel_pocket == "security"

    def test_version_without_binary_package_is_allowed(self, new_dir):
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-version": "5.15.0-143.153",
        }
        props = UbuntuKernelPlugin.properties_class.unmarshal(properties)
        assert props.ubuntu_kernel_version == "5.15.0-143.153"

    def test_invalid_pocket_raises(self, new_dir):
        """An unrecognised pocket name raises SnapcraftError."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-pocket": "bleeding-edge",
        }
        with pytest.raises(
            errors.SnapcraftError, match="Invalid value for 'ubuntu_kernel_pocket'"
        ):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

    def test_invalid_abi_raises(self, new_dir):
        """An unparseable ABI string raises SnapcraftError."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-version": "notanabi",
        }
        with pytest.raises(errors.SnapcraftError, match="cannot parse kernel ABI"):
            UbuntuKernelPlugin.properties_class.unmarshal(properties)

    @pytest.mark.parametrize(
        "pocket_input",
        ["updates", "security", "release", "proposed"],
    )
    def test_valid_pocket_accepted(self, new_dir, pocket_input):
        """Valid pocket values are accepted."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-pocket": pocket_input,
        }
        props = UbuntuKernelPlugin.properties_class.unmarshal(properties)
        assert props.ubuntu_kernel_pocket == pocket_input

    @pytest.mark.parametrize(
        "version_input, expected",
        [
            ("5.15.0-143.153", "5.15.0-143.153"),
            ("5.15.0.143.153", "5.15.0.143.153"),
        ],
    )
    def test_valid_version_accepted(self, new_dir, version_input, expected):
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-version": version_input,
        }
        props = UbuntuKernelPlugin.properties_class.unmarshal(properties)
        assert props.ubuntu_kernel_version == expected

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_snaps(self, build_params, new_dir, setup_method_fixture):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
        )
        assert plugin.get_build_snaps() == set()

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_packages(self, build_params, new_dir, setup_method_fixture):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
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
            "pahole",
            "bzip2",
            "debhelper",
            "fakeroot",
            "lz4",
            "python3",
            "dwarfdump",
            "git",
        }
        additional_cross_compile_packages = {
            f"binutils-{plugin._part_info.arch_triplet_build_for}",
            f"gcc-{plugin._part_info.arch_triplet_build_for}",
            f"libc6-dev-{plugin._part_info.target_arch}-cross",
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
                f"libstdc++-13-dev-{plugin._part_info.target_arch}-cross",
            }
        )
        assert (
            expected_packages[build_params.base][build_params.arch_build_for]
            == plugin.get_build_packages()
        )

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_environment(self, build_params, new_dir, setup_method_fixture):
        """Test the expected build packages for building the Ubuntu kernel."""
        plugin = setup_method_fixture(new_dir=new_dir, build_params=build_params)
        expected_build_env = {
            "ARCH": build_params.arch_build_for,
            "CROSS_COMPILE": f"{build_params.arch_triplet_build_for}-",
            "DEB_HOST_ARCH": build_params.arch_build_for,
            "DEB_BUILD_ARCH": build_params.arch_build_on,
        }
        assert expected_build_env == plugin.get_build_environment()

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_source_url(
        self, build_params, new_dir, setup_method_fixture
    ):
        """Test the expected pull commands when a source url is provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "source": "git://git-repo.git",
            "source-type": "git",
            "source-depth": 1,
            "source-branch": "master-next",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-updates",
                version=KERNEL_VERSION_MOCK_VALUE,
            ),
        ):
            result = plugin.get_pull_commands()
        assert result == []

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_release_name_build_from_source(
        self, build_params, new_dir, setup_method_fixture
    ):
        """Test the expected pull commands when kernel release-name is provided."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-updates",
                version=KERNEL_VERSION_MOCK_VALUE,
            ),
        ):
            result = plugin.get_pull_commands()
        assert "git fetch" in result[0]
        assert "git checkout FETCH_HEAD" in result[0]
        assert (
            "https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy"
            in result[0]
        )

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_release_name_from_debpkg_binary(
        self, build_params, new_dir, setup_method_fixture
    ):
        """Test the expected pull commands when using a binary package."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-updates",
                version=KERNEL_VERSION_MOCK_VALUE,
            ),
        ):
            result = plugin.get_pull_commands()

        script = result[0]
        assert "Kernel ABI: 5.15.0-143" in script
        assert "apt show" not in script
        assert (
            f"apt download linux-image-5.15.0-143-generic:{build_params.arch_build_for}"
            in script
        )
        assert (
            f"apt download linux-modules-5.15.0-143-generic:{build_params.arch_build_for}"
            in script
        )
        assert (
            f"apt-cache show linux-modules-extra-5.15.0-143-generic:{build_params.arch_build_for}"
            in script
        )
        assert (
            f"apt download linux-modules-extra-5.15.0-143-generic:{build_params.arch_build_for}"
            in script
        )
        assert "apt download linux-firmware" in script

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_binary_release_pocket_no_extra_source(
        self, build_params, new_dir, setup_method_fixture
    ):
        """When pocket is 'Release', no extra pocket source lines are added."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-release",
                version=KERNEL_VERSION_MOCK_VALUE,
            ),
        ):
            result = plugin.get_pull_commands()

        script = result[0]
        assert "Kernel ABI: 5.15.0-143" in script

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_explicit_version(
        self, build_params, new_dir, setup_method_fixture
    ):
        """Explicit ubuntu-kernel-version overrides the LP version in script output."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-version": "5.15.0-143.999",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-updates",
                version=ubuntu_kernel_plugin.KernelVersion(
                    full_version="5.15.0-143.153",
                    version="5.15.0",
                    abi="143",
                    spin="153",
                ),
            ),
        ) as mock_lp:
            result = plugin.get_pull_commands()

        mock_lp.assert_called_once()
        script = result[0]
        assert "Kernel ABI: 5.15.0-143" in script

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_explicit_version_dot_format(
        self, build_params, new_dir, setup_method_fixture
    ):
        """Dot-format version is parsed and rendered with dash ABI in script."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-version": "5.15.0.143.567",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-updates",
                version=KERNEL_VERSION_MOCK_VALUE,
            ),
        ):
            result = plugin.get_pull_commands()

        # Dot format should be normalised to dash form
        assert "Kernel ABI: 5.15.0-143" in result[0]

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_pull_commands_with_explicit_pocket(
        self, build_params, new_dir, setup_method_fixture
    ):
        """Explicit ubuntu-kernel-pocket is forwarded to LP query."""
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
            "ubuntu-kernel-pocket": "security",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )
        with mock.patch.object(
            ubuntu_kernel_plugin,
            "get_kernel_info_from_launchpad",
            return_value=ubuntu_kernel_plugin.KernelInfo(
                git_url="https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy",
                apt_suite="jammy-security",
                version=KERNEL_VERSION_MOCK_VALUE,
            ),
        ) as mock_lp:
            result = plugin.get_pull_commands()

        mock_lp.assert_called_once_with(
            release_name="jammy",
            flavor="generic",
            arch=build_params.arch_build_for,
            pocket=ubuntu_kernel_plugin.KernelAptPocket.SECURITY,
        )
        assert "Kernel ABI: 5.15.0-143" in result[0]

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_use_binary_package(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands when using a binary debian package."""
        ubuntu_kernel_plugin.kernel_version_from_debpkg_file = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-use-binary-package": True,
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=True, target_arch=build_params.arch_build_for
        )
        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        assert actual_cmds == common_cmds

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_stock_kernel(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands with no kernel customisations."""

        ubuntu_kernel_plugin.kernel_version_from_source_tree = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=False, target_arch=build_params.arch_build_for
        )
        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        assert actual_cmds == common_cmds

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_with_extra_kernel_tools(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands with additional tools specified."""

        ubuntu_kernel_plugin.kernel_version_from_source_tree = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-tools": ["cpupower", "perf", "bpftool"],
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=False,
            target_arch=build_params.arch_build_for,
            kernel_tools=properties["ubuntu-kernel-tools"],
        )

        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        assert actual_cmds == common_cmds

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_with_defconfig(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands with a custom kernel defconfig."""

        ubuntu_kernel_plugin.kernel_version_from_source_tree = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-defconfig": "my-defconfig-file",
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=False,
            target_arch=build_params.arch_build_for,
            kernel_defconfig=properties["ubuntu-kernel-defconfig"],
        )

        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        actual_cmds = [
            re.sub(r"[^ ]*/my-defconfig-file", ";my-defconfig-file", x)
            for x in actual_cmds
            if x
        ]
        assert actual_cmds == common_cmds

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_with_config_fragments(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands with custom kernel config fragment."""

        ubuntu_kernel_plugin.kernel_version_from_source_tree = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-config": ["CONFIG_FOO=y", "CONFIG_BAR=m"],
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=False,
            target_arch=build_params.arch_build_for,
            kernel_config_fragments=properties["ubuntu-kernel-config"],
        )

        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        # Ignore comments written to the config fragment file
        actual_cmds = [re.sub(r'^\s*echo "#.*$', "", x) for x in actual_cmds if x]
        actual_cmds = [re.sub(r'^\s*echo ""', "", x) for x in actual_cmds if x]
        # Normalise the path for comparison
        actual_cmds = [
            re.sub(r"[^ ]*/custom_config_fragment", ";custom_config_fragment", x)
            for x in actual_cmds
            if x
        ]
        assert actual_cmds == common_cmds

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_with_image_target(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands for specific image target types."""
        ubuntu_kernel_plugin.kernel_version_from_source_tree = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        image_target = "vmlinux.strip"
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-image-target": image_target,
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=False,
            target_arch=build_params.arch_build_for,
            kernel_image_target=image_target,
        )
        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        assert actual_cmds == common_cmds

    @pytest.mark.parametrize(
        "build_params",
        get_project_info_parameters(),
        ids=get_test_fixture_ids(),
    )
    def test_get_build_commands_source_build_with_dkms_list(
        self,
        build_params,
        new_dir,
        setup_method_fixture,
        build_cmds_environ,
    ):
        """Test build commands with a list of additional kernel modules to build."""
        ubuntu_kernel_plugin.kernel_version_from_source_tree = mock.MagicMock(
            return_value=KERNEL_VERSION_MOCK_VALUE
        )
        properties = {
            "plugin-name": "ubuntu-kernel",
            "ubuntu-kernel-release-name": "jammy",
            "ubuntu-kernel-dkms": ["vpoll-dkms", "evdi-dkms", "r8125-dkms"],
        }
        plugin = setup_method_fixture(
            new_dir=new_dir,
            build_params=build_params,
            properties=properties,
        )

        common_cmds = build_cmds(
            build_from_binary_package=False,
            target_arch=build_params.arch_build_for,
            kernel_dkms_modules=properties["ubuntu-kernel-dkms"],
        )
        actual_cmds = normalise_actual_cmds(plugin.get_build_commands())
        assert actual_cmds == common_cmds
