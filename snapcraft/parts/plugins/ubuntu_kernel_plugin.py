# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright 2025 Canonical Ltd.
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

"""The Ubuntu kernel plugin for building Ubuntu Core kernel snaps."""

import os
import pathlib
import re
import subprocess
from typing import Literal, cast

import jinja2
import pydantic
import requests
from craft_cli import emit
from craft_parts import infos, plugins
from typing_extensions import Self, override

from snapcraft import errors

# The kernel repository depends on the flavor
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

_LAUNCHPAD_ARCHIVE_API_URL = "https://api.launchpad.net/1.0/ubuntu/+archive/primary"

_POCKET_TO_SUITE_SUFFIX: dict[str, str] = {
    "Release": "",
    "Security": "-security",
    "Updates": "-updates",
    "Proposed": "-proposed",
    "Backports": "-backports",
}

_VALID_POCKET_NAMES: frozenset[str] = frozenset(_POCKET_TO_SUITE_SUFFIX.keys())


def kernel_abi_from_version(kernel_version: str) -> str:
    """Given the kernel version string extract the ABI component.

    Handles two version formats:
    - Dash format:  "5.15.0-143.153"  → "5.15.0-143"  (source/deb packages)
    - Dot format:   "5.4.0.1041.1041" → "5.4.0-1041"  (kernel metapackages)

    Args:
        kernel_version (str): The kernel version string with ABI and spin
        number, e.g. "5.15.0-1012.13" or "5.4.0.1041.1041".
    Returns:
        str: The kernel version with ABI but no spin number, e.g. "5.15.0-1012".
    """
    # Format 1: X.Y.Z-ABI.SPIN (source tree / deb filenames)
    rem = re.match(r"(\d+\.\d+\.\d+-\d+)\.\d+", kernel_version)
    if rem:
        return rem.group(1)
    # Format 2: X.Y.Z.ABI.SPIN (kernel metapackage versions from LP API)
    rem = re.match(r"(\d+\.\d+\.\d+)\.(\d+)\.\d+", kernel_version)
    if rem:
        return f"{rem.group(1)}-{rem.group(2)}"
    raise errors.SnapcraftError("cannot parse kernel version from changelog")


def normalise_kernel_abi(abi_str: str) -> str:
    """Normalise a user-supplied kernel ABI string to the canonical dash format.

    Accepts:
        "5.15.0-143"  (canonical dash form)
        "5.15.0.143"  (dot form used by some Ubuntu metapackages)

    Returns:
        "5.15.0-143"  (always canonical dash form)

    Raises:
        SnapcraftError: if the string cannot be parsed.
    """
    if re.match(r"^\d+\.\d+\.\d+-\d+$", abi_str):
        return abi_str
    rem = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)$", abi_str)
    if rem:
        return f"{rem.group(1)}-{rem.group(2)}"
    raise errors.SnapcraftError(
        f"cannot parse kernel ABI from {abi_str!r}",
        resolution="Provide a valid kernel ABI like '5.15.0-143' or '5.15.0.143'.",
    )


def kernel_version_from_source_tree(source_root: pathlib.Path) -> tuple[str, str]:
    """Given a changelog file path open it and extract the kernel version.

    Args:
        source_root: The path to the source root directory
    Returns:
        A tuple containing the full kernel version and kernel ABI version
    """
    changelog_file = source_root / "debian.master" / "changelog"
    with changelog_file.open("r") as fptr:
        version_line = fptr.readline()
    kernel_version = version_line.split("(")[1].split(")")[0]
    kernel_abi = kernel_abi_from_version(kernel_version)
    return kernel_version, kernel_abi


def kernel_version_from_debpkg_file(root_dir: pathlib.Path) -> tuple[str, str]:
    """Get the kernel version from debian package file names.

    Args:
        root_dir: The path to the directory containing the *.deb files.

    Returns:
        A tuple containing the full kernel version and kernel ABI version.
    """
    version_re = re.compile(r".*(\d+\.\d+\.\d+-\d+\.\d+).*\.deb")
    for filename in [
        pobj.name for pobj in sorted(root_dir.iterdir()) if pobj.is_file()
    ]:
        rem = version_re.search(filename)
        if rem:
            kernel_version = rem.group(1)
            kernel_abi = kernel_abi_from_version(kernel_version)
            return kernel_version, kernel_abi
    raise errors.SnapcraftError("cannot identify kernel version from Debian packages")


def kernel_launchpad_repository(release_name: str) -> str:
    """Get the kernel launchpad repository.

    Args:
        release_name: The name of the Ubuntu release, e.g. "jammy", "noble".
    Returns:
        The URL of the kernel source repository for the given release.
    """
    return KERNEL_REPO_STEM + release_name


def get_kernel_deb_info_from_launchpad(
    release_name: str, flavour: str, arch: str, pocket: str | None = None
) -> tuple[str, str]:
    """Query the Launchpad Archive API for the kernel metapackage ABI.

    Args:
        release_name: Ubuntu release name, e.g. "jammy".
        flavour: Kernel flavour, e.g. "generic".
        arch: Debian architecture string, e.g. "amd64", "arm64".
        pocket: LP pocket name ("Updates", "Release", "Security", …).
                When None, tries Updates then falls back to Release.

    Returns:
        Tuple of (apt_suite, kernel_abi), e.g. ("jammy-updates", "5.15.0-143").

    Raises:
        SnapcraftError: if the API call fails or no packages are found.
    """

    def _query(pocket_filter: str | None) -> list[dict]:
        params = {
            "ws.op": "getPublishedBinaries",
            "binary_name": f"linux-image-{flavour}",
            "distro_arch_series": (
                f"https://api.launchpad.net/1.0/ubuntu/{release_name}/{arch}"
            ),
            "status": "Published",
            "ordered_by_date": "true",
        }
        if pocket_filter:
            params["pocket"] = pocket_filter
        emit.debug(
            f"Querying Launchpad API for linux-image-{flavour} on "
            f"{release_name}/{arch}"
            + (f" ({pocket_filter} pocket)" if pocket_filter else "")
        )
        try:
            response = requests.get(
                _LAUNCHPAD_ARCHIVE_API_URL, params=params, timeout=30
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise errors.SnapcraftError(
                f"failed to query Launchpad Archive API: {exc}",
                resolution="Verify connectivity to https://api.launchpad.net and retry.",
            ) from exc
        return response.json().get("entries", [])

    if pocket is not None:
        entries = _query(pocket)
        resolved_pocket = pocket
        if not entries:
            raise errors.SnapcraftError(
                f"no published kernel packages found for "
                f"linux-image-{flavour} on {release_name}/{arch} "
                f"in the {pocket} pocket",
                resolution="Verify the release name, flavour, pocket, and architecture.",
            )
    else:
        # Sensible default: prefer Updates, fall back to Release.
        entries = _query("Updates")
        resolved_pocket = "Updates"
        if not entries:
            emit.debug("No packages in Updates pocket, trying Release pocket")
            entries = _query("Release")
            resolved_pocket = "Release"
        if not entries:
            raise errors.SnapcraftError(
                f"no published kernel packages found for "
                f"linux-image-{flavour} on {release_name}/{arch} "
                f"in the Updates or Release pockets",
                resolution="Verify the release name, flavour, and architecture.",
            )

    kernel_version: str = entries[0]["binary_package_version"]
    kernel_abi = kernel_abi_from_version(kernel_version)
    apt_suite = f"{release_name}{_POCKET_TO_SUITE_SUFFIX[resolved_pocket]}"
    emit.debug(
        f"Resolved kernel: version={kernel_version!r}, pocket={resolved_pocket!r}, "
        f"apt_suite={apt_suite!r}, kernel_abi={kernel_abi!r}"
    )
    return apt_suite, kernel_abi


def package_exists_in_apt_cache(package: str) -> bool:
    """Check if a package exists in apt."""
    result = subprocess.run(
        ["apt-cache", "show", package], capture_output=True, check=True
    )
    return result.returncode == 0 and b"Package:" in result.stdout


class UbuntuKernelPluginProperties(plugins.properties.PluginProperties, frozen=True):
    """The part properties used by the Ubuntu kernel plugin."""

    plugin: Literal["ubuntu-kernel"] = "ubuntu-kernel"
    """Plugin name."""
    ubuntu_kernel_flavor: str = "generic"
    """The ubuntu kernel flavor, will be ignored if defconfig provided."""
    ubuntu_kernel_dkms: list[str] = []
    """Additional dkms."""
    ubuntu_kernel_release_name: str | None = None
    """Ubuntu release to build. Mutually exclusive with 'source'."""
    ubuntu_kernel_defconfig: str | None = None
    """Path to custom defconfig, relative to the project directory."""
    ubuntu_kernel_config: list[str] = []
    """Custom set of kernel configuration parameters."""
    ubuntu_kernel_image_target: str | None = None
    """Kernel image target type."""
    ubuntu_kernel_tools: list[str] = []
    """Kernel tools to include, e.g. perf."""
    ubuntu_kernel_use_binary_package: bool = False
    """Flag to use prebuilt kernel packages. Only valid with ubuntu-kernel-release-name."""
    ubuntu_kernel_pocket: str | None = None
    """Apt pocket to pull kernel debs from ('updates', 'release', 'security', 'proposed').
    Only valid with ubuntu-kernel-use-binary-package. Default: auto-detect via LP API
    (prefers 'updates', falls back to 'release')."""
    ubuntu_kernel_abi: str | None = None
    """Explicit kernel ABI version, e.g. '5.15.0-143' or '5.15.0.143'.
    When set the LP API is not queried. Requires ubuntu-kernel-use-binary-package."""

    @pydantic.field_validator("ubuntu_kernel_pocket")
    @classmethod
    def validate_pocket(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # Normalise to title-case for internal use (matches LP API + _POCKET_TO_SUITE_SUFFIX)
        title = value.strip().title()
        if title not in _VALID_POCKET_NAMES:
            raise errors.SnapcraftError(
                f"invalid pocket {value!r}",
                resolution=(
                    f"Valid pockets: {sorted(p.lower() for p in _VALID_POCKET_NAMES)}"
                ),
            )
        return title

    @pydantic.field_validator("ubuntu_kernel_abi")
    @classmethod
    def validate_kernel_abi_field(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalise_kernel_abi(value)

    @pydantic.model_validator(mode="after")
    def validate_binary_only_options_require_binary_mode(self) -> Self:
        """Enforce that pocket/abi fields require ubuntu_kernel_use_binary_package."""
        if not self.ubuntu_kernel_use_binary_package:
            for option in ("ubuntu_kernel_pocket", "ubuntu_kernel_abi"):
                if getattr(self, option):
                    raise errors.SnapcraftError(
                        f"'{option.replace('_', '-')}' requires "
                        "'ubuntu-kernel-use-binary-package' to be set"
                    )
        return self

    @pydantic.model_validator(mode="after")
    def validate_release_name_and_source_exclusive(self) -> Self:
        """Enforce release_name and source options are mutually exclusive."""
        if self.ubuntu_kernel_release_name and self.source:
            raise errors.SnapcraftError(
                "cannot use 'ubuntu-kernel-release-name' and 'source' keys at same time"
            )
        if not self.ubuntu_kernel_release_name and not self.source:
            raise errors.SnapcraftError(
                "missing either 'ubuntu-kernel-release-name' or 'source' key"
            )
        return self

    @pydantic.model_validator(mode="after")
    def validate_binary_package_and_source_build_options_mutually_exclusive(
        self,
    ) -> Self:
        """Enforce binary package and source-only options are exclusive."""
        if self.ubuntu_kernel_use_binary_package:
            conflicting_options = [
                "source",
                "ubuntu_kernel_config",
                "ubuntu_kernel_defconfig",
                "ubuntu_kernel_image_target",
                "ubuntu_kernel_tools",
                "ubuntu_kernel_dkms",
            ]
            for option in conflicting_options:
                if getattr(self, option):
                    raise errors.SnapcraftError(
                        "'ubuntu-kernel-use-binary-package' and "
                        f"'{option.replace('_', '-')}' keys are mutually exclusive"
                    )
        return self

    @pydantic.field_validator("ubuntu_kernel_tools")
    @classmethod
    def validate_tool_list(cls, value: list[str]) -> list[str]:
        """Check the list of tools is in the available list."""
        unknown_tools = [tool for tool in value if tool not in _AVAILABLE_TOOLS]
        if unknown_tools:
            raise errors.SnapcraftError(
                "The following requested tools are not supported: "
                f"{unknown_tools!r}. Supported tools: {_AVAILABLE_TOOLS!r}"
            )
        return value


class UbuntuKernelPlugin(plugins.Plugin):
    """Plugin for the Ubuntu kernel snap build."""

    properties_class = UbuntuKernelPluginProperties

    def __init__(
        self, *, properties: plugins.PluginProperties, part_info: infos.PartInfo
    ) -> None:
        super().__init__(properties=properties, part_info=part_info)
        self.options = cast(UbuntuKernelPluginProperties, self._options)
        if part_info.base not in ("core22", "core24"):
            raise errors.SnapcraftError("only core22 and core24 bases are supported")
        self.release_name = self.options.ubuntu_kernel_release_name
        self.image_target = (
            self.options.ubuntu_kernel_image_target
            if self.options.ubuntu_kernel_image_target is not None
            else _DEFAULT_KERNEL_IMAGE_TARGET[part_info.arch_build_for]
        )

    @override
    def get_build_snaps(self) -> set[str]:
        return set()

    @override
    def get_build_packages(self) -> set[str]:
        # This should instead extract the build dependency list from the Debian
        #  source package. See https://warthogs.atlassian.net/browse/KE-427
        build_packages = {
            "common": frozenset(
                {
                    "autoconf",
                    "automake",
                    "bc",
                    "bison",
                    "bzip2",
                    "cpio",
                    "curl",
                    "debhelper",
                    "debhelper-compat",
                    "default-jdk-headless",
                    "dkms",
                    "dwarfdump",
                    "fakeroot",
                    "flex",
                    "gawk",
                    "git",
                    "java-common",
                    "kmod",
                    "libaudit-dev",
                    "libcap-dev",
                    "libdw-dev",
                    "libelf-dev",
                    "libiberty-dev",
                    "liblzma-dev",
                    "libnewt-dev",
                    "libnuma-dev",
                    "libpci-dev",
                    "libssl-dev",
                    "libtool",
                    "libudev-dev",
                    "libunwind8-dev",
                    "lz4",
                    "makedumpfile",
                    "openssl",
                    "pahole",  # not in control file
                    "pkg-config",
                    "python3",
                    "python3-dev",
                    "rsync",
                    "uuid-dev",
                    "zstd",
                    *(
                        {
                            f"binutils-{self._part_info.arch_triplet_build_for}",
                            f"gcc-{self._part_info.arch_triplet_build_for}",
                            f"libc6-dev-{self._part_info.target_arch}-cross",
                        }
                        if self._part_info.is_cross_compiling
                        else set()
                    ),
                }
            ),
            "core22": frozenset(),
            "core24": frozenset(
                {
                    "bindgen-0.65",
                    "clang-18",
                    "libstdc++-13-dev",
                    "libtraceevent-dev",
                    "libtracefs-dev",
                    "python3-setuptools",
                    "rust-src",
                    "rustc",
                    "rustfmt",
                    *(
                        {
                            f"libstdc++-13-dev-{self._part_info.target_arch}-cross",
                        }
                        if self._part_info.is_cross_compiling
                        else set()
                    ),
                }
            ),
        }
        return set(build_packages["common"] | build_packages[self._part_info.base])

    @override
    def get_build_environment(self) -> dict[str, str]:
        """Returns additional build environment variables."""
        emit.debug("Getting build environment")
        return {
            "ARCH": self._part_info.arch_build_for,
            "CROSS_COMPILE": f"{self._part_info.arch_triplet_build_for}-",
            "DEB_HOST_ARCH": self._part_info.arch_build_for,
            "DEB_BUILD_ARCH": self._part_info.arch_build_on,
        }

    @override
    def get_pull_commands(self) -> list[str]:
        """Get the commands to pull the source code for the part.

        This will clone the kernel source explicitly if no `source` URL is
        provided. If building with binary deb packages, it will fetch the
        debian packages.

        See jinja2 templates in snapcraft/templates/kernel/ for details.
        """
        emit.debug("Getting pull commands")
        if self.options.source:
            return super().get_pull_commands()
        if not self.release_name:
            raise errors.SnapcraftError(
                "missing either 'ubuntu-kernel-release-name' or 'source' key"
            )
        template_file = "kernel/ubuntu_kernel_get_pull_commands.sh.j2"
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("snapcraft", "templates"), autoescape=True
        )
        template = env.get_template(template_file)
        source_repo_url = kernel_launchpad_repository(self.release_name)

        apt_suite: str | None = None
        kernel_abi: str | None = None
        if self.options.ubuntu_kernel_use_binary_package:
            if self.options.ubuntu_kernel_abi:
                # User supplied ABI explicitly — skip LP query.
                kernel_abi = (
                    self.options.ubuntu_kernel_abi
                )  # already normalised by validator
                pocket = self.options.ubuntu_kernel_pocket or "Updates"  # title-case
                apt_suite = f"{self.release_name}{_POCKET_TO_SUITE_SUFFIX[pocket]}"
            else:
                apt_suite, kernel_abi = get_kernel_deb_info_from_launchpad(
                    release_name=self.release_name,
                    flavour=self.options.ubuntu_kernel_flavour,
                    arch=self._part_info.target_arch,
                    pocket=self.options.ubuntu_kernel_pocket,  # None → auto-detect
                )

        script = template.render(
            {
                "ubuntu_kernel_use_binary_package": self.options.ubuntu_kernel_use_binary_package,
                "ubuntu_kernel_release_name": self.release_name,
                "is_cross_compiling": self._part_info.is_cross_compiling,
                "target_arch": self._part_info.target_arch,
                "ubuntu_kernel_flavor": self.options.ubuntu_kernel_flavor,
                "source_repo_url": source_repo_url,
                "apt_suite": apt_suite,
                "kernel_abi": kernel_abi,
            }
        )
        return [script]

    @override
    def get_build_commands(self) -> list[str]:
        """Get the commands to build the part.

        The build command script is defined in the jinja2 templates under
        snapcraft/templates/kernel/.
        """
        emit.debug("Getting build commands")
        # Get the kernel version from the source files.
        if self.options.ubuntu_kernel_use_binary_package:
            kernel_version, kernel_abi = kernel_version_from_debpkg_file(
                self._part_info.part_src_dir
            )
        else:
            kernel_version, kernel_abi = kernel_version_from_source_tree(
                self._part_info.part_src_dir
            )

        template_file = "kernel/ubuntu_kernel_get_build_commands.sh.j2"
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("snapcraft", "templates"), autoescape=True
        )
        template = env.get_template(template_file)
        script = template.render(
            {
                "craft_arch_build_for": self._part_info.arch_build_for,
                "craft_arch_build_on": self._part_info.arch_build_on,
                "craft_arch_triplet_build_for": self._part_info.arch_triplet_build_for,
                "craft_arch_triplet_build_on": self._part_info.arch_triplet_build_on,
                "craft_part_build_dir": self._part_info.part_build_dir,
                "craft_part_install_dir": self._part_info.part_install_dir,
                "craft_part_src_dir": self._part_info.part_src_dir,
                "craft_project_dir": self._part_info.project_dir,
                "has_ubuntu_kernel_config_fragments": bool(
                    self.options.ubuntu_kernel_config
                ),
                "has_ubuntu_kernel_defconfig": bool(
                    self.options.ubuntu_kernel_defconfig
                ),
                "has_ubuntu_kernel_image_target": bool(
                    self.options.ubuntu_kernel_image_target
                ),
                "is_cross_compiling": self._part_info.is_cross_compiling,
                "kernel_abi": kernel_abi,
                "kernel_version": kernel_version,
                "pkgfile_version_all": f"{kernel_abi}_{kernel_version}_all",
                # The package version can get quite long so to keep jinja2
                # templates readable it is substituted with a variable.
                "pkgfile_version_flavor": (
                    f"{kernel_abi}-{self.options.ubuntu_kernel_flavor}_"
                    f"{kernel_version}_{self._part_info.target_arch}"
                ),
                "snap_context": os.environ["SNAP_CONTEXT"],
                "snap_data_path": os.environ["SNAP"],
                "snap_version": os.environ["SNAP_VERSION"],
                "target_arch": self._part_info.target_arch,
                "ubuntu_kernel_config": self.options.ubuntu_kernel_config,
                "ubuntu_kernel_defconfig": self.options.ubuntu_kernel_defconfig,
                "ubuntu_kernel_dkms": self.options.ubuntu_kernel_dkms,
                "ubuntu_kernel_flavor": self.options.ubuntu_kernel_flavor,
                "ubuntu_kernel_image_target": self.options.ubuntu_kernel_image_target,
                "ubuntu_kernel_tools": self.options.ubuntu_kernel_tools,
                "ubuntu_kernel_use_binary_package": self.options.ubuntu_kernel_use_binary_package,
            }
        )
        return [script]

    @override
    @classmethod
    def get_out_of_source_build(cls) -> bool:
        """Return whether the plugin performs out-of-source-tree builds."""
        return True
