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

import dataclasses
import enum
import os
import pathlib
import re
from functools import lru_cache
from typing import Literal, cast

import jinja2
import pydantic
import requests
from craft_cli import emit
from craft_parts import infos, plugins
from launchpadlib.launchpad import Launchpad
from typing_extensions import Self, override

from snapcraft import errors

# The kernel repository depends on the flavor
KERNEL_REPO_STEM = "https://git.launchpad.net/~{owner}/ubuntu/+source/{source_name}/+git/{release_name}"
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


@dataclasses.dataclass
class KernelVersion:
    """Ubuntu kernel version information."""

    full_version: str
    abi: str
    version: str
    spin: str

    def kernel_abi(self) -> str:
        """Get the kernel ABI version"""
        return f"{self.version}-{self.abi}"


class KernelAptPocket(str, enum.Enum):
    """Apt pocket to pull kernel debs from."""

    UPDATES = "updates"
    RELEASE = "release"
    SECURITY = "security"
    PROPOSED = "proposed"


def _parse_version_components(input_str: str) -> KernelVersion | None:
    """Parse the version string and return the parts.

    Handles two version formats:
    - Dash format:  "5.15.0-143.153"  → "5.15.0-143"  (source/deb packages)
    - Dot format:   "5.4.0.1041.1041" → "5.4.0-1041"  (kernel metapackages)

    Args:
        input_str: Kernel version to parse
    Returns:
        A KernelVersion with components extracted from the version string
    """
    emit.debug(f"Parse version components: {input_str}")
    rem = re.match(r".*(\d+\.\d+\.\d+)-(\d+)\.(\d+).*$", input_str)
    if not rem:
        # Format 2: X.Y.Z.ABI.SPIN (kernel metapackage versions from LP API)
        rem = re.match(r".*(\d+\.\d+\.\d+)\.(\d+)\.(\d+).*$", input_str)
    if rem:
        return KernelVersion(
            full_version=f"{rem.group(1)}-{rem.group(2)}.{rem.group(3)}",
            version=rem.group(1),
            abi=rem.group(2),
            spin=rem.group(3),
        )
    return None


def kernel_version_from_source_tree(
    source_root: pathlib.Path, flavor: str
) -> KernelVersion:
    """Given a changelog file path, open it and extract the kernel version.

    Args:
        source_root: The path to the source root directory
        flavor: Kernel flavor to look up
    Returns:
        A KernelVersion dataclass
    """
    changelog_file = source_root / f"debian.{flavor}" / "changelog"
    with changelog_file.open("r") as fptr:
        version_line = fptr.readline()
    kernel_version = _parse_version_components(version_line.split("(")[1].split(")")[0])
    if not kernel_version:
        raise errors.SnapcraftError("Failed to parse kernel version from changelog")
    return kernel_version


def kernel_version_from_debpkg_file(root_dir: pathlib.Path) -> KernelVersion:
    """Get the kernel version from debian package file names.

    Args:
        root_dir: The path to the directory containing the *.deb files.

    Returns:
        A tuple containing the full kernel version and kernel ABI version.
    """
    for filename in root_dir.glob("linux*image*.deb"):
        kernel_version = _parse_version_components(str(filename))
        if kernel_version:
            return kernel_version
    raise errors.SnapcraftError("cannot identify kernel version from Debian packages")


@lru_cache(maxsize=1)
def _get_launchpad() -> Launchpad:
    """Get an anonymous Launchpad API connection."""
    return Launchpad.login_anonymously(
        "snapcraft-ubuntu-kernel", "production", version="devel"
    )


def _resolve_kernel_git_url(release_name: str, flavor: str) -> str:
    """Get the kernel source git URL."""
    # Launchpad does not have an API to find the git repository for a kernel
    # from series name and flavor. We have to match against the two manifests
    # to find the owner.

    team_names = ["ubuntu-kernel", "canonical-kernel"]
    source_pkg = "linux"
    if flavor != "generic":
        source_pkg = f"linux-{flavor}"

    for name in team_names:
        url = f"https://code.launchpad.net/~{name}/+git"
        try:
            response = requests.get(url, timeout=5)
        except requests.RequestException as exc:
            raise errors.SnapcraftError(f"Failed to fetch {url}") from exc

        # Look for the source package repository for the release name
        # The URL pattern is typically: /~name/ubuntu/+source/source_pkg/+git/release_name
        match_part = f"~{name}/ubuntu/+source/{source_pkg}/+git/{release_name}"
        if match_part in response.text:
            return f"https://git.launchpad.net/~{name}/ubuntu/+source/{source_pkg}/+git/{release_name}"
    raise errors.SnapcraftError(
        f"failed to find kernel source url: {release_name}:linux-{flavor}"
    )


@dataclasses.dataclass
class KernelInfo:
    git_url: str
    apt_suite: str
    version: KernelVersion


def get_kernel_info_from_launchpad(
    release_name: str, flavor: str, arch: str, pocket: KernelAptPocket
) -> KernelInfo:
    """Query the Launchpad Archive API for the kernel metapackage ABI.

    Args:
        release_name: Ubuntu release name, e.g. "jammy".
        flavor: Kernel flavor, e.g. "generic".
        arch: Debian architecture string, e.g. "amd64", "arm64".
        pocket: LP pocket

    Returns:
        A kernel launchpad info instnace

    Raises:
        SnapcraftError: if the API call fails or no packages are found.
    """
    try:
        lp = _get_launchpad()
        ubuntu = lp.distributions["ubuntu"]
        archive = ubuntu.main_archive
        series = ubuntu.getSeries(name_or_version=release_name)
        distro_arch_series = series.getDistroArchSeries(archtag=arch)
    except Exception as exc:
        raise errors.SnapcraftError(
            f"failed to query Launchpad Archive API: {exc}",
            resolution="Verify connectivity to https://api.launchpad.net and retry.",
        ) from exc

    def _query() -> tuple[list, list]:
        emit.debug(
            f"Querying Launchpad API for linux-image-{flavor} on "
            f"{release_name}/{arch}" + f" ({pocket.value} pocket)"
        )
        try:
            query_result = archive.getPublishedBinaries(
                binary_name=f"linux-image-{flavor}",
                distro_arch_series=distro_arch_series,
                status="Published",
                pocket=pocket.value.capitalize(),
            )
            source_query_result = archive.getPublishedSources(
                source_name=f"linux-{flavor}", distro_series=series, status="Published"
            )
            return list(query_result), list(source_query_result)
        except Exception as query_exc:
            raise errors.SnapcraftError(
                f"failed to query Launchpad Archive API: {query_exc}",
                resolution="Verify connectivity to https://api.launchpad.net and retry.",
            ) from query_exc

    binary_entries, source_entries = _query()
    if not binary_entries or not source_entries:
        raise errors.SnapcraftError(
            f"no published kernel packages found for "
            f"linux-image-{flavor} on {release_name}/{arch} "
            f"in the {pocket} pocket",
            resolution="Verify the release name, flavor, pocket, and architecture.",
        )

    kernel_version = _parse_version_components(binary_entries[0].binary_package_version)
    apt_suite = f"{release_name}-{pocket.value}"
    git_url = _resolve_kernel_git_url(release_name=release_name, flavor=flavor)

    emit.debug(
        f"Resolved kernel: version={kernel_version}, pocket={pocket.value}, "
        f"apt_suite={apt_suite}, "
        f"git_url={git_url}, "
        f"kernel_abi={kernel_version.kernel_abi}"
    )
    return KernelInfo(git_url=git_url, apt_suite=apt_suite, version=kernel_version)


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
    ubuntu_kernel_pocket: str | None = "updates"
    """Apt pocket to pull kernel debs from ('updates', 'release', 'security', 'proposed').
    Default: updates"""
    ubuntu_kernel_version: str | None = None
    """Explicit kernel version, e.g. '5.15.0-143.567' or '5.15.0.143.567'.
    When set the LP API is not queried. Requires ubuntu-kernel-use-binary-package."""
    ubuntu_kernel_source_ref: str | None = None
    """Explicit kernel git ref to checkout when building from source.
    This can be a branch, tag or commit sha references. This option is only
    applicable when ubuntu_kernel_use_binary_package is false."""

    @pydantic.field_validator("ubuntu_kernel_version")
    @classmethod
    def validate_kernel_version_field(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _parse_version_components(value):
            raise errors.SnapcraftError(
                f"cannot parse kernel ABI from {value}",
                resolution="Provide a valid kernel ABI like '5.15.0-143.145' "
                "or '5.15.0.143.145'.",
            )
        return value

    @pydantic.model_validator(mode="after")
    def validate_binary_only_options_require_binary_mode(self) -> Self:
        """Enforce that pocket is a valid type."""
        if self.ubuntu_kernel_pocket not in KernelAptPocket.__members__.values():
            raise errors.SnapcraftError(
                "'ubuntu-kernel-pocket' must be one of 'updates', 'release', "
                f"'security', 'proposed', got '{self.ubuntu_kernel_pocket}'",
                resolution="Choose a valid pocket type.",
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
                "ubuntu_kernel_source_ref",
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
                f"{unknown_tools}. Supported tools: {_AVAILABLE_TOOLS}"
            )
        return value

    @pydantic.field_validator("ubuntu_kernel_pocket")
    @classmethod
    def validate_kernel_pocket(cls, value: str | None) -> str | None:
        """Check the kernel pocket is a valid debian package pocket."""
        if value is None:
            return None
        values = [x.value for x in KernelAptPocket]
        if value not in values:
            raise errors.SnapcraftError(
                f"Invalid value for 'ubuntu_kernel_pocket': {value}. "
                f"Valid values: {values}"
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
        self.pocket = (
            KernelAptPocket(self.options.ubuntu_kernel_pocket)
            if self.options.ubuntu_kernel_pocket
            else None
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
        source_repo_url: str | None = None
        kernel_info = get_kernel_info_from_launchpad(
            release_name=self.release_name,
            flavor=self.options.ubuntu_kernel_flavor,
            arch=self._part_info.target_arch,
            pocket=self.pocket,
        )
        if (
            self.options.ubuntu_kernel_use_binary_package
            and self.options.ubuntu_kernel_version
        ):
            # User supplied ABI explicitly — override LP queried version.
            kernel_info.version = _parse_version_components(
                self.options.ubuntu_kernel_version
            )
        source_repo_url = kernel_info.git_url
        kernel_abi = kernel_info.version.kernel_abi()
        template_vars = {
            "ubuntu_kernel_use_binary_package": self.options.ubuntu_kernel_use_binary_package,
            "ubuntu_kernel_release_name": self.release_name,
            "is_cross_compiling": self._part_info.is_cross_compiling,
            "host_arch": self._part_info.arch_build_on,
            "target_arch": self._part_info.target_arch,
            "ubuntu_kernel_flavor": self.options.ubuntu_kernel_flavor,
            "source_repo_url": source_repo_url,
            "apt_suite": kernel_info.apt_suite,
            "kernel_abi": kernel_abi,
            "kernel_source_ref": self.options.ubuntu_kernel_source_ref,
            "ubuntu_kernel_pocket": self.pocket.value,
        }
        emit.debug(f"Pull script template: {template_vars}")
        script = template.render(template_vars)
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
            kernel_version = kernel_version_from_debpkg_file(
                self._part_info.part_src_dir
            )
        else:
            kernel_version = kernel_version_from_source_tree(
                self._part_info.part_src_dir,
                flavor=self.options.ubuntu_kernel_flavor,
            )

        template_file = "kernel/ubuntu_kernel_get_build_commands.sh.j2"
        env = jinja2.Environment(
            loader=jinja2.PackageLoader("snapcraft", "templates"), autoescape=True
        )
        template = env.get_template(template_file)
        template_vars = {
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
            "has_ubuntu_kernel_defconfig": bool(self.options.ubuntu_kernel_defconfig),
            "has_ubuntu_kernel_image_target": bool(
                self.options.ubuntu_kernel_image_target
            ),
            "is_cross_compiling": self._part_info.is_cross_compiling,
            "kernel_abi": kernel_version.kernel_abi(),
            "kernel_version": kernel_version.full_version,
            # The package version can get quite long, so to keep jinja2
            # templates readable, it is substituted with a variable.
            "pkgfile_version_flavor": (
                f"{kernel_version.kernel_abi()}-{self.options.ubuntu_kernel_flavor}_"
                f"{kernel_version.full_version}_{self._part_info.target_arch}"
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
        emit.debug(f"Build script template: {template_vars}")
        script = template.render(template_vars)
        return [script]

    @override
    @classmethod
    def get_out_of_source_build(cls) -> bool:
        """Return whether the plugin performs out-of-source-tree builds."""
        return True
