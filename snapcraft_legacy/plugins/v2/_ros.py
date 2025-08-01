# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright (C) 2020 Canonical Ltd
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

import abc
import os
import pathlib
import re
import subprocess
import sys
from typing import Dict, List, Set

import click
from catkin_pkg import packages as catkin_packages

from snapcraft_legacy.internal import errors
from snapcraft_legacy.internal.repo import Repo
from snapcraft_legacy.internal.repo.snaps import _get_parsed_snap
from snapcraft_legacy.plugins.v2 import PluginV2


class RosdepUnexpectedResultError(errors.SnapcraftError):
    fmt = (
        "Received unexpected result from rosdep when trying to resolve "
        "{dependency!r}:\n{output}"
    )

    def __init__(self, dependency, output):
        super().__init__(dependency=dependency, output=output)


def _parse_rosdep_resolve_dependencies(
    dependency_name: str, output: str
) -> Dict[str, Set[str]]:
    # The output of rosdep follows the pattern:
    #
    #    #apt
    #    package1
    #    package2
    #    #pip
    #    pip-package1
    #    pip-package2
    #
    # Split these out into a dict of dependency type -> dependencies.
    delimiters = re.compile(r"\n|\s")
    lines = delimiters.split(output)
    dependencies: Dict[str, Set[str]] = {}
    dependency_set = None
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            key = line.strip("# ")
            dependencies[key] = set()
            dependency_set = dependencies[key]
        elif line:
            if dependency_set is None:
                raise RosdepUnexpectedResultError(dependency_name, output)
            else:
                dependency_set.add(line)

    return dependencies


class RosPlugin(PluginV2):
    """Base class for ROS-related plugins. Not intended for use by end users."""

    def get_build_snaps(self) -> Set[str]:
        return (
            set(self.options.ros_build_snaps) if self.options.ros_build_snaps else set()
        )

    def get_build_packages(self) -> Set[str]:
        return {
            "python3-rosdep",
            "rospack-tools",
        }

    def get_build_environment(self) -> Dict[str, str]:
        return {
            "ROS_PYTHON_VERSION": "3",
        }

    @property
    def out_of_source_build(self):
        return True

    @abc.abstractmethod
    def _get_workspace_activation_commands(self) -> List[str]:
        """Return a list of commands source a ROS workspace.

        The commands returned will be run before doing anything else.
        They will be run in a single shell instance with the rest of
        the build step, so these commands can affect the commands that
        follow.

        snapcraftctl can be used in the script to call out to snapcraft
        specific functionality.
        """

    @abc.abstractmethod
    def _get_build_commands(self) -> List[str]:
        """Return a list of commands to run during the build step.

        The commands returned will be run after rosdep is used to install
        build dependencies, and before staging runtime dependencies.
        These commands are run in a single shell instance with the rest
        of the build step, so these commands can be affected by the commands
        preceding it, and can affect those that follow.

        snapcraftctl can be used in the script to call out to snapcraft
        specific functionality.
        """

    def _get_list_packages_commands(self) -> List[str]:
        cmd = list()

        # Clean up previously established list of packages in build snaps
        cmd.append('rm -f "${SNAPCRAFT_PART_INSTALL}/.installed_packages.txt"')
        cmd.append('rm -f "${SNAPCRAFT_PART_INSTALL}/.build_snaps.txt"')

        if self.options.ros_build_snaps:
            for ros_build_snap in self.options.ros_build_snaps:
                snap_name = _get_parsed_snap(ros_build_snap)[0]
                path = f"/snap/{snap_name}/current/opt/ros"
                cmd.extend(
                    [
                        # Retrieve the list of all ROS packages available in the build snap
                        f"if [ -d {path} ]; then",
                        f"ROS_PACKAGE_PATH={path} "
                        'rospack list-names | (xargs rosdep resolve --rosdistro "${ROS_DISTRO}" || echo "") | '
                        'awk "/#apt/{getline;print;}" >> "${SNAPCRAFT_PART_INSTALL}/.installed_packages.txt"',
                        "fi",
                        # Retrieve the list of all non-ROS packages available in the build snap
                        f'if [ -d "{path}/${{ROS_DISTRO}}/" ]; then',
                        f'rosdep keys --rosdistro "${{ROS_DISTRO}}" --from-paths "{path}/${{ROS_DISTRO}}" --ignore-packages-from-source '
                        '| (xargs rosdep resolve --rosdistro "${ROS_DISTRO}" || echo "") | grep -v "#" >> "${SNAPCRAFT_PART_INSTALL}"/.installed_packages.txt',
                        "fi",
                        f'if [ -d "{path}/snap/" ]; then',
                        f'rosdep keys --rosdistro "${{ROS_DISTRO}}" --from-paths "{path}/snap" --ignore-packages-from-source '
                        '| (xargs rosdep resolve --rosdistro "${ROS_DISTRO}" || echo "") | grep -v "#" >> "${SNAPCRAFT_PART_INSTALL}"/.installed_packages.txt',
                        "fi",
                    ]
                )
            cmd.append("")

        return cmd

    def _get_stage_runtime_dependencies_commands(self) -> List[str]:
        env = dict(LANG="C.UTF-8", LC_ALL="C.UTF-8")

        for key in [
            "PATH",
            "SNAP",
            "SNAP_ARCH",
            "SNAP_NAME",
            "SNAP_VERSION",
            "http_proxy",
            "https_proxy",
        ]:
            if key in os.environ:
                env[key] = os.environ[key]

        env_flags = [f"{key}={value}" for key, value in env.items()]
        return [
            " ".join(
                [
                    "env",
                    "-i",
                    *env_flags,
                    sys.executable,
                    "-I",
                    os.path.abspath(__file__),
                    "stage-runtime-dependencies",
                    "--part-src",
                    '"${SNAPCRAFT_PART_SRC_WORK}"',
                    "--part-install",
                    '"${SNAPCRAFT_PART_INSTALL}"',
                    "--ros-version",
                    '"${ROS_VERSION}"',
                    "--ros-distro",
                    '"${ROS_DISTRO}"',
                    "--target-arch",
                    '"${SNAPCRAFT_TARGET_ARCH}"',
                ]
            )
        ]

    def get_build_commands(self) -> List[str]:
        return (
            [
                "if [ ! -f /etc/ros/rosdep/sources.list.d/20-default.list ]; then",
                # Preserve http(s)_proxy env var in root for remote-build proxy since rosdep
                # doesn't support proxy
                # https://github.com/ros-infrastructure/rosdep/issues/271
                "sudo --preserve-env=http_proxy,https_proxy rosdep init; fi",
                'rosdep update --include-eol-distros --rosdistro "${ROS_DISTRO}"',
            ]
            # There are a number of unbound vars, disable flag
            # after saving current state to restore after.
            + [
                'state="$(set +o); set -$-"',
                "set +u",
                "",
            ]
            + self._get_workspace_activation_commands()
            # Restore saved state
            + ['eval "${state}"']
            + self._get_list_packages_commands()
            + [
                'rosdep install --default-yes --ignore-packages-from-source --from-paths "${SNAPCRAFT_PART_SRC_WORK}"',
            ]
            + [
                'state="$(set +o); set -$-"',
                "set +u",
                "",
            ]
            + self._get_workspace_activation_commands()
            + ['eval "${state}"']
            + self._get_build_commands()
            + self._get_stage_runtime_dependencies_commands()
        )


@click.group()
def plugin_cli():
    pass


def get_installed_dependencies(installed_packages_path: str) -> Set[str]:
    """Retrieve recursive apt dependencies of a given package list."""
    if os.path.isfile(installed_packages_path):
        try:
            with open(installed_packages_path, "r") as f:
                build_snap_packages = set(f.read().split())
                package_dependencies = set()
                for package in build_snap_packages:
                    cmd = [
                        "apt",
                        "depends",
                        "--recurse",
                        "--no-recommends",
                        "--no-suggests",
                        "--no-conflicts",
                        "--no-breaks",
                        "--no-replaces",
                        "--no-enhances",
                        f"{package}",
                    ]
                    click.echo(f"Running {cmd!r}")
                    try:
                        proc = subprocess.run(
                            cmd,
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            env=dict(PATH=os.environ["PATH"]),
                        )
                    except subprocess.CalledProcessError as error:
                        click.echo(f"failed to run {cmd!r}: {error.output}")
                    else:
                        apt_dependency_regex = re.compile(r"^\w.*$")
                        for line in proc.stdout.decode().strip().split("\n"):
                            if apt_dependency_regex.match(line):
                                package_dependencies.add(line)

                build_snap_packages.update(package_dependencies)
                click.echo(f"Will not fetch staged packages: {build_snap_packages!r}")
                return build_snap_packages
        except IOError:
            pass
    return set()


@plugin_cli.command()
@click.option("--part-src", envvar="SNAPCRAFT_PART_SRC_WORK", required=True)
@click.option("--part-install", envvar="SNAPCRAFT_PART_INSTALL", required=True)
@click.option("--ros-version", envvar="ROS_VERSION", required=True)
@click.option("--ros-distro", envvar="ROS_DISTRO", required=True)
@click.option("--target-arch", envvar="SNAPCRAFT_TARGET_ARCH", required=True)
def stage_runtime_dependencies(
    part_src: str,
    part_install: str,
    ros_version: str,
    ros_distro: str,
    target_arch: str,
):
    click.echo("Staging runtime dependencies...")
    # TODO: support python packages (only apt currently supported)
    apt_packages: Set[str] = set()

    installed_pkgs = catkin_packages.find_packages(part_install).values()
    for pkg in catkin_packages.find_packages(part_src).values():
        # Evaluate the conditions of all dependencies
        pkg.evaluate_conditions(
            {
                "ROS_VERSION": ros_version,
                "ROS_DISTRO": ros_distro,
                "ROS_PYTHON_VERSION": "3",
            }
        )
        # Retrieve only the 'exec_depends' which condition are true
        for dep in (
            exec_dep for exec_dep in pkg.exec_depends if exec_dep.evaluated_condition
        ):
            # No need to resolve this dependency if we know it's local
            if any(p for p in installed_pkgs if p.name == dep.name):
                continue

            cmd = ["rosdep", "resolve", dep.name, "--rosdistro", ros_distro]
            try:
                click.echo(f"Running {cmd!r}")
                proc = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=dict(PATH=os.environ["PATH"]),
                )
            except subprocess.CalledProcessError as error:
                click.echo(f"failed to run {cmd!r}: {error.stdout}, {error.stderr}")

            parsed = _parse_rosdep_resolve_dependencies(
                dep, proc.stdout.decode().strip()
            )
            apt_packages |= parsed.pop("apt", set())

            if parsed:  # still non-empty after removing apt packages
                click.echo(f"unhandled dependencies: {parsed!r}")

    build_snap_packages = get_installed_dependencies(
        part_install + "/.installed_packages.txt"
    )

    if apt_packages:
        package_names = sorted(apt_packages)
        install_path = pathlib.Path(part_install)
        stage_packages_path = install_path.parent / "stage_packages"

        click.echo(f"Fetching stage packages: {package_names!r}")
        fetched_stage_packages = Repo.fetch_stage_packages(
            package_names=package_names,
            base="core20",
            stage_packages_path=stage_packages_path,
            target_arch=target_arch,
            packages_filters=build_snap_packages,
        )

        click.echo(f"Unpacking stage packages: {fetched_stage_packages!r}")
        Repo.unpack_stage_packages(
            stage_packages_path=stage_packages_path, install_path=install_path
        )


if __name__ == "__main__":
    plugin_cli()
