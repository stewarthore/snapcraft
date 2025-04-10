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

"""The plugin for building Ubuntu Core image."""

import logging
import pathlib
from typing import Literal, Self, cast

import pydantic
from craft_parts import infos, plugins
from overrides import overrides

from snapcraft import errors

logger = logging.getLogger(__name__)


class UbuntuCoreImagePluginProperties(plugins.properties.PluginProperties, frozen=True):
    """The part properties used by the Ubuntu Core initrd plugin."""

    plugin: Literal["ubuntu-core-image"] = "ubuntu-core-image"
    ubuntu_core_image_type: Literal["efi", "fit", "custom"] = "efi"
    ubuntu_core_custom_image_type: str | None = None
    ubuntu_core_image_output: pathlib.Path | None = None
    ubuntu_core_image_parameters: list[str] | None = None

    # Validate so that release_name and source are mutually exclusive
    @pydantic.model_validator(mode="after")
    def validate_image_type(self) -> Self:
        """Enforce when image_type is 'custom' then a custom_image_type is given.

        Also validates that custom_image_type is empty when a non-custom image_type is
        given.
        """
        if (
            self.ubuntu_core_image_type == "custom"
            and not self.ubuntu_core_custom_image_type
        ):
            raise errors.SnapcraftError(
                "must provide `custom_image_type` when `image_type` is `custom`"
            )
        if (
            self.ubuntu_core_image_type != "custom"
            and self.ubuntu_core_custom_image_type
        ):
            raise errors.SnapcraftError(
                "must not provide `custom_image_type` when `image_type` is not `custom`"
            )

        return self


class UbuntuCoreImagePlugin(plugins.Plugin):
    """Plugin for the Ubuntu Core image build."""

    properties_class = UbuntuCoreImagePluginProperties

    def __init__(
        self, *, properties: plugins.PluginProperties, part_info: infos.PartInfo
    ) -> None:
        super().__init__(properties=properties, part_info=part_info)
        self.options = cast(UbuntuCoreImagePluginProperties, self._options)
        self.part_info = part_info
        if part_info.base not in ("core22", "core24"):
            raise errors.SnapcraftError("only core22 and core24 bases are supported")

    @overrides
    def get_build_snaps(self) -> set[str]:
        return {
            "ubuntu-image",
        }

    @overrides
    def get_build_packages(self) -> set[str]:
        return set()

    @overrides
    def get_build_environment(self) -> dict[str, str]:
        return dict()

    def _create_model_file(self) -> None:
        """Create the model file for the image build."""
        if self.options.ubuntu_core_image_type == "custom":
            # Create the model file for the custom image
            model_file = self.part_info.build_path / "model.yaml"
            with open(model_file, "w") as f:
                f.write("Hello Sailor!\n")

    @overrides
    def get_build_commands(self) -> list[str]:
        logger.info("Setting build commands...")
        self._create_model_file()

        return []

    @classmethod
    def get_out_of_source_build(cls) -> bool:
        """Return whether the plugin performs out-of-source-tree builds."""
        return True
