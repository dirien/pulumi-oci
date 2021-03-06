# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'ManagementAgentPluginListArgs',
    'GetManagementAgentAvailableHistoriesFilterArgs',
    'GetManagementAgentImagesFilterArgs',
    'GetManagementAgentInstallKeysFilterArgs',
    'GetManagementAgentPluginsFilterArgs',
    'GetManagementAgentsFilterArgs',
]

@pulumi.input_type
class ManagementAgentPluginListArgs:
    def __init__(__self__, *,
                 plugin_display_name: Optional[pulumi.Input[str]] = None,
                 plugin_id: Optional[pulumi.Input[str]] = None,
                 plugin_name: Optional[pulumi.Input[str]] = None,
                 plugin_version: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] plugin_display_name: Management Agent Plugin Identifier, can be renamed
        :param pulumi.Input[str] plugin_id: Plugin Id
        :param pulumi.Input[str] plugin_name: Management Agent Plugin Name
        :param pulumi.Input[str] plugin_version: Plugin Version
        """
        if plugin_display_name is not None:
            pulumi.set(__self__, "plugin_display_name", plugin_display_name)
        if plugin_id is not None:
            pulumi.set(__self__, "plugin_id", plugin_id)
        if plugin_name is not None:
            pulumi.set(__self__, "plugin_name", plugin_name)
        if plugin_version is not None:
            pulumi.set(__self__, "plugin_version", plugin_version)

    @property
    @pulumi.getter(name="pluginDisplayName")
    def plugin_display_name(self) -> Optional[pulumi.Input[str]]:
        """
        Management Agent Plugin Identifier, can be renamed
        """
        return pulumi.get(self, "plugin_display_name")

    @plugin_display_name.setter
    def plugin_display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plugin_display_name", value)

    @property
    @pulumi.getter(name="pluginId")
    def plugin_id(self) -> Optional[pulumi.Input[str]]:
        """
        Plugin Id
        """
        return pulumi.get(self, "plugin_id")

    @plugin_id.setter
    def plugin_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plugin_id", value)

    @property
    @pulumi.getter(name="pluginName")
    def plugin_name(self) -> Optional[pulumi.Input[str]]:
        """
        Management Agent Plugin Name
        """
        return pulumi.get(self, "plugin_name")

    @plugin_name.setter
    def plugin_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plugin_name", value)

    @property
    @pulumi.getter(name="pluginVersion")
    def plugin_version(self) -> Optional[pulumi.Input[str]]:
        """
        Plugin Version
        """
        return pulumi.get(self, "plugin_version")

    @plugin_version.setter
    def plugin_version(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "plugin_version", value)


@pulumi.input_type
class GetManagementAgentAvailableHistoriesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetManagementAgentImagesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only resources that match the entire platform name given.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the entire platform name given.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetManagementAgentInstallKeysFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetManagementAgentPluginsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Management Agent Plugin Name
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Management Agent Plugin Name
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetManagementAgentsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


