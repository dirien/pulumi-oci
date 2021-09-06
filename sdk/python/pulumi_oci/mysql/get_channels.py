# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetChannelsResult',
    'AwaitableGetChannelsResult',
    'get_channels',
]

@pulumi.output_type
class GetChannelsResult:
    """
    A collection of values returned by getChannels.
    """
    def __init__(__self__, channel_id=None, channels=None, compartment_id=None, db_system_id=None, display_name=None, filters=None, id=None, is_enabled=None, state=None):
        if channel_id and not isinstance(channel_id, str):
            raise TypeError("Expected argument 'channel_id' to be a str")
        pulumi.set(__self__, "channel_id", channel_id)
        if channels and not isinstance(channels, list):
            raise TypeError("Expected argument 'channels' to be a list")
        pulumi.set(__self__, "channels", channels)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if db_system_id and not isinstance(db_system_id, str):
            raise TypeError("Expected argument 'db_system_id' to be a str")
        pulumi.set(__self__, "db_system_id", db_system_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="channelId")
    def channel_id(self) -> Optional[str]:
        return pulumi.get(self, "channel_id")

    @property
    @pulumi.getter
    def channels(self) -> Sequence['outputs.GetChannelsChannelResult']:
        """
        The list of channels.
        """
        return pulumi.get(self, "channels")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> Optional[str]:
        """
        The OCID of the source DB System.
        """
        return pulumi.get(self, "db_system_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The user-friendly name for the Channel. It does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetChannelsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> Optional[bool]:
        """
        Whether the Channel has been enabled by the user.
        """
        return pulumi.get(self, "is_enabled")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The state of the Channel.
        """
        return pulumi.get(self, "state")


class AwaitableGetChannelsResult(GetChannelsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetChannelsResult(
            channel_id=self.channel_id,
            channels=self.channels,
            compartment_id=self.compartment_id,
            db_system_id=self.db_system_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            is_enabled=self.is_enabled,
            state=self.state)


def get_channels(channel_id: Optional[str] = None,
                 compartment_id: Optional[str] = None,
                 db_system_id: Optional[str] = None,
                 display_name: Optional[str] = None,
                 filters: Optional[Sequence[pulumi.InputType['GetChannelsFilterArgs']]] = None,
                 is_enabled: Optional[bool] = None,
                 state: Optional[str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetChannelsResult:
    """
    This data source provides the list of Channels in Oracle Cloud Infrastructure MySQL Database service.

    Lists all the Channels that match the specified filters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_channels = oci.mysql.get_channels(compartment_id=var["compartment_id"],
        channel_id=oci_mysql_channel["test_channel"]["id"],
        db_system_id=oci_database_db_system["test_db_system"]["id"],
        display_name=var["channel_display_name"],
        is_enabled=var["channel_is_enabled"],
        state=var["channel_state"])
    ```


    :param str channel_id: The OCID of the Channel.
    :param str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param str db_system_id: The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param str display_name: A filter to return only the resource matching the given display name exactly.
    :param bool is_enabled: If true, returns only Channels that are enabled. If false, returns only Channels that are disabled.
    :param str state: The LifecycleState of the Channel.
    """
    __args__ = dict()
    __args__['channelId'] = channel_id
    __args__['compartmentId'] = compartment_id
    __args__['dbSystemId'] = db_system_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['isEnabled'] = is_enabled
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:mysql/getChannels:getChannels', __args__, opts=opts, typ=GetChannelsResult).value

    return AwaitableGetChannelsResult(
        channel_id=__ret__.channel_id,
        channels=__ret__.channels,
        compartment_id=__ret__.compartment_id,
        db_system_id=__ret__.db_system_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        is_enabled=__ret__.is_enabled,
        state=__ret__.state)
