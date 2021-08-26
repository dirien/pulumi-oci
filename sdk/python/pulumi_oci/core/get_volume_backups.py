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
    'GetVolumeBackupsResult',
    'AwaitableGetVolumeBackupsResult',
    'get_volume_backups',
]

@pulumi.output_type
class GetVolumeBackupsResult:
    """
    A collection of values returned by getVolumeBackups.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, source_volume_backup_id=None, state=None, volume_backups=None, volume_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if source_volume_backup_id and not isinstance(source_volume_backup_id, str):
            raise TypeError("Expected argument 'source_volume_backup_id' to be a str")
        pulumi.set(__self__, "source_volume_backup_id", source_volume_backup_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if volume_backups and not isinstance(volume_backups, list):
            raise TypeError("Expected argument 'volume_backups' to be a list")
        pulumi.set(__self__, "volume_backups", volume_backups)
        if volume_id and not isinstance(volume_id, str):
            raise TypeError("Expected argument 'volume_id' to be a str")
        pulumi.set(__self__, "volume_id", volume_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the volume backup.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name for the volume backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetVolumeBackupsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="sourceVolumeBackupId")
    def source_volume_backup_id(self) -> Optional[str]:
        """
        The OCID of the source volume backup.
        """
        return pulumi.get(self, "source_volume_backup_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of a volume backup.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="volumeBackups")
    def volume_backups(self) -> Sequence['outputs.GetVolumeBackupsVolumeBackupResult']:
        """
        The list of volume_backups.
        """
        return pulumi.get(self, "volume_backups")

    @property
    @pulumi.getter(name="volumeId")
    def volume_id(self) -> Optional[str]:
        """
        The OCID of the volume.
        """
        return pulumi.get(self, "volume_id")


class AwaitableGetVolumeBackupsResult(GetVolumeBackupsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVolumeBackupsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            source_volume_backup_id=self.source_volume_backup_id,
            state=self.state,
            volume_backups=self.volume_backups,
            volume_id=self.volume_id)


def get_volume_backups(compartment_id: Optional[str] = None,
                       display_name: Optional[str] = None,
                       filters: Optional[Sequence[pulumi.InputType['GetVolumeBackupsFilterArgs']]] = None,
                       source_volume_backup_id: Optional[str] = None,
                       state: Optional[str] = None,
                       volume_id: Optional[str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVolumeBackupsResult:
    """
    This data source provides the list of Volume Backups in Oracle Cloud Infrastructure Core service.

    Lists the volume backups in the specified compartment. You can filter the results by volume.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_volume_backups = oci.core.get_volume_backups(compartment_id=var["compartment_id"],
        display_name=var["volume_backup_display_name"],
        source_volume_backup_id=oci_core_volume_backup["test_volume_backup"]["id"],
        state=var["volume_backup_state"],
        volume_id=oci_core_volume["test_volume"]["id"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str source_volume_backup_id: A filter to return only resources that originated from the given source volume backup.
    :param str state: A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
    :param str volume_id: The OCID of the volume.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['sourceVolumeBackupId'] = source_volume_backup_id
    __args__['state'] = state
    __args__['volumeId'] = volume_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getVolumeBackups:getVolumeBackups', __args__, opts=opts, typ=GetVolumeBackupsResult).value

    return AwaitableGetVolumeBackupsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        source_volume_backup_id=__ret__.source_volume_backup_id,
        state=__ret__.state,
        volume_backups=__ret__.volume_backups,
        volume_id=__ret__.volume_id)
