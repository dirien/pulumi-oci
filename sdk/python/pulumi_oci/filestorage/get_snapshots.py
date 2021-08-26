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
    'GetSnapshotsResult',
    'AwaitableGetSnapshotsResult',
    'get_snapshots',
]

@pulumi.output_type
class GetSnapshotsResult:
    """
    A collection of values returned by getSnapshots.
    """
    def __init__(__self__, file_system_id=None, filters=None, id=None, snapshots=None, state=None):
        if file_system_id and not isinstance(file_system_id, str):
            raise TypeError("Expected argument 'file_system_id' to be a str")
        pulumi.set(__self__, "file_system_id", file_system_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if snapshots and not isinstance(snapshots, list):
            raise TypeError("Expected argument 'snapshots' to be a list")
        pulumi.set(__self__, "snapshots", snapshots)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="fileSystemId")
    def file_system_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system from which the snapshot was created.
        """
        return pulumi.get(self, "file_system_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSnapshotsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def snapshots(self) -> Sequence['outputs.GetSnapshotsSnapshotResult']:
        """
        The list of snapshots.
        """
        return pulumi.get(self, "snapshots")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the snapshot.
        """
        return pulumi.get(self, "state")


class AwaitableGetSnapshotsResult(GetSnapshotsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSnapshotsResult(
            file_system_id=self.file_system_id,
            filters=self.filters,
            id=self.id,
            snapshots=self.snapshots,
            state=self.state)


def get_snapshots(file_system_id: Optional[str] = None,
                  filters: Optional[Sequence[pulumi.InputType['GetSnapshotsFilterArgs']]] = None,
                  id: Optional[str] = None,
                  state: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSnapshotsResult:
    """
    This data source provides the list of Snapshots in Oracle Cloud Infrastructure File Storage service.

    Lists snapshots of the specified file system.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_snapshots = oci.filestorage.get_snapshots(file_system_id=oci_file_storage_file_system["test_file_system"]["id"],
        id=var["snapshot_id"],
        state=var["snapshot_state"])
    ```


    :param str file_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
    :param str id: Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
    :param str state: Filter results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['fileSystemId'] = file_system_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:filestorage/getSnapshots:getSnapshots', __args__, opts=opts, typ=GetSnapshotsResult).value

    return AwaitableGetSnapshotsResult(
        file_system_id=__ret__.file_system_id,
        filters=__ret__.filters,
        id=__ret__.id,
        snapshots=__ret__.snapshots,
        state=__ret__.state)
