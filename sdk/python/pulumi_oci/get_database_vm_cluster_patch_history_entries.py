# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetDatabaseVmClusterPatchHistoryEntriesResult',
    'AwaitableGetDatabaseVmClusterPatchHistoryEntriesResult',
    'get_database_vm_cluster_patch_history_entries',
]

@pulumi.output_type
class GetDatabaseVmClusterPatchHistoryEntriesResult:
    """
    A collection of values returned by GetDatabaseVmClusterPatchHistoryEntries.
    """
    def __init__(__self__, filters=None, id=None, patch_history_entries=None, vm_cluster_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if patch_history_entries and not isinstance(patch_history_entries, list):
            raise TypeError("Expected argument 'patch_history_entries' to be a list")
        pulumi.set(__self__, "patch_history_entries", patch_history_entries)
        if vm_cluster_id and not isinstance(vm_cluster_id, str):
            raise TypeError("Expected argument 'vm_cluster_id' to be a str")
        pulumi.set(__self__, "vm_cluster_id", vm_cluster_id)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDatabaseVmClusterPatchHistoryEntriesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="patchHistoryEntries")
    def patch_history_entries(self) -> Sequence['outputs.GetDatabaseVmClusterPatchHistoryEntriesPatchHistoryEntryResult']:
        """
        The list of patch_history_entries.
        """
        return pulumi.get(self, "patch_history_entries")

    @property
    @pulumi.getter(name="vmClusterId")
    def vm_cluster_id(self) -> str:
        return pulumi.get(self, "vm_cluster_id")


class AwaitableGetDatabaseVmClusterPatchHistoryEntriesResult(GetDatabaseVmClusterPatchHistoryEntriesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDatabaseVmClusterPatchHistoryEntriesResult(
            filters=self.filters,
            id=self.id,
            patch_history_entries=self.patch_history_entries,
            vm_cluster_id=self.vm_cluster_id)


def get_database_vm_cluster_patch_history_entries(filters: Optional[Sequence[pulumi.InputType['GetDatabaseVmClusterPatchHistoryEntriesFilterArgs']]] = None,
                                                  vm_cluster_id: Optional[str] = None,
                                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDatabaseVmClusterPatchHistoryEntriesResult:
    """
    This data source provides the list of Vm Cluster Patch History Entries in Oracle Cloud Infrastructure Database service.

    Gets the history of the patch actions performed on the specified VM cluster in an Exadata Cloud@Customer system.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patch_history_entries = oci.get_database_vm_cluster_patch_history_entries(vm_cluster_id=oci_database_vm_cluster["test_vm_cluster"]["id"])
    ```


    :param str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['vmClusterId'] = vm_cluster_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getDatabaseVmClusterPatchHistoryEntries:GetDatabaseVmClusterPatchHistoryEntries', __args__, opts=opts, typ=GetDatabaseVmClusterPatchHistoryEntriesResult).value

    return AwaitableGetDatabaseVmClusterPatchHistoryEntriesResult(
        filters=__ret__.filters,
        id=__ret__.id,
        patch_history_entries=__ret__.patch_history_entries,
        vm_cluster_id=__ret__.vm_cluster_id)