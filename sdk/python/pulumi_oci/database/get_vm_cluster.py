# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetVmClusterResult',
    'AwaitableGetVmClusterResult',
    'get_vm_cluster',
]

@pulumi.output_type
class GetVmClusterResult:
    """
    A collection of values returned by getVmCluster.
    """
    def __init__(__self__, compartment_id=None, cpu_core_count=None, cpus_enabled=None, data_storage_size_in_tbs=None, db_node_storage_size_in_gbs=None, defined_tags=None, display_name=None, exadata_infrastructure_id=None, freeform_tags=None, gi_version=None, id=None, is_local_backup_enabled=None, is_sparse_diskgroup_enabled=None, last_patch_history_entry_id=None, license_model=None, lifecycle_details=None, memory_size_in_gbs=None, shape=None, ssh_public_keys=None, state=None, system_version=None, time_created=None, time_zone=None, vm_cluster_id=None, vm_cluster_network_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if cpu_core_count and not isinstance(cpu_core_count, int):
            raise TypeError("Expected argument 'cpu_core_count' to be a int")
        pulumi.set(__self__, "cpu_core_count", cpu_core_count)
        if cpus_enabled and not isinstance(cpus_enabled, int):
            raise TypeError("Expected argument 'cpus_enabled' to be a int")
        pulumi.set(__self__, "cpus_enabled", cpus_enabled)
        if data_storage_size_in_tbs and not isinstance(data_storage_size_in_tbs, float):
            raise TypeError("Expected argument 'data_storage_size_in_tbs' to be a float")
        pulumi.set(__self__, "data_storage_size_in_tbs", data_storage_size_in_tbs)
        if db_node_storage_size_in_gbs and not isinstance(db_node_storage_size_in_gbs, int):
            raise TypeError("Expected argument 'db_node_storage_size_in_gbs' to be a int")
        pulumi.set(__self__, "db_node_storage_size_in_gbs", db_node_storage_size_in_gbs)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if exadata_infrastructure_id and not isinstance(exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "exadata_infrastructure_id", exadata_infrastructure_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if gi_version and not isinstance(gi_version, str):
            raise TypeError("Expected argument 'gi_version' to be a str")
        pulumi.set(__self__, "gi_version", gi_version)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_local_backup_enabled and not isinstance(is_local_backup_enabled, bool):
            raise TypeError("Expected argument 'is_local_backup_enabled' to be a bool")
        pulumi.set(__self__, "is_local_backup_enabled", is_local_backup_enabled)
        if is_sparse_diskgroup_enabled and not isinstance(is_sparse_diskgroup_enabled, bool):
            raise TypeError("Expected argument 'is_sparse_diskgroup_enabled' to be a bool")
        pulumi.set(__self__, "is_sparse_diskgroup_enabled", is_sparse_diskgroup_enabled)
        if last_patch_history_entry_id and not isinstance(last_patch_history_entry_id, str):
            raise TypeError("Expected argument 'last_patch_history_entry_id' to be a str")
        pulumi.set(__self__, "last_patch_history_entry_id", last_patch_history_entry_id)
        if license_model and not isinstance(license_model, str):
            raise TypeError("Expected argument 'license_model' to be a str")
        pulumi.set(__self__, "license_model", license_model)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if memory_size_in_gbs and not isinstance(memory_size_in_gbs, int):
            raise TypeError("Expected argument 'memory_size_in_gbs' to be a int")
        pulumi.set(__self__, "memory_size_in_gbs", memory_size_in_gbs)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if ssh_public_keys and not isinstance(ssh_public_keys, list):
            raise TypeError("Expected argument 'ssh_public_keys' to be a list")
        pulumi.set(__self__, "ssh_public_keys", ssh_public_keys)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_version and not isinstance(system_version, str):
            raise TypeError("Expected argument 'system_version' to be a str")
        pulumi.set(__self__, "system_version", system_version)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_zone and not isinstance(time_zone, str):
            raise TypeError("Expected argument 'time_zone' to be a str")
        pulumi.set(__self__, "time_zone", time_zone)
        if vm_cluster_id and not isinstance(vm_cluster_id, str):
            raise TypeError("Expected argument 'vm_cluster_id' to be a str")
        pulumi.set(__self__, "vm_cluster_id", vm_cluster_id)
        if vm_cluster_network_id and not isinstance(vm_cluster_network_id, str):
            raise TypeError("Expected argument 'vm_cluster_network_id' to be a str")
        pulumi.set(__self__, "vm_cluster_network_id", vm_cluster_network_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="cpuCoreCount")
    def cpu_core_count(self) -> int:
        return pulumi.get(self, "cpu_core_count")

    @property
    @pulumi.getter(name="cpusEnabled")
    def cpus_enabled(self) -> int:
        """
        The number of enabled CPU cores.
        """
        return pulumi.get(self, "cpus_enabled")

    @property
    @pulumi.getter(name="dataStorageSizeInTbs")
    def data_storage_size_in_tbs(self) -> float:
        """
        Size, in terabytes, of the DATA disk group.
        """
        return pulumi.get(self, "data_storage_size_in_tbs")

    @property
    @pulumi.getter(name="dbNodeStorageSizeInGbs")
    def db_node_storage_size_in_gbs(self) -> int:
        """
        The local node storage allocated in GBs.
        """
        return pulumi.get(self, "db_node_storage_size_in_gbs")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="exadataInfrastructureId")
    def exadata_infrastructure_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        """
        return pulumi.get(self, "exadata_infrastructure_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="giVersion")
    def gi_version(self) -> str:
        """
        The Oracle Grid Infrastructure software version for the VM cluster.
        """
        return pulumi.get(self, "gi_version")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isLocalBackupEnabled")
    def is_local_backup_enabled(self) -> bool:
        """
        If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
        """
        return pulumi.get(self, "is_local_backup_enabled")

    @property
    @pulumi.getter(name="isSparseDiskgroupEnabled")
    def is_sparse_diskgroup_enabled(self) -> bool:
        """
        If true, sparse disk group is configured for the VM cluster. If false, sparse disk group is not created.
        """
        return pulumi.get(self, "is_sparse_diskgroup_enabled")

    @property
    @pulumi.getter(name="lastPatchHistoryEntryId")
    def last_patch_history_entry_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
        """
        return pulumi.get(self, "last_patch_history_entry_id")

    @property
    @pulumi.getter(name="licenseModel")
    def license_model(self) -> str:
        """
        The Oracle license model that applies to the VM cluster. The default is LICENSE_INCLUDED.
        """
        return pulumi.get(self, "license_model")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="memorySizeInGbs")
    def memory_size_in_gbs(self) -> int:
        """
        The memory allocated in GBs.
        """
        return pulumi.get(self, "memory_size_in_gbs")

    @property
    @pulumi.getter
    def shape(self) -> str:
        """
        The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
        """
        return pulumi.get(self, "shape")

    @property
    @pulumi.getter(name="sshPublicKeys")
    def ssh_public_keys(self) -> Sequence[str]:
        """
        The public key portion of one or more key pairs used for SSH access to the VM cluster.
        """
        return pulumi.get(self, "ssh_public_keys")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the VM cluster.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemVersion")
    def system_version(self) -> str:
        """
        Operating system version of the image.
        """
        return pulumi.get(self, "system_version")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time that the VM cluster was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeZone")
    def time_zone(self) -> str:
        """
        The time zone of the Exadata infrastructure. For details, see [Exadata Infrastructure Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        """
        return pulumi.get(self, "time_zone")

    @property
    @pulumi.getter(name="vmClusterId")
    def vm_cluster_id(self) -> str:
        return pulumi.get(self, "vm_cluster_id")

    @property
    @pulumi.getter(name="vmClusterNetworkId")
    def vm_cluster_network_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
        """
        return pulumi.get(self, "vm_cluster_network_id")


class AwaitableGetVmClusterResult(GetVmClusterResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVmClusterResult(
            compartment_id=self.compartment_id,
            cpu_core_count=self.cpu_core_count,
            cpus_enabled=self.cpus_enabled,
            data_storage_size_in_tbs=self.data_storage_size_in_tbs,
            db_node_storage_size_in_gbs=self.db_node_storage_size_in_gbs,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            exadata_infrastructure_id=self.exadata_infrastructure_id,
            freeform_tags=self.freeform_tags,
            gi_version=self.gi_version,
            id=self.id,
            is_local_backup_enabled=self.is_local_backup_enabled,
            is_sparse_diskgroup_enabled=self.is_sparse_diskgroup_enabled,
            last_patch_history_entry_id=self.last_patch_history_entry_id,
            license_model=self.license_model,
            lifecycle_details=self.lifecycle_details,
            memory_size_in_gbs=self.memory_size_in_gbs,
            shape=self.shape,
            ssh_public_keys=self.ssh_public_keys,
            state=self.state,
            system_version=self.system_version,
            time_created=self.time_created,
            time_zone=self.time_zone,
            vm_cluster_id=self.vm_cluster_id,
            vm_cluster_network_id=self.vm_cluster_network_id)


def get_vm_cluster(vm_cluster_id: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVmClusterResult:
    """
    This data source provides details about a specific Vm Cluster resource in Oracle Cloud Infrastructure Database service.

    Gets information about the VM cluster. Applies to Exadata Cloud@Customer instances only.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster = oci.database.get_vm_cluster(vm_cluster_id=oci_database_vm_cluster["test_vm_cluster"]["id"])
    ```


    :param str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['vmClusterId'] = vm_cluster_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getVmCluster:getVmCluster', __args__, opts=opts, typ=GetVmClusterResult).value

    return AwaitableGetVmClusterResult(
        compartment_id=__ret__.compartment_id,
        cpu_core_count=__ret__.cpu_core_count,
        cpus_enabled=__ret__.cpus_enabled,
        data_storage_size_in_tbs=__ret__.data_storage_size_in_tbs,
        db_node_storage_size_in_gbs=__ret__.db_node_storage_size_in_gbs,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        exadata_infrastructure_id=__ret__.exadata_infrastructure_id,
        freeform_tags=__ret__.freeform_tags,
        gi_version=__ret__.gi_version,
        id=__ret__.id,
        is_local_backup_enabled=__ret__.is_local_backup_enabled,
        is_sparse_diskgroup_enabled=__ret__.is_sparse_diskgroup_enabled,
        last_patch_history_entry_id=__ret__.last_patch_history_entry_id,
        license_model=__ret__.license_model,
        lifecycle_details=__ret__.lifecycle_details,
        memory_size_in_gbs=__ret__.memory_size_in_gbs,
        shape=__ret__.shape,
        ssh_public_keys=__ret__.ssh_public_keys,
        state=__ret__.state,
        system_version=__ret__.system_version,
        time_created=__ret__.time_created,
        time_zone=__ret__.time_zone,
        vm_cluster_id=__ret__.vm_cluster_id,
        vm_cluster_network_id=__ret__.vm_cluster_network_id)
