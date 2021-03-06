# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetCloudExadataInfrastructureResult',
    'AwaitableGetCloudExadataInfrastructureResult',
    'get_cloud_exadata_infrastructure',
]

@pulumi.output_type
class GetCloudExadataInfrastructureResult:
    """
    A collection of values returned by getCloudExadataInfrastructure.
    """
    def __init__(__self__, availability_domain=None, available_storage_size_in_gbs=None, cloud_exadata_infrastructure_id=None, compartment_id=None, compute_count=None, customer_contacts=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, last_maintenance_run_id=None, lifecycle_details=None, maintenance_window=None, next_maintenance_run_id=None, shape=None, state=None, storage_count=None, time_created=None, total_storage_size_in_gbs=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if available_storage_size_in_gbs and not isinstance(available_storage_size_in_gbs, int):
            raise TypeError("Expected argument 'available_storage_size_in_gbs' to be a int")
        pulumi.set(__self__, "available_storage_size_in_gbs", available_storage_size_in_gbs)
        if cloud_exadata_infrastructure_id and not isinstance(cloud_exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'cloud_exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "cloud_exadata_infrastructure_id", cloud_exadata_infrastructure_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_count and not isinstance(compute_count, int):
            raise TypeError("Expected argument 'compute_count' to be a int")
        pulumi.set(__self__, "compute_count", compute_count)
        if customer_contacts and not isinstance(customer_contacts, list):
            raise TypeError("Expected argument 'customer_contacts' to be a list")
        pulumi.set(__self__, "customer_contacts", customer_contacts)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if last_maintenance_run_id and not isinstance(last_maintenance_run_id, str):
            raise TypeError("Expected argument 'last_maintenance_run_id' to be a str")
        pulumi.set(__self__, "last_maintenance_run_id", last_maintenance_run_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if maintenance_window and not isinstance(maintenance_window, dict):
            raise TypeError("Expected argument 'maintenance_window' to be a dict")
        pulumi.set(__self__, "maintenance_window", maintenance_window)
        if next_maintenance_run_id and not isinstance(next_maintenance_run_id, str):
            raise TypeError("Expected argument 'next_maintenance_run_id' to be a str")
        pulumi.set(__self__, "next_maintenance_run_id", next_maintenance_run_id)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if storage_count and not isinstance(storage_count, int):
            raise TypeError("Expected argument 'storage_count' to be a int")
        pulumi.set(__self__, "storage_count", storage_count)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if total_storage_size_in_gbs and not isinstance(total_storage_size_in_gbs, int):
            raise TypeError("Expected argument 'total_storage_size_in_gbs' to be a int")
        pulumi.set(__self__, "total_storage_size_in_gbs", total_storage_size_in_gbs)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> str:
        """
        The name of the availability domain that the cloud Exadata infrastructure resource is located in.
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="availableStorageSizeInGbs")
    def available_storage_size_in_gbs(self) -> int:
        """
        The available storage can be allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
        """
        return pulumi.get(self, "available_storage_size_in_gbs")

    @property
    @pulumi.getter(name="cloudExadataInfrastructureId")
    def cloud_exadata_infrastructure_id(self) -> str:
        return pulumi.get(self, "cloud_exadata_infrastructure_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="computeCount")
    def compute_count(self) -> int:
        """
        The number of compute servers for the cloud Exadata infrastructure.
        """
        return pulumi.get(self, "compute_count")

    @property
    @pulumi.getter(name="customerContacts")
    def customer_contacts(self) -> Sequence['outputs.GetCloudExadataInfrastructureCustomerContactResult']:
        """
        The list of customer email addresses that receive information from Oracle about the specified Oracle Cloud Infrastructure Database service resource. Oracle uses these email addresses to send notifications about planned and unplanned software maintenance updates, information about system hardware, and other information needed by administrators. Up to 10 email addresses can be added to the customer contacts for a cloud Exadata infrastructure instance.
        """
        return pulumi.get(self, "customer_contacts")

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
        The user-friendly name for the cloud Exadata infrastructure resource. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lastMaintenanceRunId")
    def last_maintenance_run_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        """
        return pulumi.get(self, "last_maintenance_run_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="maintenanceWindow")
    def maintenance_window(self) -> 'outputs.GetCloudExadataInfrastructureMaintenanceWindowResult':
        """
        The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        """
        return pulumi.get(self, "maintenance_window")

    @property
    @pulumi.getter(name="nextMaintenanceRunId")
    def next_maintenance_run_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        """
        return pulumi.get(self, "next_maintenance_run_id")

    @property
    @pulumi.getter
    def shape(self) -> str:
        """
        The model name of the cloud Exadata infrastructure resource.
        """
        return pulumi.get(self, "shape")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current lifecycle state of the cloud Exadata infrastructure resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="storageCount")
    def storage_count(self) -> int:
        """
        The number of storage servers for the cloud Exadata infrastructure.
        """
        return pulumi.get(self, "storage_count")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the cloud Exadata infrastructure resource was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="totalStorageSizeInGbs")
    def total_storage_size_in_gbs(self) -> int:
        """
        The total storage allocated to the cloud Exadata infrastructure resource, in gigabytes (GB).
        """
        return pulumi.get(self, "total_storage_size_in_gbs")


class AwaitableGetCloudExadataInfrastructureResult(GetCloudExadataInfrastructureResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCloudExadataInfrastructureResult(
            availability_domain=self.availability_domain,
            available_storage_size_in_gbs=self.available_storage_size_in_gbs,
            cloud_exadata_infrastructure_id=self.cloud_exadata_infrastructure_id,
            compartment_id=self.compartment_id,
            compute_count=self.compute_count,
            customer_contacts=self.customer_contacts,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            last_maintenance_run_id=self.last_maintenance_run_id,
            lifecycle_details=self.lifecycle_details,
            maintenance_window=self.maintenance_window,
            next_maintenance_run_id=self.next_maintenance_run_id,
            shape=self.shape,
            state=self.state,
            storage_count=self.storage_count,
            time_created=self.time_created,
            total_storage_size_in_gbs=self.total_storage_size_in_gbs)


def get_cloud_exadata_infrastructure(cloud_exadata_infrastructure_id: Optional[str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCloudExadataInfrastructureResult:
    """
    This data source provides details about a specific Cloud Exadata Infrastructure resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified cloud Exadata infrastructure resource. Applies to Exadata Cloud Service instances only.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cloud_exadata_infrastructure = oci.database.get_cloud_exadata_infrastructure(cloud_exadata_infrastructure_id=oci_database_cloud_exadata_infrastructure["test_cloud_exadata_infrastructure"]["id"])
    ```


    :param str cloud_exadata_infrastructure_id: The cloud Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['cloudExadataInfrastructureId'] = cloud_exadata_infrastructure_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getCloudExadataInfrastructure:getCloudExadataInfrastructure', __args__, opts=opts, typ=GetCloudExadataInfrastructureResult).value

    return AwaitableGetCloudExadataInfrastructureResult(
        availability_domain=__ret__.availability_domain,
        available_storage_size_in_gbs=__ret__.available_storage_size_in_gbs,
        cloud_exadata_infrastructure_id=__ret__.cloud_exadata_infrastructure_id,
        compartment_id=__ret__.compartment_id,
        compute_count=__ret__.compute_count,
        customer_contacts=__ret__.customer_contacts,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        last_maintenance_run_id=__ret__.last_maintenance_run_id,
        lifecycle_details=__ret__.lifecycle_details,
        maintenance_window=__ret__.maintenance_window,
        next_maintenance_run_id=__ret__.next_maintenance_run_id,
        shape=__ret__.shape,
        state=__ret__.state,
        storage_count=__ret__.storage_count,
        time_created=__ret__.time_created,
        total_storage_size_in_gbs=__ret__.total_storage_size_in_gbs)
