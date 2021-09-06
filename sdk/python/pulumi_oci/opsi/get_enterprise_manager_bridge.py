# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetEnterpriseManagerBridgeResult',
    'AwaitableGetEnterpriseManagerBridgeResult',
    'get_enterprise_manager_bridge',
]

@pulumi.output_type
class GetEnterpriseManagerBridgeResult:
    """
    A collection of values returned by getEnterpriseManagerBridge.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, display_name=None, enterprise_manager_bridge_id=None, freeform_tags=None, id=None, lifecycle_details=None, object_storage_bucket_name=None, object_storage_bucket_status_details=None, object_storage_namespace_name=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if enterprise_manager_bridge_id and not isinstance(enterprise_manager_bridge_id, str):
            raise TypeError("Expected argument 'enterprise_manager_bridge_id' to be a str")
        pulumi.set(__self__, "enterprise_manager_bridge_id", enterprise_manager_bridge_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if object_storage_bucket_name and not isinstance(object_storage_bucket_name, str):
            raise TypeError("Expected argument 'object_storage_bucket_name' to be a str")
        pulumi.set(__self__, "object_storage_bucket_name", object_storage_bucket_name)
        if object_storage_bucket_status_details and not isinstance(object_storage_bucket_status_details, str):
            raise TypeError("Expected argument 'object_storage_bucket_status_details' to be a str")
        pulumi.set(__self__, "object_storage_bucket_status_details", object_storage_bucket_status_details)
        if object_storage_namespace_name and not isinstance(object_storage_namespace_name, str):
            raise TypeError("Expected argument 'object_storage_namespace_name' to be a str")
        pulumi.set(__self__, "object_storage_namespace_name", object_storage_namespace_name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment identifier of the Enterprise Manager bridge
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of Enterprise Manager Bridge
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        User-friedly name of Enterprise Manager Bridge that does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="enterpriseManagerBridgeId")
    def enterprise_manager_bridge_id(self) -> str:
        return pulumi.get(self, "enterprise_manager_bridge_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Enterprise Manager bridge identifier
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="objectStorageBucketName")
    def object_storage_bucket_name(self) -> str:
        """
        Object Storage Bucket Name
        """
        return pulumi.get(self, "object_storage_bucket_name")

    @property
    @pulumi.getter(name="objectStorageBucketStatusDetails")
    def object_storage_bucket_status_details(self) -> str:
        """
        A message describing status of the object storage bucket of this resource. For example, it can be used to provide actionable information about the permission and content validity of the bucket.
        """
        return pulumi.get(self, "object_storage_bucket_status_details")

    @property
    @pulumi.getter(name="objectStorageNamespaceName")
    def object_storage_namespace_name(self) -> str:
        """
        Object Storage Namespace Name
        """
        return pulumi.get(self, "object_storage_namespace_name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the Enterprise Manager bridge.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the Enterprise Manager bridge was first created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the Enterprise Manager bridge was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetEnterpriseManagerBridgeResult(GetEnterpriseManagerBridgeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetEnterpriseManagerBridgeResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            enterprise_manager_bridge_id=self.enterprise_manager_bridge_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            object_storage_bucket_name=self.object_storage_bucket_name,
            object_storage_bucket_status_details=self.object_storage_bucket_status_details,
            object_storage_namespace_name=self.object_storage_namespace_name,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_enterprise_manager_bridge(enterprise_manager_bridge_id: Optional[str] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetEnterpriseManagerBridgeResult:
    """
    This data source provides details about a specific Enterprise Manager Bridge resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of an Operations Insights Enterprise Manager bridge.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_enterprise_manager_bridge = oci.opsi.get_enterprise_manager_bridge(enterprise_manager_bridge_id=oci_opsi_enterprise_manager_bridge["test_enterprise_manager_bridge"]["id"])
    ```


    :param str enterprise_manager_bridge_id: Unique Enterprise Manager bridge identifier
    """
    __args__ = dict()
    __args__['enterpriseManagerBridgeId'] = enterprise_manager_bridge_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:opsi/getEnterpriseManagerBridge:getEnterpriseManagerBridge', __args__, opts=opts, typ=GetEnterpriseManagerBridgeResult).value

    return AwaitableGetEnterpriseManagerBridgeResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        display_name=__ret__.display_name,
        enterprise_manager_bridge_id=__ret__.enterprise_manager_bridge_id,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        object_storage_bucket_name=__ret__.object_storage_bucket_name,
        object_storage_bucket_status_details=__ret__.object_storage_bucket_status_details,
        object_storage_namespace_name=__ret__.object_storage_namespace_name,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
