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
    'GetDeploymentResult',
    'AwaitableGetDeploymentResult',
    'get_deployment',
]

@pulumi.output_type
class GetDeploymentResult:
    """
    A collection of values returned by getDeployment.
    """
    def __init__(__self__, compartment_id=None, cpu_core_count=None, defined_tags=None, deployment_backup_id=None, deployment_id=None, deployment_type=None, deployment_url=None, description=None, display_name=None, fqdn=None, freeform_tags=None, id=None, is_auto_scaling_enabled=None, is_healthy=None, is_latest_version=None, is_public=None, license_model=None, lifecycle_details=None, nsg_ids=None, ogg_data=None, private_ip_address=None, public_ip_address=None, state=None, subnet_id=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if cpu_core_count and not isinstance(cpu_core_count, int):
            raise TypeError("Expected argument 'cpu_core_count' to be a int")
        pulumi.set(__self__, "cpu_core_count", cpu_core_count)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deployment_backup_id and not isinstance(deployment_backup_id, str):
            raise TypeError("Expected argument 'deployment_backup_id' to be a str")
        pulumi.set(__self__, "deployment_backup_id", deployment_backup_id)
        if deployment_id and not isinstance(deployment_id, str):
            raise TypeError("Expected argument 'deployment_id' to be a str")
        pulumi.set(__self__, "deployment_id", deployment_id)
        if deployment_type and not isinstance(deployment_type, str):
            raise TypeError("Expected argument 'deployment_type' to be a str")
        pulumi.set(__self__, "deployment_type", deployment_type)
        if deployment_url and not isinstance(deployment_url, str):
            raise TypeError("Expected argument 'deployment_url' to be a str")
        pulumi.set(__self__, "deployment_url", deployment_url)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if fqdn and not isinstance(fqdn, str):
            raise TypeError("Expected argument 'fqdn' to be a str")
        pulumi.set(__self__, "fqdn", fqdn)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_auto_scaling_enabled and not isinstance(is_auto_scaling_enabled, bool):
            raise TypeError("Expected argument 'is_auto_scaling_enabled' to be a bool")
        pulumi.set(__self__, "is_auto_scaling_enabled", is_auto_scaling_enabled)
        if is_healthy and not isinstance(is_healthy, bool):
            raise TypeError("Expected argument 'is_healthy' to be a bool")
        pulumi.set(__self__, "is_healthy", is_healthy)
        if is_latest_version and not isinstance(is_latest_version, bool):
            raise TypeError("Expected argument 'is_latest_version' to be a bool")
        pulumi.set(__self__, "is_latest_version", is_latest_version)
        if is_public and not isinstance(is_public, bool):
            raise TypeError("Expected argument 'is_public' to be a bool")
        pulumi.set(__self__, "is_public", is_public)
        if license_model and not isinstance(license_model, str):
            raise TypeError("Expected argument 'license_model' to be a str")
        pulumi.set(__self__, "license_model", license_model)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if nsg_ids and not isinstance(nsg_ids, list):
            raise TypeError("Expected argument 'nsg_ids' to be a list")
        pulumi.set(__self__, "nsg_ids", nsg_ids)
        if ogg_data and not isinstance(ogg_data, dict):
            raise TypeError("Expected argument 'ogg_data' to be a dict")
        pulumi.set(__self__, "ogg_data", ogg_data)
        if private_ip_address and not isinstance(private_ip_address, str):
            raise TypeError("Expected argument 'private_ip_address' to be a str")
        pulumi.set(__self__, "private_ip_address", private_ip_address)
        if public_ip_address and not isinstance(public_ip_address, str):
            raise TypeError("Expected argument 'public_ip_address' to be a str")
        pulumi.set(__self__, "public_ip_address", public_ip_address)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subnet_id and not isinstance(subnet_id, str):
            raise TypeError("Expected argument 'subnet_id' to be a str")
        pulumi.set(__self__, "subnet_id", subnet_id)
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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="cpuCoreCount")
    def cpu_core_count(self) -> int:
        """
        The Minimum number of OCPUs to be made available for this Deployment.
        """
        return pulumi.get(self, "cpu_core_count")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="deploymentBackupId")
    def deployment_backup_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
        """
        return pulumi.get(self, "deployment_backup_id")

    @property
    @pulumi.getter(name="deploymentId")
    def deployment_id(self) -> str:
        return pulumi.get(self, "deployment_id")

    @property
    @pulumi.getter(name="deploymentType")
    def deployment_type(self) -> str:
        """
        The deployment type.
        """
        return pulumi.get(self, "deployment_type")

    @property
    @pulumi.getter(name="deploymentUrl")
    def deployment_url(self) -> str:
        """
        The URL of a resource.
        """
        return pulumi.get(self, "deployment_url")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Metadata about this specific object.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        An object's Display Name.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def fqdn(self) -> str:
        """
        A three-label Fully Qualified Domain Name (FQDN) for a resource.
        """
        return pulumi.get(self, "fqdn")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isAutoScalingEnabled")
    def is_auto_scaling_enabled(self) -> bool:
        """
        Indicates if auto scaling is enabled for the Deployment's CPU core count.
        """
        return pulumi.get(self, "is_auto_scaling_enabled")

    @property
    @pulumi.getter(name="isHealthy")
    def is_healthy(self) -> bool:
        """
        True if all of the aggregate resources are working correctly.
        """
        return pulumi.get(self, "is_healthy")

    @property
    @pulumi.getter(name="isLatestVersion")
    def is_latest_version(self) -> bool:
        """
        Indicates if the resource is the the latest available version.
        """
        return pulumi.get(self, "is_latest_version")

    @property
    @pulumi.getter(name="isPublic")
    def is_public(self) -> bool:
        """
        True if this object is publicly available.
        """
        return pulumi.get(self, "is_public")

    @property
    @pulumi.getter(name="licenseModel")
    def license_model(self) -> str:
        """
        The Oracle license model that applies to a Deployment.
        """
        return pulumi.get(self, "license_model")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="nsgIds")
    def nsg_ids(self) -> Sequence[str]:
        """
        An array of [Network Security Group](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/networksecuritygroups.htm) OCIDs used to define network access for a deployment.
        """
        return pulumi.get(self, "nsg_ids")

    @property
    @pulumi.getter(name="oggData")
    def ogg_data(self) -> 'outputs.GetDeploymentOggDataResult':
        """
        Deployment Data for an OggDeployment
        """
        return pulumi.get(self, "ogg_data")

    @property
    @pulumi.getter(name="privateIpAddress")
    def private_ip_address(self) -> str:
        """
        The private IP address in the customer's VCN representing the access point for the associated endpoint service in the GoldenGate service VCN.
        """
        return pulumi.get(self, "private_ip_address")

    @property
    @pulumi.getter(name="publicIpAddress")
    def public_ip_address(self) -> str:
        """
        The public IP address representing the access point for the Deployment.
        """
        return pulumi.get(self, "public_ip_address")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Possible lifecycle states.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet being referenced.
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeploymentResult(GetDeploymentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentResult(
            compartment_id=self.compartment_id,
            cpu_core_count=self.cpu_core_count,
            defined_tags=self.defined_tags,
            deployment_backup_id=self.deployment_backup_id,
            deployment_id=self.deployment_id,
            deployment_type=self.deployment_type,
            deployment_url=self.deployment_url,
            description=self.description,
            display_name=self.display_name,
            fqdn=self.fqdn,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_auto_scaling_enabled=self.is_auto_scaling_enabled,
            is_healthy=self.is_healthy,
            is_latest_version=self.is_latest_version,
            is_public=self.is_public,
            license_model=self.license_model,
            lifecycle_details=self.lifecycle_details,
            nsg_ids=self.nsg_ids,
            ogg_data=self.ogg_data,
            private_ip_address=self.private_ip_address,
            public_ip_address=self.public_ip_address,
            state=self.state,
            subnet_id=self.subnet_id,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_deployment(deployment_id: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentResult:
    """
    This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure Golden Gate service.

    Retrieves a deployment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployment = oci.goldengate.get_deployment(deployment_id=oci_golden_gate_deployment["test_deployment"]["id"])
    ```


    :param str deployment_id: A unique Deployment identifier.
    """
    __args__ = dict()
    __args__['deploymentId'] = deployment_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:goldengate/getDeployment:getDeployment', __args__, opts=opts, typ=GetDeploymentResult).value

    return AwaitableGetDeploymentResult(
        compartment_id=__ret__.compartment_id,
        cpu_core_count=__ret__.cpu_core_count,
        defined_tags=__ret__.defined_tags,
        deployment_backup_id=__ret__.deployment_backup_id,
        deployment_id=__ret__.deployment_id,
        deployment_type=__ret__.deployment_type,
        deployment_url=__ret__.deployment_url,
        description=__ret__.description,
        display_name=__ret__.display_name,
        fqdn=__ret__.fqdn,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        is_auto_scaling_enabled=__ret__.is_auto_scaling_enabled,
        is_healthy=__ret__.is_healthy,
        is_latest_version=__ret__.is_latest_version,
        is_public=__ret__.is_public,
        license_model=__ret__.license_model,
        lifecycle_details=__ret__.lifecycle_details,
        nsg_ids=__ret__.nsg_ids,
        ogg_data=__ret__.ogg_data,
        private_ip_address=__ret__.private_ip_address,
        public_ip_address=__ret__.public_ip_address,
        state=__ret__.state,
        subnet_id=__ret__.subnet_id,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
