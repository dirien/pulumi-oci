# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetDeploymentBackupResult',
    'AwaitableGetDeploymentBackupResult',
    'get_deployment_backup',
]

@pulumi.output_type
class GetDeploymentBackupResult:
    """
    A collection of values returned by getDeploymentBackup.
    """
    def __init__(__self__, backup_type=None, bucket=None, compartment_id=None, defined_tags=None, deployment_backup_id=None, deployment_id=None, display_name=None, freeform_tags=None, id=None, is_automatic=None, lifecycle_details=None, namespace=None, object=None, ogg_version=None, state=None, system_tags=None, time_created=None, time_of_backup=None, time_updated=None):
        if backup_type and not isinstance(backup_type, str):
            raise TypeError("Expected argument 'backup_type' to be a str")
        pulumi.set(__self__, "backup_type", backup_type)
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deployment_backup_id and not isinstance(deployment_backup_id, str):
            raise TypeError("Expected argument 'deployment_backup_id' to be a str")
        pulumi.set(__self__, "deployment_backup_id", deployment_backup_id)
        if deployment_id and not isinstance(deployment_id, str):
            raise TypeError("Expected argument 'deployment_id' to be a str")
        pulumi.set(__self__, "deployment_id", deployment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_automatic and not isinstance(is_automatic, bool):
            raise TypeError("Expected argument 'is_automatic' to be a bool")
        pulumi.set(__self__, "is_automatic", is_automatic)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if object and not isinstance(object, str):
            raise TypeError("Expected argument 'object' to be a str")
        pulumi.set(__self__, "object", object)
        if ogg_version and not isinstance(ogg_version, str):
            raise TypeError("Expected argument 'ogg_version' to be a str")
        pulumi.set(__self__, "ogg_version", ogg_version)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_of_backup and not isinstance(time_of_backup, str):
            raise TypeError("Expected argument 'time_of_backup' to be a str")
        pulumi.set(__self__, "time_of_backup", time_of_backup)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="backupType")
    def backup_type(self) -> str:
        """
        Possible Deployment backup types.
        """
        return pulumi.get(self, "backup_type")

    @property
    @pulumi.getter
    def bucket(self) -> str:
        """
        Name of the bucket where the object is to be uploaded in the object storage
        """
        return pulumi.get(self, "bucket")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        """
        return pulumi.get(self, "compartment_id")

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
        return pulumi.get(self, "deployment_backup_id")

    @property
    @pulumi.getter(name="deploymentId")
    def deployment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
        """
        return pulumi.get(self, "deployment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        An object's Display Name.
        """
        return pulumi.get(self, "display_name")

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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isAutomatic")
    def is_automatic(self) -> bool:
        """
        True if this object is automatically created
        """
        return pulumi.get(self, "is_automatic")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def namespace(self) -> str:
        """
        Name of namespace that serves as a container for all of your buckets
        """
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter
    def object(self) -> str:
        """
        Name of the object to be uploaded to object storage
        """
        return pulumi.get(self, "object")

    @property
    @pulumi.getter(name="oggVersion")
    def ogg_version(self) -> str:
        """
        Version of OGG
        """
        return pulumi.get(self, "ogg_version")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Possible lifecycle states.
        """
        return pulumi.get(self, "state")

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
    @pulumi.getter(name="timeOfBackup")
    def time_of_backup(self) -> str:
        """
        The time of the resource backup. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_of_backup")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeploymentBackupResult(GetDeploymentBackupResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentBackupResult(
            backup_type=self.backup_type,
            bucket=self.bucket,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            deployment_backup_id=self.deployment_backup_id,
            deployment_id=self.deployment_id,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_automatic=self.is_automatic,
            lifecycle_details=self.lifecycle_details,
            namespace=self.namespace,
            object=self.object,
            ogg_version=self.ogg_version,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_of_backup=self.time_of_backup,
            time_updated=self.time_updated)


def get_deployment_backup(deployment_backup_id: Optional[str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentBackupResult:
    """
    This data source provides details about a specific Deployment Backup resource in Oracle Cloud Infrastructure Golden Gate service.

    Retrieves a DeploymentBackup.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployment_backup = oci.goldengate.get_deployment_backup(deployment_backup_id=oci_golden_gate_deployment_backup["test_deployment_backup"]["id"])
    ```


    :param str deployment_backup_id: A unique DeploymentBackup identifier.
    """
    __args__ = dict()
    __args__['deploymentBackupId'] = deployment_backup_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:goldengate/getDeploymentBackup:getDeploymentBackup', __args__, opts=opts, typ=GetDeploymentBackupResult).value

    return AwaitableGetDeploymentBackupResult(
        backup_type=__ret__.backup_type,
        bucket=__ret__.bucket,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        deployment_backup_id=__ret__.deployment_backup_id,
        deployment_id=__ret__.deployment_id,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        is_automatic=__ret__.is_automatic,
        lifecycle_details=__ret__.lifecycle_details,
        namespace=__ret__.namespace,
        object=__ret__.object,
        ogg_version=__ret__.ogg_version,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_of_backup=__ret__.time_of_backup,
        time_updated=__ret__.time_updated)
