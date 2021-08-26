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
    def __init__(__self__, compartment_id=None, defined_tags=None, deployment_id=None, display_name=None, endpoint=None, freeform_tags=None, gateway_id=None, id=None, lifecycle_details=None, path_prefix=None, specification=None, state=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deployment_id and not isinstance(deployment_id, str):
            raise TypeError("Expected argument 'deployment_id' to be a str")
        pulumi.set(__self__, "deployment_id", deployment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if endpoint and not isinstance(endpoint, str):
            raise TypeError("Expected argument 'endpoint' to be a str")
        pulumi.set(__self__, "endpoint", endpoint)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if gateway_id and not isinstance(gateway_id, str):
            raise TypeError("Expected argument 'gateway_id' to be a str")
        pulumi.set(__self__, "gateway_id", gateway_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if path_prefix and not isinstance(path_prefix, str):
            raise TypeError("Expected argument 'path_prefix' to be a str")
        pulumi.set(__self__, "path_prefix", path_prefix)
        if specification and not isinstance(specification, dict):
            raise TypeError("Expected argument 'specification' to be a dict")
        pulumi.set(__self__, "specification", specification)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="deploymentId")
    def deployment_id(self) -> str:
        return pulumi.get(self, "deployment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def endpoint(self) -> str:
        """
        The endpoint to access this deployment on the gateway.
        """
        return pulumi.get(self, "endpoint")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="gatewayId")
    def gateway_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "gateway_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="pathPrefix")
    def path_prefix(self) -> str:
        """
        A path on which to deploy all routes contained in the API deployment specification. For more information, see [Deploying an API on an API Gateway by Creating an API Deployment](https://docs.cloud.oracle.com/iaas/Content/APIGateway/Tasks/apigatewaycreatingdeployment.htm).
        """
        return pulumi.get(self, "path_prefix")

    @property
    @pulumi.getter
    def specification(self) -> 'outputs.GetDeploymentSpecificationResult':
        """
        The logical configuration of the API exposed by a deployment.
        """
        return pulumi.get(self, "specification")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the deployment.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time this resource was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time this resource was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeploymentResult(GetDeploymentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            deployment_id=self.deployment_id,
            display_name=self.display_name,
            endpoint=self.endpoint,
            freeform_tags=self.freeform_tags,
            gateway_id=self.gateway_id,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            path_prefix=self.path_prefix,
            specification=self.specification,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_deployment(deployment_id: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentResult:
    """
    This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure API Gateway service.

    Gets a deployment by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployment = oci.apigateway.get_deployment(deployment_id=oci_apigateway_deployment["test_deployment"]["id"])
    ```


    :param str deployment_id: The ocid of the deployment.
    """
    __args__ = dict()
    __args__['deploymentId'] = deployment_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:apigateway/getDeployment:getDeployment', __args__, opts=opts, typ=GetDeploymentResult).value

    return AwaitableGetDeploymentResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        deployment_id=__ret__.deployment_id,
        display_name=__ret__.display_name,
        endpoint=__ret__.endpoint,
        freeform_tags=__ret__.freeform_tags,
        gateway_id=__ret__.gateway_id,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        path_prefix=__ret__.path_prefix,
        specification=__ret__.specification,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
