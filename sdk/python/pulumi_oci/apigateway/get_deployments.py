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
    'GetDeploymentsResult',
    'AwaitableGetDeploymentsResult',
    'get_deployments',
]

@pulumi.output_type
class GetDeploymentsResult:
    """
    A collection of values returned by getDeployments.
    """
    def __init__(__self__, compartment_id=None, deployment_collections=None, display_name=None, filters=None, gateway_id=None, id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if deployment_collections and not isinstance(deployment_collections, list):
            raise TypeError("Expected argument 'deployment_collections' to be a list")
        pulumi.set(__self__, "deployment_collections", deployment_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if gateway_id and not isinstance(gateway_id, str):
            raise TypeError("Expected argument 'gateway_id' to be a str")
        pulumi.set(__self__, "gateway_id", gateway_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="deploymentCollections")
    def deployment_collections(self) -> Sequence['outputs.GetDeploymentsDeploymentCollectionResult']:
        """
        The list of deployment_collection.
        """
        return pulumi.get(self, "deployment_collections")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDeploymentsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter(name="gatewayId")
    def gateway_id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "gateway_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the deployment.
        """
        return pulumi.get(self, "state")


class AwaitableGetDeploymentsResult(GetDeploymentsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentsResult(
            compartment_id=self.compartment_id,
            deployment_collections=self.deployment_collections,
            display_name=self.display_name,
            filters=self.filters,
            gateway_id=self.gateway_id,
            id=self.id,
            state=self.state)


def get_deployments(compartment_id: Optional[str] = None,
                    display_name: Optional[str] = None,
                    filters: Optional[Sequence[pulumi.InputType['GetDeploymentsFilterArgs']]] = None,
                    gateway_id: Optional[str] = None,
                    state: Optional[str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentsResult:
    """
    This data source provides the list of Deployments in Oracle Cloud Infrastructure API Gateway service.

    Returns a list of deployments.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployments = oci.apigateway.get_deployments(compartment_id=var["compartment_id"],
        display_name=var["deployment_display_name"],
        gateway_id=oci_apigateway_gateway["test_gateway"]["id"],
        state=var["deployment_state"])
    ```


    :param str compartment_id: The ocid of the compartment in which to list resources.
    :param str display_name: A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
    :param str gateway_id: Filter deployments by the gateway ocid.
    :param str state: A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['gatewayId'] = gateway_id
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:apigateway/getDeployments:getDeployments', __args__, opts=opts, typ=GetDeploymentsResult).value

    return AwaitableGetDeploymentsResult(
        compartment_id=__ret__.compartment_id,
        deployment_collections=__ret__.deployment_collections,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        gateway_id=__ret__.gateway_id,
        id=__ret__.id,
        state=__ret__.state)
