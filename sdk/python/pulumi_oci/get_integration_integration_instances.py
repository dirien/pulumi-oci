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
    'GetIntegrationIntegrationInstancesResult',
    'AwaitableGetIntegrationIntegrationInstancesResult',
    'get_integration_integration_instances',
]

@pulumi.output_type
class GetIntegrationIntegrationInstancesResult:
    """
    A collection of values returned by GetIntegrationIntegrationInstances.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, integration_instances=None, state=None):
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
        if integration_instances and not isinstance(integration_instances, list):
            raise TypeError("Expected argument 'integration_instances' to be a list")
        pulumi.set(__self__, "integration_instances", integration_instances)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        Integration Instance Identifier, can be renamed.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetIntegrationIntegrationInstancesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="integrationInstances")
    def integration_instances(self) -> Sequence['outputs.GetIntegrationIntegrationInstancesIntegrationInstanceResult']:
        """
        The list of integration_instances.
        """
        return pulumi.get(self, "integration_instances")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the integration instance.
        """
        return pulumi.get(self, "state")


class AwaitableGetIntegrationIntegrationInstancesResult(GetIntegrationIntegrationInstancesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIntegrationIntegrationInstancesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            integration_instances=self.integration_instances,
            state=self.state)


def get_integration_integration_instances(compartment_id: Optional[str] = None,
                                          display_name: Optional[str] = None,
                                          filters: Optional[Sequence[pulumi.InputType['GetIntegrationIntegrationInstancesFilterArgs']]] = None,
                                          state: Optional[str] = None,
                                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIntegrationIntegrationInstancesResult:
    """
    This data source provides the list of Integration Instances in Oracle Cloud Infrastructure Integration service.

    Returns a list of Integration Instances.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_integration_instances = oci.get_integration_integration_instances(compartment_id=var["compartment_id"],
        display_name=var["integration_instance_display_name"],
        state=var["integration_instance_state"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
    :param str state: Life cycle state to query on.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getIntegrationIntegrationInstances:GetIntegrationIntegrationInstances', __args__, opts=opts, typ=GetIntegrationIntegrationInstancesResult).value

    return AwaitableGetIntegrationIntegrationInstancesResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        integration_instances=__ret__.integration_instances,
        state=__ret__.state)