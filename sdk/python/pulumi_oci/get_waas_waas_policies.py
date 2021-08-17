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
    'GetWaasWaasPoliciesResult',
    'AwaitableGetWaasWaasPoliciesResult',
    'get_waas_waas_policies',
]

@pulumi.output_type
class GetWaasWaasPoliciesResult:
    """
    A collection of values returned by GetWaasWaasPolicies.
    """
    def __init__(__self__, compartment_id=None, display_names=None, filters=None, id=None, ids=None, states=None, time_created_greater_than_or_equal_to=None, time_created_less_than=None, waas_policies=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_names and not isinstance(display_names, list):
            raise TypeError("Expected argument 'display_names' to be a list")
        pulumi.set(__self__, "display_names", display_names)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ids and not isinstance(ids, list):
            raise TypeError("Expected argument 'ids' to be a list")
        pulumi.set(__self__, "ids", ids)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)
        if time_created_greater_than_or_equal_to and not isinstance(time_created_greater_than_or_equal_to, str):
            raise TypeError("Expected argument 'time_created_greater_than_or_equal_to' to be a str")
        pulumi.set(__self__, "time_created_greater_than_or_equal_to", time_created_greater_than_or_equal_to)
        if time_created_less_than and not isinstance(time_created_less_than, str):
            raise TypeError("Expected argument 'time_created_less_than' to be a str")
        pulumi.set(__self__, "time_created_less_than", time_created_less_than)
        if waas_policies and not isinstance(waas_policies, list):
            raise TypeError("Expected argument 'waas_policies' to be a list")
        pulumi.set(__self__, "waas_policies", waas_policies)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayNames")
    def display_names(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "display_names")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetWaasWaasPoliciesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def ids(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "ids")

    @property
    @pulumi.getter
    def states(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "states")

    @property
    @pulumi.getter(name="timeCreatedGreaterThanOrEqualTo")
    def time_created_greater_than_or_equal_to(self) -> Optional[str]:
        return pulumi.get(self, "time_created_greater_than_or_equal_to")

    @property
    @pulumi.getter(name="timeCreatedLessThan")
    def time_created_less_than(self) -> Optional[str]:
        return pulumi.get(self, "time_created_less_than")

    @property
    @pulumi.getter(name="waasPolicies")
    def waas_policies(self) -> Sequence['outputs.GetWaasWaasPoliciesWaasPolicyResult']:
        """
        The list of waas_policies.
        """
        return pulumi.get(self, "waas_policies")


class AwaitableGetWaasWaasPoliciesResult(GetWaasWaasPoliciesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetWaasWaasPoliciesResult(
            compartment_id=self.compartment_id,
            display_names=self.display_names,
            filters=self.filters,
            id=self.id,
            ids=self.ids,
            states=self.states,
            time_created_greater_than_or_equal_to=self.time_created_greater_than_or_equal_to,
            time_created_less_than=self.time_created_less_than,
            waas_policies=self.waas_policies)


def get_waas_waas_policies(compartment_id: Optional[str] = None,
                           display_names: Optional[Sequence[str]] = None,
                           filters: Optional[Sequence[pulumi.InputType['GetWaasWaasPoliciesFilterArgs']]] = None,
                           ids: Optional[Sequence[str]] = None,
                           states: Optional[Sequence[str]] = None,
                           time_created_greater_than_or_equal_to: Optional[str] = None,
                           time_created_less_than: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetWaasWaasPoliciesResult:
    """
    This data source provides the list of Waas Policies in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

    Gets a list of WAAS policies.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_waas_policies = oci.get_waas_waas_policies(compartment_id=var["compartment_id"],
        display_names=var["waas_policy_display_names"],
        ids=var["waas_policy_ids"],
        states=var["waas_policy_states"],
        time_created_greater_than_or_equal_to=var["waas_policy_time_created_greater_than_or_equal_to"],
        time_created_less_than=var["waas_policy_time_created_less_than"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
    :param Sequence[str] display_names: Filter policies using a list of display names.
    :param Sequence[str] ids: Filter policies using a list of policy OCIDs.
    :param Sequence[str] states: Filter policies using a list of lifecycle states.
    :param str time_created_greater_than_or_equal_to: A filter that matches policies created on or after the specified date and time.
    :param str time_created_less_than: A filter that matches policies created before the specified date-time.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayNames'] = display_names
    __args__['filters'] = filters
    __args__['ids'] = ids
    __args__['states'] = states
    __args__['timeCreatedGreaterThanOrEqualTo'] = time_created_greater_than_or_equal_to
    __args__['timeCreatedLessThan'] = time_created_less_than
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getWaasWaasPolicies:GetWaasWaasPolicies', __args__, opts=opts, typ=GetWaasWaasPoliciesResult).value

    return AwaitableGetWaasWaasPoliciesResult(
        compartment_id=__ret__.compartment_id,
        display_names=__ret__.display_names,
        filters=__ret__.filters,
        id=__ret__.id,
        ids=__ret__.ids,
        states=__ret__.states,
        time_created_greater_than_or_equal_to=__ret__.time_created_greater_than_or_equal_to,
        time_created_less_than=__ret__.time_created_less_than,
        waas_policies=__ret__.waas_policies)