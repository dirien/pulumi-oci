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
    'GetManagementAgentInstallKeysResult',
    'AwaitableGetManagementAgentInstallKeysResult',
    'get_management_agent_install_keys',
]

@pulumi.output_type
class GetManagementAgentInstallKeysResult:
    """
    A collection of values returned by getManagementAgentInstallKeys.
    """
    def __init__(__self__, access_level=None, compartment_id=None, compartment_id_in_subtree=None, display_name=None, filters=None, id=None, management_agent_install_keys=None, state=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if management_agent_install_keys and not isinstance(management_agent_install_keys, list):
            raise TypeError("Expected argument 'management_agent_install_keys' to be a list")
        pulumi.set(__self__, "management_agent_install_keys", management_agent_install_keys)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[str]:
        return pulumi.get(self, "access_level")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        Management Agent Install Key Name
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagementAgentInstallKeysFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="managementAgentInstallKeys")
    def management_agent_install_keys(self) -> Sequence['outputs.GetManagementAgentInstallKeysManagementAgentInstallKeyResult']:
        """
        The list of management_agent_install_keys.
        """
        return pulumi.get(self, "management_agent_install_keys")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        Status of Key
        """
        return pulumi.get(self, "state")


class AwaitableGetManagementAgentInstallKeysResult(GetManagementAgentInstallKeysResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagementAgentInstallKeysResult(
            access_level=self.access_level,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            management_agent_install_keys=self.management_agent_install_keys,
            state=self.state)


def get_management_agent_install_keys(access_level: Optional[str] = None,
                                      compartment_id: Optional[str] = None,
                                      compartment_id_in_subtree: Optional[bool] = None,
                                      display_name: Optional[str] = None,
                                      filters: Optional[Sequence[pulumi.InputType['GetManagementAgentInstallKeysFilterArgs']]] = None,
                                      state: Optional[str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagementAgentInstallKeysResult:
    """
    This data source provides the list of Management Agent Install Keys in Oracle Cloud Infrastructure Management Agent service.

    Returns a list of Management Agent installed Keys.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_management_agent_install_keys = oci.managementagent.get_management_agent_install_keys(compartment_id=var["compartment_id"],
        access_level=var["management_agent_install_key_access_level"],
        compartment_id_in_subtree=var["management_agent_install_key_compartment_id_in_subtree"],
        display_name=var["management_agent_install_key_display_name"],
        state=var["management_agent_install_key_state"])
    ```


    :param str access_level: Value of this is always "ACCESSIBLE" and any other value is not supported.
    :param str compartment_id: The ID of the compartment from which the Management Agents to be listed.
    :param bool compartment_id_in_subtree: if set to true then it fetches install key for all compartments where user has access to else only on the compartment specified.
    :param str display_name: The display name for which the Key needs to be listed.
    :param str state: Filter to return only Management Agents in the particular lifecycle state.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:managementagent/getManagementAgentInstallKeys:getManagementAgentInstallKeys', __args__, opts=opts, typ=GetManagementAgentInstallKeysResult).value

    return AwaitableGetManagementAgentInstallKeysResult(
        access_level=__ret__.access_level,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        management_agent_install_keys=__ret__.management_agent_install_keys,
        state=__ret__.state)
