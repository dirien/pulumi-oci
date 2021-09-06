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
    'GetAgentsResult',
    'AwaitableGetAgentsResult',
    'get_agents',
]

@pulumi.output_type
class GetAgentsResult:
    """
    A collection of values returned by getAgents.
    """
    def __init__(__self__, agent_collections=None, compartment_id=None, display_name=None, filters=None, id=None, state=None):
        if agent_collections and not isinstance(agent_collections, list):
            raise TypeError("Expected argument 'agent_collections' to be a list")
        pulumi.set(__self__, "agent_collections", agent_collections)
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
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="agentCollections")
    def agent_collections(self) -> Sequence['outputs.GetAgentsAgentCollectionResult']:
        """
        The list of agent_collection.
        """
        return pulumi.get(self, "agent_collections")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        OCID of the compartment
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        ODMS Agent name
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAgentsFilterResult']]:
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
    def state(self) -> Optional[str]:
        """
        The current state of the ODMS On Prem Agent.
        """
        return pulumi.get(self, "state")


class AwaitableGetAgentsResult(GetAgentsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAgentsResult(
            agent_collections=self.agent_collections,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_agents(compartment_id: Optional[str] = None,
               display_name: Optional[str] = None,
               filters: Optional[Sequence[pulumi.InputType['GetAgentsFilterArgs']]] = None,
               state: Optional[str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAgentsResult:
    """
    This data source provides the list of Agents in Oracle Cloud Infrastructure Database Migration service.

    Display the name of all the existing ODMS Agents in the server.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_agents = oci.databasemigration.get_agents(compartment_id=var["compartment_id"],
        display_name=var["agent_display_name"],
        state=var["agent_state"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str state: The current state of the Database Migration Deployment.
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
    __ret__ = pulumi.runtime.invoke('oci:databasemigration/getAgents:getAgents', __args__, opts=opts, typ=GetAgentsResult).value

    return AwaitableGetAgentsResult(
        agent_collections=__ret__.agent_collections,
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        state=__ret__.state)
