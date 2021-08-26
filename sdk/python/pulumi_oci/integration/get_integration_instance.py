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
    'GetIntegrationInstanceResult',
    'AwaitableGetIntegrationInstanceResult',
    'get_integration_instance',
]

@pulumi.output_type
class GetIntegrationInstanceResult:
    """
    A collection of values returned by getIntegrationInstance.
    """
    def __init__(__self__, alternate_custom_endpoints=None, compartment_id=None, consumption_model=None, custom_endpoint=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, idcs_at=None, instance_url=None, integration_instance_id=None, integration_instance_type=None, is_byol=None, is_file_server_enabled=None, is_visual_builder_enabled=None, message_packs=None, network_endpoint_details=None, state=None, state_message=None, time_created=None, time_updated=None):
        if alternate_custom_endpoints and not isinstance(alternate_custom_endpoints, list):
            raise TypeError("Expected argument 'alternate_custom_endpoints' to be a list")
        pulumi.set(__self__, "alternate_custom_endpoints", alternate_custom_endpoints)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if consumption_model and not isinstance(consumption_model, str):
            raise TypeError("Expected argument 'consumption_model' to be a str")
        pulumi.set(__self__, "consumption_model", consumption_model)
        if custom_endpoint and not isinstance(custom_endpoint, dict):
            raise TypeError("Expected argument 'custom_endpoint' to be a dict")
        pulumi.set(__self__, "custom_endpoint", custom_endpoint)
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
        if idcs_at and not isinstance(idcs_at, str):
            raise TypeError("Expected argument 'idcs_at' to be a str")
        pulumi.set(__self__, "idcs_at", idcs_at)
        if instance_url and not isinstance(instance_url, str):
            raise TypeError("Expected argument 'instance_url' to be a str")
        pulumi.set(__self__, "instance_url", instance_url)
        if integration_instance_id and not isinstance(integration_instance_id, str):
            raise TypeError("Expected argument 'integration_instance_id' to be a str")
        pulumi.set(__self__, "integration_instance_id", integration_instance_id)
        if integration_instance_type and not isinstance(integration_instance_type, str):
            raise TypeError("Expected argument 'integration_instance_type' to be a str")
        pulumi.set(__self__, "integration_instance_type", integration_instance_type)
        if is_byol and not isinstance(is_byol, bool):
            raise TypeError("Expected argument 'is_byol' to be a bool")
        pulumi.set(__self__, "is_byol", is_byol)
        if is_file_server_enabled and not isinstance(is_file_server_enabled, bool):
            raise TypeError("Expected argument 'is_file_server_enabled' to be a bool")
        pulumi.set(__self__, "is_file_server_enabled", is_file_server_enabled)
        if is_visual_builder_enabled and not isinstance(is_visual_builder_enabled, bool):
            raise TypeError("Expected argument 'is_visual_builder_enabled' to be a bool")
        pulumi.set(__self__, "is_visual_builder_enabled", is_visual_builder_enabled)
        if message_packs and not isinstance(message_packs, int):
            raise TypeError("Expected argument 'message_packs' to be a int")
        pulumi.set(__self__, "message_packs", message_packs)
        if network_endpoint_details and not isinstance(network_endpoint_details, dict):
            raise TypeError("Expected argument 'network_endpoint_details' to be a dict")
        pulumi.set(__self__, "network_endpoint_details", network_endpoint_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if state_message and not isinstance(state_message, str):
            raise TypeError("Expected argument 'state_message' to be a str")
        pulumi.set(__self__, "state_message", state_message)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="alternateCustomEndpoints")
    def alternate_custom_endpoints(self) -> Sequence['outputs.GetIntegrationInstanceAlternateCustomEndpointResult']:
        """
        A list of alternate custom endpoints used for the integration instance URL.
        """
        return pulumi.get(self, "alternate_custom_endpoints")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="consumptionModel")
    def consumption_model(self) -> str:
        """
        The entitlement used for billing purposes.
        """
        return pulumi.get(self, "consumption_model")

    @property
    @pulumi.getter(name="customEndpoint")
    def custom_endpoint(self) -> 'outputs.GetIntegrationInstanceCustomEndpointResult':
        """
        Details for a custom endpoint for the integration instance.
        """
        return pulumi.get(self, "custom_endpoint")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Integration Instance Identifier, can be renamed.
        """
        return pulumi.get(self, "display_name")

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
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAt")
    def idcs_at(self) -> str:
        return pulumi.get(self, "idcs_at")

    @property
    @pulumi.getter(name="instanceUrl")
    def instance_url(self) -> str:
        """
        The Integration Instance URL.
        """
        return pulumi.get(self, "instance_url")

    @property
    @pulumi.getter(name="integrationInstanceId")
    def integration_instance_id(self) -> str:
        return pulumi.get(self, "integration_instance_id")

    @property
    @pulumi.getter(name="integrationInstanceType")
    def integration_instance_type(self) -> str:
        """
        Standard or Enterprise type
        """
        return pulumi.get(self, "integration_instance_type")

    @property
    @pulumi.getter(name="isByol")
    def is_byol(self) -> bool:
        """
        Bring your own license.
        """
        return pulumi.get(self, "is_byol")

    @property
    @pulumi.getter(name="isFileServerEnabled")
    def is_file_server_enabled(self) -> bool:
        """
        The file server is enabled or not.
        """
        return pulumi.get(self, "is_file_server_enabled")

    @property
    @pulumi.getter(name="isVisualBuilderEnabled")
    def is_visual_builder_enabled(self) -> bool:
        """
        Visual Builder is enabled or not.
        """
        return pulumi.get(self, "is_visual_builder_enabled")

    @property
    @pulumi.getter(name="messagePacks")
    def message_packs(self) -> int:
        """
        The number of configured message packs (if any)
        """
        return pulumi.get(self, "message_packs")

    @property
    @pulumi.getter(name="networkEndpointDetails")
    def network_endpoint_details(self) -> 'outputs.GetIntegrationInstanceNetworkEndpointDetailsResult':
        """
        Base representation of a network endpoint.
        """
        return pulumi.get(self, "network_endpoint_details")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the integration instance.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="stateMessage")
    def state_message(self) -> str:
        """
        An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "state_message")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the Integration Instance was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the IntegrationInstance was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetIntegrationInstanceResult(GetIntegrationInstanceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIntegrationInstanceResult(
            alternate_custom_endpoints=self.alternate_custom_endpoints,
            compartment_id=self.compartment_id,
            consumption_model=self.consumption_model,
            custom_endpoint=self.custom_endpoint,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            idcs_at=self.idcs_at,
            instance_url=self.instance_url,
            integration_instance_id=self.integration_instance_id,
            integration_instance_type=self.integration_instance_type,
            is_byol=self.is_byol,
            is_file_server_enabled=self.is_file_server_enabled,
            is_visual_builder_enabled=self.is_visual_builder_enabled,
            message_packs=self.message_packs,
            network_endpoint_details=self.network_endpoint_details,
            state=self.state,
            state_message=self.state_message,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_integration_instance(integration_instance_id: Optional[str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIntegrationInstanceResult:
    """
    This data source provides details about a specific Integration Instance resource in Oracle Cloud Infrastructure Integration service.

    Gets a IntegrationInstance by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_integration_instance = oci.integration.get_integration_instance(integration_instance_id=oci_integration_integration_instance["test_integration_instance"]["id"])
    ```


    :param str integration_instance_id: Unique Integration Instance identifier.
    """
    __args__ = dict()
    __args__['integrationInstanceId'] = integration_instance_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:integration/getIntegrationInstance:getIntegrationInstance', __args__, opts=opts, typ=GetIntegrationInstanceResult).value

    return AwaitableGetIntegrationInstanceResult(
        alternate_custom_endpoints=__ret__.alternate_custom_endpoints,
        compartment_id=__ret__.compartment_id,
        consumption_model=__ret__.consumption_model,
        custom_endpoint=__ret__.custom_endpoint,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        idcs_at=__ret__.idcs_at,
        instance_url=__ret__.instance_url,
        integration_instance_id=__ret__.integration_instance_id,
        integration_instance_type=__ret__.integration_instance_type,
        is_byol=__ret__.is_byol,
        is_file_server_enabled=__ret__.is_file_server_enabled,
        is_visual_builder_enabled=__ret__.is_visual_builder_enabled,
        message_packs=__ret__.message_packs,
        network_endpoint_details=__ret__.network_endpoint_details,
        state=__ret__.state,
        state_message=__ret__.state_message,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
