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
    'GetExternalDatabaseConnectorResult',
    'AwaitableGetExternalDatabaseConnectorResult',
    'get_external_database_connector',
]

@pulumi.output_type
class GetExternalDatabaseConnectorResult:
    """
    A collection of values returned by getExternalDatabaseConnector.
    """
    def __init__(__self__, compartment_id=None, connection_credentials=None, connection_status=None, connection_string=None, connector_agent_id=None, connector_type=None, defined_tags=None, display_name=None, external_database_connector_id=None, external_database_id=None, freeform_tags=None, id=None, lifecycle_details=None, state=None, time_connection_status_last_updated=None, time_created=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if connection_credentials and not isinstance(connection_credentials, dict):
            raise TypeError("Expected argument 'connection_credentials' to be a dict")
        pulumi.set(__self__, "connection_credentials", connection_credentials)
        if connection_status and not isinstance(connection_status, str):
            raise TypeError("Expected argument 'connection_status' to be a str")
        pulumi.set(__self__, "connection_status", connection_status)
        if connection_string and not isinstance(connection_string, dict):
            raise TypeError("Expected argument 'connection_string' to be a dict")
        pulumi.set(__self__, "connection_string", connection_string)
        if connector_agent_id and not isinstance(connector_agent_id, str):
            raise TypeError("Expected argument 'connector_agent_id' to be a str")
        pulumi.set(__self__, "connector_agent_id", connector_agent_id)
        if connector_type and not isinstance(connector_type, str):
            raise TypeError("Expected argument 'connector_type' to be a str")
        pulumi.set(__self__, "connector_type", connector_type)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if external_database_connector_id and not isinstance(external_database_connector_id, str):
            raise TypeError("Expected argument 'external_database_connector_id' to be a str")
        pulumi.set(__self__, "external_database_connector_id", external_database_connector_id)
        if external_database_id and not isinstance(external_database_id, str):
            raise TypeError("Expected argument 'external_database_id' to be a str")
        pulumi.set(__self__, "external_database_id", external_database_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_connection_status_last_updated and not isinstance(time_connection_status_last_updated, str):
            raise TypeError("Expected argument 'time_connection_status_last_updated' to be a str")
        pulumi.set(__self__, "time_connection_status_last_updated", time_connection_status_last_updated)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="connectionCredentials")
    def connection_credentials(self) -> 'outputs.GetExternalDatabaseConnectorConnectionCredentialsResult':
        """
        Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
        """
        return pulumi.get(self, "connection_credentials")

    @property
    @pulumi.getter(name="connectionStatus")
    def connection_status(self) -> str:
        """
        The status of connectivity to the external database.
        """
        return pulumi.get(self, "connection_status")

    @property
    @pulumi.getter(name="connectionString")
    def connection_string(self) -> 'outputs.GetExternalDatabaseConnectorConnectionStringResult':
        """
        The Oracle Database connection string.
        """
        return pulumi.get(self, "connection_string")

    @property
    @pulumi.getter(name="connectorAgentId")
    def connector_agent_id(self) -> str:
        """
        The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        """
        return pulumi.get(self, "connector_agent_id")

    @property
    @pulumi.getter(name="connectorType")
    def connector_type(self) -> str:
        """
        The type of connector used by the external database resource.
        """
        return pulumi.get(self, "connector_type")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="externalDatabaseConnectorId")
    def external_database_connector_id(self) -> str:
        return pulumi.get(self, "external_database_connector_id")

    @property
    @pulumi.getter(name="externalDatabaseId")
    def external_database_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
        """
        return pulumi.get(self, "external_database_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current lifecycle state of the external database connector resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeConnectionStatusLastUpdated")
    def time_connection_status_last_updated(self) -> str:
        """
        The date and time the `connectionStatus` of this external connector was last updated.
        """
        return pulumi.get(self, "time_connection_status_last_updated")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the external connector was created.
        """
        return pulumi.get(self, "time_created")


class AwaitableGetExternalDatabaseConnectorResult(GetExternalDatabaseConnectorResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetExternalDatabaseConnectorResult(
            compartment_id=self.compartment_id,
            connection_credentials=self.connection_credentials,
            connection_status=self.connection_status,
            connection_string=self.connection_string,
            connector_agent_id=self.connector_agent_id,
            connector_type=self.connector_type,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            external_database_connector_id=self.external_database_connector_id,
            external_database_id=self.external_database_id,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            state=self.state,
            time_connection_status_last_updated=self.time_connection_status_last_updated,
            time_created=self.time_created)


def get_external_database_connector(external_database_connector_id: Optional[str] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetExternalDatabaseConnectorResult:
    """
    This data source provides details about a specific External Database Connector resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified external database connector.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_database_connector = oci.database.get_external_database_connector(external_database_connector_id=oci_database_external_database_connector["test_external_database_connector"]["id"])
    ```


    :param str external_database_connector_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector resource (`ExternalDatabaseConnectorId`).
    """
    __args__ = dict()
    __args__['externalDatabaseConnectorId'] = external_database_connector_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getExternalDatabaseConnector:getExternalDatabaseConnector', __args__, opts=opts, typ=GetExternalDatabaseConnectorResult).value

    return AwaitableGetExternalDatabaseConnectorResult(
        compartment_id=__ret__.compartment_id,
        connection_credentials=__ret__.connection_credentials,
        connection_status=__ret__.connection_status,
        connection_string=__ret__.connection_string,
        connector_agent_id=__ret__.connector_agent_id,
        connector_type=__ret__.connector_type,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        external_database_connector_id=__ret__.external_database_connector_id,
        external_database_id=__ret__.external_database_id,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        state=__ret__.state,
        time_connection_status_last_updated=__ret__.time_connection_status_last_updated,
        time_created=__ret__.time_created)
