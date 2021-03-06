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
    'GetDatabaseInsightsResult',
    'AwaitableGetDatabaseInsightsResult',
    'get_database_insights',
]

@pulumi.output_type
class GetDatabaseInsightsResult:
    """
    A collection of values returned by getDatabaseInsights.
    """
    def __init__(__self__, compartment_id=None, database_ids=None, database_insights_collections=None, database_types=None, enterprise_manager_bridge_id=None, fields=None, filters=None, id=None, states=None, statuses=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if database_ids and not isinstance(database_ids, list):
            raise TypeError("Expected argument 'database_ids' to be a list")
        pulumi.set(__self__, "database_ids", database_ids)
        if database_insights_collections and not isinstance(database_insights_collections, list):
            raise TypeError("Expected argument 'database_insights_collections' to be a list")
        pulumi.set(__self__, "database_insights_collections", database_insights_collections)
        if database_types and not isinstance(database_types, list):
            raise TypeError("Expected argument 'database_types' to be a list")
        pulumi.set(__self__, "database_types", database_types)
        if enterprise_manager_bridge_id and not isinstance(enterprise_manager_bridge_id, str):
            raise TypeError("Expected argument 'enterprise_manager_bridge_id' to be a str")
        pulumi.set(__self__, "enterprise_manager_bridge_id", enterprise_manager_bridge_id)
        if fields and not isinstance(fields, list):
            raise TypeError("Expected argument 'fields' to be a list")
        pulumi.set(__self__, "fields", fields)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)
        if statuses and not isinstance(statuses, list):
            raise TypeError("Expected argument 'statuses' to be a list")
        pulumi.set(__self__, "statuses", statuses)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        Compartment identifier of the database
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="databaseIds")
    def database_ids(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "database_ids")

    @property
    @pulumi.getter(name="databaseInsightsCollections")
    def database_insights_collections(self) -> Sequence['outputs.GetDatabaseInsightsDatabaseInsightsCollectionResult']:
        """
        The list of database_insights_collection.
        """
        return pulumi.get(self, "database_insights_collections")

    @property
    @pulumi.getter(name="databaseTypes")
    def database_types(self) -> Optional[Sequence[str]]:
        """
        Operations Insights internal representation of the database type.
        """
        return pulumi.get(self, "database_types")

    @property
    @pulumi.getter(name="enterpriseManagerBridgeId")
    def enterprise_manager_bridge_id(self) -> Optional[str]:
        """
        OPSI Enterprise Manager Bridge OCID
        """
        return pulumi.get(self, "enterprise_manager_bridge_id")

    @property
    @pulumi.getter
    def fields(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "fields")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDatabaseInsightsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        Database insight identifier
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def states(self) -> Optional[Sequence[str]]:
        """
        The current state of the database.
        """
        return pulumi.get(self, "states")

    @property
    @pulumi.getter
    def statuses(self) -> Optional[Sequence[str]]:
        """
        Indicates the status of a database insight in Operations Insights
        """
        return pulumi.get(self, "statuses")


class AwaitableGetDatabaseInsightsResult(GetDatabaseInsightsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDatabaseInsightsResult(
            compartment_id=self.compartment_id,
            database_ids=self.database_ids,
            database_insights_collections=self.database_insights_collections,
            database_types=self.database_types,
            enterprise_manager_bridge_id=self.enterprise_manager_bridge_id,
            fields=self.fields,
            filters=self.filters,
            id=self.id,
            states=self.states,
            statuses=self.statuses)


def get_database_insights(compartment_id: Optional[str] = None,
                          database_ids: Optional[Sequence[str]] = None,
                          database_types: Optional[Sequence[str]] = None,
                          enterprise_manager_bridge_id: Optional[str] = None,
                          fields: Optional[Sequence[str]] = None,
                          filters: Optional[Sequence[pulumi.InputType['GetDatabaseInsightsFilterArgs']]] = None,
                          id: Optional[str] = None,
                          states: Optional[Sequence[str]] = None,
                          statuses: Optional[Sequence[str]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDatabaseInsightsResult:
    """
    This data source provides the list of Database Insights in Oracle Cloud Infrastructure Opsi service.

    Gets a list of database insights based on the query parameters specified. Either compartmentId or id query parameter must be specified.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_database_insights = oci.opsi.get_database_insights(compartment_id=var["compartment_id"],
        database_ids=oci_database_database["test_database"]["id"],
        database_types=var["database_insight_database_type"],
        enterprise_manager_bridge_id=oci_opsi_enterprise_manager_bridge["test_enterprise_manager_bridge"]["id"],
        fields=var["database_insight_fields"],
        id=var["database_insight_id"],
        states=var["database_insight_state"],
        statuses=var["database_insight_status"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param Sequence[str] database_ids: Optional list of database [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated DBaaS entity.
    :param Sequence[str] database_types: Filter by one or more database type. Possible values are ADW-S, ATP-S, ADW-D, ATP-D, EXTERNAL-PDB, EXTERNAL-NONCDB.
    :param str enterprise_manager_bridge_id: Unique Enterprise Manager bridge identifier
    :param Sequence[str] fields: Specifies the fields to return in a database summary response. By default all fields are returned if omitted.
    :param str id: Optional database insight resource [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database insight resource.
    :param Sequence[str] states: Lifecycle states
    :param Sequence[str] statuses: Resource Status
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['databaseIds'] = database_ids
    __args__['databaseTypes'] = database_types
    __args__['enterpriseManagerBridgeId'] = enterprise_manager_bridge_id
    __args__['fields'] = fields
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['states'] = states
    __args__['statuses'] = statuses
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:opsi/getDatabaseInsights:getDatabaseInsights', __args__, opts=opts, typ=GetDatabaseInsightsResult).value

    return AwaitableGetDatabaseInsightsResult(
        compartment_id=__ret__.compartment_id,
        database_ids=__ret__.database_ids,
        database_insights_collections=__ret__.database_insights_collections,
        database_types=__ret__.database_types,
        enterprise_manager_bridge_id=__ret__.enterprise_manager_bridge_id,
        fields=__ret__.fields,
        filters=__ret__.filters,
        id=__ret__.id,
        states=__ret__.states,
        statuses=__ret__.statuses)
