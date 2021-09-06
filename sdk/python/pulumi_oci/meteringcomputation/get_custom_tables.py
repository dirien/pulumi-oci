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
    'GetCustomTablesResult',
    'AwaitableGetCustomTablesResult',
    'get_custom_tables',
]

@pulumi.output_type
class GetCustomTablesResult:
    """
    A collection of values returned by getCustomTables.
    """
    def __init__(__self__, compartment_id=None, custom_table_collections=None, filters=None, id=None, saved_report_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if custom_table_collections and not isinstance(custom_table_collections, list):
            raise TypeError("Expected argument 'custom_table_collections' to be a list")
        pulumi.set(__self__, "custom_table_collections", custom_table_collections)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if saved_report_id and not isinstance(saved_report_id, str):
            raise TypeError("Expected argument 'saved_report_id' to be a str")
        pulumi.set(__self__, "saved_report_id", saved_report_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The custom table compartment OCID.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="customTableCollections")
    def custom_table_collections(self) -> Sequence['outputs.GetCustomTablesCustomTableCollectionResult']:
        """
        The list of custom_table_collection.
        """
        return pulumi.get(self, "custom_table_collections")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetCustomTablesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="savedReportId")
    def saved_report_id(self) -> str:
        """
        The custom table associated saved report OCID.
        """
        return pulumi.get(self, "saved_report_id")


class AwaitableGetCustomTablesResult(GetCustomTablesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCustomTablesResult(
            compartment_id=self.compartment_id,
            custom_table_collections=self.custom_table_collections,
            filters=self.filters,
            id=self.id,
            saved_report_id=self.saved_report_id)


def get_custom_tables(compartment_id: Optional[str] = None,
                      filters: Optional[Sequence[pulumi.InputType['GetCustomTablesFilterArgs']]] = None,
                      saved_report_id: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCustomTablesResult:
    """
    This data source provides the list of Custom Tables in Oracle Cloud Infrastructure Metering Computation service.

    Returns the saved custom table list.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_custom_tables = oci.meteringcomputation.get_custom_tables(compartment_id=var["compartment_id"],
        saved_report_id=oci_metering_computation_saved_report["test_saved_report"]["id"])
    ```


    :param str compartment_id: The compartment ID in which to list resources.
    :param str saved_report_id: The saved report ID in which to list resources.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['savedReportId'] = saved_report_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:meteringcomputation/getCustomTables:getCustomTables', __args__, opts=opts, typ=GetCustomTablesResult).value

    return AwaitableGetCustomTablesResult(
        compartment_id=__ret__.compartment_id,
        custom_table_collections=__ret__.custom_table_collections,
        filters=__ret__.filters,
        id=__ret__.id,
        saved_report_id=__ret__.saved_report_id)
