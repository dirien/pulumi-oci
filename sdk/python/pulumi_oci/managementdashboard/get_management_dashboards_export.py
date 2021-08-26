# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetManagementDashboardsExportResult',
    'AwaitableGetManagementDashboardsExportResult',
    'get_management_dashboards_export',
]

@pulumi.output_type
class GetManagementDashboardsExportResult:
    """
    A collection of values returned by getManagementDashboardsExport.
    """
    def __init__(__self__, export_dashboard_id=None, export_details=None, id=None):
        if export_dashboard_id and not isinstance(export_dashboard_id, str):
            raise TypeError("Expected argument 'export_dashboard_id' to be a str")
        pulumi.set(__self__, "export_dashboard_id", export_dashboard_id)
        if export_details and not isinstance(export_details, str):
            raise TypeError("Expected argument 'export_details' to be a str")
        pulumi.set(__self__, "export_details", export_details)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="exportDashboardId")
    def export_dashboard_id(self) -> str:
        return pulumi.get(self, "export_dashboard_id")

    @property
    @pulumi.getter(name="exportDetails")
    def export_details(self) -> str:
        """
        String containing Array of Dashboards exported, check [ManagementDashboardExportDetails](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/managementdashboard/20200901/datatypes/ManagementDashboardExportDetails) for exact contents in the string value. The value of `export_details` can be used to pass as `import_details` (CompartmentIds may have to be changed) in `managementdashboard.ManagementDashboardsImport` resource.
        """
        return pulumi.get(self, "export_details")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetManagementDashboardsExportResult(GetManagementDashboardsExportResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagementDashboardsExportResult(
            export_dashboard_id=self.export_dashboard_id,
            export_details=self.export_details,
            id=self.id)


def get_management_dashboards_export(export_dashboard_id: Optional[str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagementDashboardsExportResult:
    """
    This data source provides details about a specific Management Dashboards Export resource in Oracle Cloud Infrastructure Management Dashboard service.

    Exports an array of dashboards and their saved searches. Export is designed to work with importDashboard. An example using Oracle Cloud Infrastructure CLI is $oci management-dashboard dashboard export --query data --export-dashboard-id "{\"dashboardIds\":[\"ocid1.managementdashboard.oc1..dashboardId1\"]}"  > dashboards.json $oci management-dashboard dashboard import --from-json file://dashboards.json

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_management_dashboards_export = oci.managementdashboard.get_management_dashboards_export(export_dashboard_id=oci_management_dashboard_export_dashboard["test_export_dashboard"]["id"])
    ```


    :param str export_dashboard_id: List of dashboardIds in plain text. The syntaxt is '{"dashboardIds":["dashboardId1", "dashboardId2", ...]}'. Escaping is needed when using in Oracle Cloud Infrastructure CLI. For example, "{\"dashboardIds\":[\"ocid1.managementdashboard.oc1..dashboardId1\"]}" .
    """
    __args__ = dict()
    __args__['exportDashboardId'] = export_dashboard_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:managementdashboard/getManagementDashboardsExport:getManagementDashboardsExport', __args__, opts=opts, typ=GetManagementDashboardsExportResult).value

    return AwaitableGetManagementDashboardsExportResult(
        export_dashboard_id=__ret__.export_dashboard_id,
        export_details=__ret__.export_details,
        id=__ret__.id)
