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
    'GetAlarmStatusesResult',
    'AwaitableGetAlarmStatusesResult',
    'get_alarm_statuses',
]

@pulumi.output_type
class GetAlarmStatusesResult:
    """
    A collection of values returned by getAlarmStatuses.
    """
    def __init__(__self__, alarm_statuses=None, compartment_id=None, compartment_id_in_subtree=None, display_name=None, filters=None, id=None):
        if alarm_statuses and not isinstance(alarm_statuses, list):
            raise TypeError("Expected argument 'alarm_statuses' to be a list")
        pulumi.set(__self__, "alarm_statuses", alarm_statuses)
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

    @property
    @pulumi.getter(name="alarmStatuses")
    def alarm_statuses(self) -> Sequence['outputs.GetAlarmStatusesAlarmStatusResult']:
        """
        The list of alarm_statuses.
        """
        return pulumi.get(self, "alarm_statuses")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The configured name of the alarm.  Example: `High CPU Utilization`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAlarmStatusesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetAlarmStatusesResult(GetAlarmStatusesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAlarmStatusesResult(
            alarm_statuses=self.alarm_statuses,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id)


def get_alarm_statuses(compartment_id: Optional[str] = None,
                       compartment_id_in_subtree: Optional[bool] = None,
                       display_name: Optional[str] = None,
                       filters: Optional[Sequence[pulumi.InputType['GetAlarmStatusesFilterArgs']]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAlarmStatusesResult:
    """
    This data source provides the list of Alarm Statuses in Oracle Cloud Infrastructure Monitoring service.

    List the status of each alarm in the specified compartment.
    For important limits information, see [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#Limits).

    This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
    Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
    or transactions, per second (TPS) for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alarm_statuses = oci.monitoring.get_alarm_statuses(compartment_id=var["compartment_id"],
        compartment_id_in_subtree=var["alarm_status_compartment_id_in_subtree"],
        display_name=var["alarm_status_display_name"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
    :param bool compartment_id_in_subtree: When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
    :param str display_name: A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:monitoring/getAlarmStatuses:getAlarmStatuses', __args__, opts=opts, typ=GetAlarmStatusesResult).value

    return AwaitableGetAlarmStatusesResult(
        alarm_statuses=__ret__.alarm_statuses,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id)
