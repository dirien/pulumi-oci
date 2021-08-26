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
    'GetAlarmHistoryCollectionResult',
    'AwaitableGetAlarmHistoryCollectionResult',
    'get_alarm_history_collection',
]

@pulumi.output_type
class GetAlarmHistoryCollectionResult:
    """
    A collection of values returned by getAlarmHistoryCollection.
    """
    def __init__(__self__, alarm_historytype=None, alarm_id=None, entries=None, id=None, is_enabled=None, timestamp_greater_than_or_equal_to=None, timestamp_less_than=None):
        if alarm_historytype and not isinstance(alarm_historytype, str):
            raise TypeError("Expected argument 'alarm_historytype' to be a str")
        pulumi.set(__self__, "alarm_historytype", alarm_historytype)
        if alarm_id and not isinstance(alarm_id, str):
            raise TypeError("Expected argument 'alarm_id' to be a str")
        pulumi.set(__self__, "alarm_id", alarm_id)
        if entries and not isinstance(entries, list):
            raise TypeError("Expected argument 'entries' to be a list")
        pulumi.set(__self__, "entries", entries)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if timestamp_greater_than_or_equal_to and not isinstance(timestamp_greater_than_or_equal_to, str):
            raise TypeError("Expected argument 'timestamp_greater_than_or_equal_to' to be a str")
        pulumi.set(__self__, "timestamp_greater_than_or_equal_to", timestamp_greater_than_or_equal_to)
        if timestamp_less_than and not isinstance(timestamp_less_than, str):
            raise TypeError("Expected argument 'timestamp_less_than' to be a str")
        pulumi.set(__self__, "timestamp_less_than", timestamp_less_than)

    @property
    @pulumi.getter(name="alarmHistorytype")
    def alarm_historytype(self) -> Optional[str]:
        return pulumi.get(self, "alarm_historytype")

    @property
    @pulumi.getter(name="alarmId")
    def alarm_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm for which to retrieve history.
        """
        return pulumi.get(self, "alarm_id")

    @property
    @pulumi.getter
    def entries(self) -> Sequence['outputs.GetAlarmHistoryCollectionEntryResult']:
        """
        The set of history entries retrieved for the alarm.
        """
        return pulumi.get(self, "entries")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> bool:
        """
        Whether the alarm is enabled.  Example: `true`
        """
        return pulumi.get(self, "is_enabled")

    @property
    @pulumi.getter(name="timestampGreaterThanOrEqualTo")
    def timestamp_greater_than_or_equal_to(self) -> Optional[str]:
        return pulumi.get(self, "timestamp_greater_than_or_equal_to")

    @property
    @pulumi.getter(name="timestampLessThan")
    def timestamp_less_than(self) -> Optional[str]:
        return pulumi.get(self, "timestamp_less_than")


class AwaitableGetAlarmHistoryCollectionResult(GetAlarmHistoryCollectionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAlarmHistoryCollectionResult(
            alarm_historytype=self.alarm_historytype,
            alarm_id=self.alarm_id,
            entries=self.entries,
            id=self.id,
            is_enabled=self.is_enabled,
            timestamp_greater_than_or_equal_to=self.timestamp_greater_than_or_equal_to,
            timestamp_less_than=self.timestamp_less_than)


def get_alarm_history_collection(alarm_historytype: Optional[str] = None,
                                 alarm_id: Optional[str] = None,
                                 timestamp_greater_than_or_equal_to: Optional[str] = None,
                                 timestamp_less_than: Optional[str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAlarmHistoryCollectionResult:
    """
    This data source provides details about a specific Alarm History Collection resource in Oracle Cloud Infrastructure Monitoring service.

    Get the history of the specified alarm.
    For important limits information, see [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#Limits).

    This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
    Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
    or transactions, per second (TPS) for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alarm_history_collection = oci.monitoring.get_alarm_history_collection(alarm_id=oci_monitoring_alarm["test_alarm"]["id"],
        alarm_historytype=var["alarm_history_collection_alarm_historytype"],
        timestamp_greater_than_or_equal_to=var["alarm_history_collection_timestamp_greater_than_or_equal_to"],
        timestamp_less_than=var["alarm_history_collection_timestamp_less_than"])
    ```


    :param str alarm_historytype: The type of history entries to retrieve. State history (STATE_HISTORY) or state transition history (STATE_TRANSITION_HISTORY). If not specified, entries of both types are retrieved.  Example: `STATE_HISTORY`
    :param str alarm_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an alarm.
    :param str timestamp_greater_than_or_equal_to: A filter to return only alarm history entries with timestamps occurring on or after the specified date and time. Format defined by RFC3339.  Example: `2019-01-01T01:00:00.789Z`
    :param str timestamp_less_than: A filter to return only alarm history entries with timestamps occurring before the specified date and time. Format defined by RFC3339.  Example: `2019-01-02T01:00:00.789Z`
    """
    __args__ = dict()
    __args__['alarmHistorytype'] = alarm_historytype
    __args__['alarmId'] = alarm_id
    __args__['timestampGreaterThanOrEqualTo'] = timestamp_greater_than_or_equal_to
    __args__['timestampLessThan'] = timestamp_less_than
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:monitoring/getAlarmHistoryCollection:getAlarmHistoryCollection', __args__, opts=opts, typ=GetAlarmHistoryCollectionResult).value

    return AwaitableGetAlarmHistoryCollectionResult(
        alarm_historytype=__ret__.alarm_historytype,
        alarm_id=__ret__.alarm_id,
        entries=__ret__.entries,
        id=__ret__.id,
        is_enabled=__ret__.is_enabled,
        timestamp_greater_than_or_equal_to=__ret__.timestamp_greater_than_or_equal_to,
        timestamp_less_than=__ret__.timestamp_less_than)
