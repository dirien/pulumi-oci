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
    'GetRunLogsResult',
    'AwaitableGetRunLogsResult',
    'get_run_logs',
]

@pulumi.output_type
class GetRunLogsResult:
    """
    A collection of values returned by getRunLogs.
    """
    def __init__(__self__, filters=None, id=None, run_id=None, run_logs=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if run_id and not isinstance(run_id, str):
            raise TypeError("Expected argument 'run_id' to be a str")
        pulumi.set(__self__, "run_id", run_id)
        if run_logs and not isinstance(run_logs, list):
            raise TypeError("Expected argument 'run_logs' to be a list")
        pulumi.set(__self__, "run_logs", run_logs)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRunLogsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="runId")
    def run_id(self) -> str:
        return pulumi.get(self, "run_id")

    @property
    @pulumi.getter(name="runLogs")
    def run_logs(self) -> Sequence['outputs.GetRunLogsRunLogResult']:
        """
        The list of run_logs.
        """
        return pulumi.get(self, "run_logs")


class AwaitableGetRunLogsResult(GetRunLogsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRunLogsResult(
            filters=self.filters,
            id=self.id,
            run_id=self.run_id,
            run_logs=self.run_logs)


def get_run_logs(filters: Optional[Sequence[pulumi.InputType['GetRunLogsFilterArgs']]] = None,
                 run_id: Optional[str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRunLogsResult:
    """
    This data source provides the list of Run Logs in Oracle Cloud Infrastructure Data Flow service.

    Retrieves summaries of the run's logs.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_run_logs = oci.dataflow.get_run_logs(run_id=oci_dataflow_run["test_run"]["id"])
    ```


    :param str run_id: The unique ID for the run
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['runId'] = run_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:dataflow/getRunLogs:getRunLogs', __args__, opts=opts, typ=GetRunLogsResult).value

    return AwaitableGetRunLogsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        run_id=__ret__.run_id,
        run_logs=__ret__.run_logs)
