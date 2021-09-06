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
    'GetAutonomousExadataInfrastructureOcpuResult',
    'AwaitableGetAutonomousExadataInfrastructureOcpuResult',
    'get_autonomous_exadata_infrastructure_ocpu',
]

@pulumi.output_type
class GetAutonomousExadataInfrastructureOcpuResult:
    """
    A collection of values returned by getAutonomousExadataInfrastructureOcpu.
    """
    def __init__(__self__, autonomous_exadata_infrastructure_id=None, by_workload_types=None, consumed_cpu=None, id=None, total_cpu=None):
        if autonomous_exadata_infrastructure_id and not isinstance(autonomous_exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'autonomous_exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "autonomous_exadata_infrastructure_id", autonomous_exadata_infrastructure_id)
        if by_workload_types and not isinstance(by_workload_types, list):
            raise TypeError("Expected argument 'by_workload_types' to be a list")
        pulumi.set(__self__, "by_workload_types", by_workload_types)
        if consumed_cpu and not isinstance(consumed_cpu, float):
            raise TypeError("Expected argument 'consumed_cpu' to be a float")
        pulumi.set(__self__, "consumed_cpu", consumed_cpu)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if total_cpu and not isinstance(total_cpu, float):
            raise TypeError("Expected argument 'total_cpu' to be a float")
        pulumi.set(__self__, "total_cpu", total_cpu)

    @property
    @pulumi.getter(name="autonomousExadataInfrastructureId")
    def autonomous_exadata_infrastructure_id(self) -> str:
        return pulumi.get(self, "autonomous_exadata_infrastructure_id")

    @property
    @pulumi.getter(name="byWorkloadTypes")
    def by_workload_types(self) -> Sequence['outputs.GetAutonomousExadataInfrastructureOcpuByWorkloadTypeResult']:
        """
        The number of consumed OCPUs, by database workload type.
        """
        return pulumi.get(self, "by_workload_types")

    @property
    @pulumi.getter(name="consumedCpu")
    def consumed_cpu(self) -> float:
        """
        The total number of consumed OCPUs in the Autonomous Exadata Infrastructure instance.
        """
        return pulumi.get(self, "consumed_cpu")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="totalCpu")
    def total_cpu(self) -> float:
        """
        The total number of OCPUs in the Autonomous Exadata Infrastructure instance.
        """
        return pulumi.get(self, "total_cpu")


class AwaitableGetAutonomousExadataInfrastructureOcpuResult(GetAutonomousExadataInfrastructureOcpuResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAutonomousExadataInfrastructureOcpuResult(
            autonomous_exadata_infrastructure_id=self.autonomous_exadata_infrastructure_id,
            by_workload_types=self.by_workload_types,
            consumed_cpu=self.consumed_cpu,
            id=self.id,
            total_cpu=self.total_cpu)


def get_autonomous_exadata_infrastructure_ocpu(autonomous_exadata_infrastructure_id: Optional[str] = None,
                                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAutonomousExadataInfrastructureOcpuResult:
    """
    This data source provides details about a specific Autonomous Exadata Infrastructure Ocpu resource in Oracle Cloud Infrastructure Database service.

    Gets details of the available and consumed OCPUs for the specified Autonomous Exadata Infrastructure resource.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_autonomous_exadata_infrastructure_ocpu = oci.database.get_autonomous_exadata_infrastructure_ocpu(autonomous_exadata_infrastructure_id=oci_database_autonomous_exadata_infrastructure["test_autonomous_exadata_infrastructure"]["id"])
    ```


    :param str autonomous_exadata_infrastructure_id: The Autonomous Exadata Infrastructure  [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['autonomousExadataInfrastructureId'] = autonomous_exadata_infrastructure_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getAutonomousExadataInfrastructureOcpu:getAutonomousExadataInfrastructureOcpu', __args__, opts=opts, typ=GetAutonomousExadataInfrastructureOcpuResult).value

    return AwaitableGetAutonomousExadataInfrastructureOcpuResult(
        autonomous_exadata_infrastructure_id=__ret__.autonomous_exadata_infrastructure_id,
        by_workload_types=__ret__.by_workload_types,
        consumed_cpu=__ret__.consumed_cpu,
        id=__ret__.id,
        total_cpu=__ret__.total_cpu)
