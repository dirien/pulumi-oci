# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetMaintenanceRunResult',
    'AwaitableGetMaintenanceRunResult',
    'get_maintenance_run',
]

@pulumi.output_type
class GetMaintenanceRunResult:
    """
    A collection of values returned by getMaintenanceRun.
    """
    def __init__(__self__, compartment_id=None, description=None, display_name=None, id=None, is_enabled=None, is_patch_now_enabled=None, lifecycle_details=None, maintenance_run_id=None, maintenance_subtype=None, maintenance_type=None, patch_failure_count=None, patch_id=None, patching_mode=None, peer_maintenance_run_id=None, state=None, target_resource_id=None, target_resource_type=None, time_ended=None, time_scheduled=None, time_started=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if is_patch_now_enabled and not isinstance(is_patch_now_enabled, bool):
            raise TypeError("Expected argument 'is_patch_now_enabled' to be a bool")
        pulumi.set(__self__, "is_patch_now_enabled", is_patch_now_enabled)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if maintenance_run_id and not isinstance(maintenance_run_id, str):
            raise TypeError("Expected argument 'maintenance_run_id' to be a str")
        pulumi.set(__self__, "maintenance_run_id", maintenance_run_id)
        if maintenance_subtype and not isinstance(maintenance_subtype, str):
            raise TypeError("Expected argument 'maintenance_subtype' to be a str")
        pulumi.set(__self__, "maintenance_subtype", maintenance_subtype)
        if maintenance_type and not isinstance(maintenance_type, str):
            raise TypeError("Expected argument 'maintenance_type' to be a str")
        pulumi.set(__self__, "maintenance_type", maintenance_type)
        if patch_failure_count and not isinstance(patch_failure_count, int):
            raise TypeError("Expected argument 'patch_failure_count' to be a int")
        pulumi.set(__self__, "patch_failure_count", patch_failure_count)
        if patch_id and not isinstance(patch_id, str):
            raise TypeError("Expected argument 'patch_id' to be a str")
        pulumi.set(__self__, "patch_id", patch_id)
        if patching_mode and not isinstance(patching_mode, str):
            raise TypeError("Expected argument 'patching_mode' to be a str")
        pulumi.set(__self__, "patching_mode", patching_mode)
        if peer_maintenance_run_id and not isinstance(peer_maintenance_run_id, str):
            raise TypeError("Expected argument 'peer_maintenance_run_id' to be a str")
        pulumi.set(__self__, "peer_maintenance_run_id", peer_maintenance_run_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if target_resource_id and not isinstance(target_resource_id, str):
            raise TypeError("Expected argument 'target_resource_id' to be a str")
        pulumi.set(__self__, "target_resource_id", target_resource_id)
        if target_resource_type and not isinstance(target_resource_type, str):
            raise TypeError("Expected argument 'target_resource_type' to be a str")
        pulumi.set(__self__, "target_resource_type", target_resource_type)
        if time_ended and not isinstance(time_ended, str):
            raise TypeError("Expected argument 'time_ended' to be a str")
        pulumi.set(__self__, "time_ended", time_ended)
        if time_scheduled and not isinstance(time_scheduled, str):
            raise TypeError("Expected argument 'time_scheduled' to be a str")
        pulumi.set(__self__, "time_scheduled", time_scheduled)
        if time_started and not isinstance(time_started, str):
            raise TypeError("Expected argument 'time_started' to be a str")
        pulumi.set(__self__, "time_started", time_started)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description of the maintenance run.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The user-friendly name for the maintenance run.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The OCID of the maintenance run.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> bool:
        return pulumi.get(self, "is_enabled")

    @property
    @pulumi.getter(name="isPatchNowEnabled")
    def is_patch_now_enabled(self) -> bool:
        return pulumi.get(self, "is_patch_now_enabled")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="maintenanceRunId")
    def maintenance_run_id(self) -> str:
        return pulumi.get(self, "maintenance_run_id")

    @property
    @pulumi.getter(name="maintenanceSubtype")
    def maintenance_subtype(self) -> str:
        """
        Maintenance sub-type.
        """
        return pulumi.get(self, "maintenance_subtype")

    @property
    @pulumi.getter(name="maintenanceType")
    def maintenance_type(self) -> str:
        """
        Maintenance type.
        """
        return pulumi.get(self, "maintenance_type")

    @property
    @pulumi.getter(name="patchFailureCount")
    def patch_failure_count(self) -> int:
        """
        Contain the patch failure count.
        """
        return pulumi.get(self, "patch_failure_count")

    @property
    @pulumi.getter(name="patchId")
    def patch_id(self) -> str:
        """
        The unique identifier of the patch. The identifier string includes the patch type, the Oracle Database version, and the patch creation date (using the format YYMMDD). For example, the identifier `ru_patch_19.9.0.0_201030` is used for an RU patch for Oracle Database 19.9.0.0 that was released October 30, 2020.
        """
        return pulumi.get(self, "patch_id")

    @property
    @pulumi.getter(name="patchingMode")
    def patching_mode(self) -> str:
        """
        Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
        """
        return pulumi.get(self, "patching_mode")

    @property
    @pulumi.getter(name="peerMaintenanceRunId")
    def peer_maintenance_run_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
        """
        return pulumi.get(self, "peer_maintenance_run_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the maintenance run. For Autonomous Database on shared Exadata infrastructure, valid states are IN_PROGRESS, SUCCEEDED and FAILED.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="targetResourceId")
    def target_resource_id(self) -> str:
        """
        The ID of the target resource on which the maintenance run occurs.
        """
        return pulumi.get(self, "target_resource_id")

    @property
    @pulumi.getter(name="targetResourceType")
    def target_resource_type(self) -> str:
        """
        The type of the target resource on which the maintenance run occurs.
        """
        return pulumi.get(self, "target_resource_type")

    @property
    @pulumi.getter(name="timeEnded")
    def time_ended(self) -> str:
        """
        The date and time the maintenance run was completed.
        """
        return pulumi.get(self, "time_ended")

    @property
    @pulumi.getter(name="timeScheduled")
    def time_scheduled(self) -> str:
        """
        The date and time the maintenance run is scheduled to occur.
        """
        return pulumi.get(self, "time_scheduled")

    @property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> str:
        """
        The date and time the maintenance run starts.
        """
        return pulumi.get(self, "time_started")


class AwaitableGetMaintenanceRunResult(GetMaintenanceRunResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMaintenanceRunResult(
            compartment_id=self.compartment_id,
            description=self.description,
            display_name=self.display_name,
            id=self.id,
            is_enabled=self.is_enabled,
            is_patch_now_enabled=self.is_patch_now_enabled,
            lifecycle_details=self.lifecycle_details,
            maintenance_run_id=self.maintenance_run_id,
            maintenance_subtype=self.maintenance_subtype,
            maintenance_type=self.maintenance_type,
            patch_failure_count=self.patch_failure_count,
            patch_id=self.patch_id,
            patching_mode=self.patching_mode,
            peer_maintenance_run_id=self.peer_maintenance_run_id,
            state=self.state,
            target_resource_id=self.target_resource_id,
            target_resource_type=self.target_resource_type,
            time_ended=self.time_ended,
            time_scheduled=self.time_scheduled,
            time_started=self.time_started)


def get_maintenance_run(maintenance_run_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMaintenanceRunResult:
    """
    This data source provides details about a specific Maintenance Run resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified maintenance run.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_maintenance_run = oci.database.get_maintenance_run(maintenance_run_id=oci_database_maintenance_run["test_maintenance_run"]["id"])
    ```


    :param str maintenance_run_id: The maintenance run OCID.
    """
    __args__ = dict()
    __args__['maintenanceRunId'] = maintenance_run_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getMaintenanceRun:getMaintenanceRun', __args__, opts=opts, typ=GetMaintenanceRunResult).value

    return AwaitableGetMaintenanceRunResult(
        compartment_id=__ret__.compartment_id,
        description=__ret__.description,
        display_name=__ret__.display_name,
        id=__ret__.id,
        is_enabled=__ret__.is_enabled,
        is_patch_now_enabled=__ret__.is_patch_now_enabled,
        lifecycle_details=__ret__.lifecycle_details,
        maintenance_run_id=__ret__.maintenance_run_id,
        maintenance_subtype=__ret__.maintenance_subtype,
        maintenance_type=__ret__.maintenance_type,
        patch_failure_count=__ret__.patch_failure_count,
        patch_id=__ret__.patch_id,
        patching_mode=__ret__.patching_mode,
        peer_maintenance_run_id=__ret__.peer_maintenance_run_id,
        state=__ret__.state,
        target_resource_id=__ret__.target_resource_id,
        target_resource_type=__ret__.target_resource_type,
        time_ended=__ret__.time_ended,
        time_scheduled=__ret__.time_scheduled,
        time_started=__ret__.time_started)
