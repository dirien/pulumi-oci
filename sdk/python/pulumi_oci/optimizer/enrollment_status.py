# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['EnrollmentStatusArgs', 'EnrollmentStatus']

@pulumi.input_type
class EnrollmentStatusArgs:
    def __init__(__self__, *,
                 enrollment_status_id: pulumi.Input[str],
                 status: pulumi.Input[str]):
        """
        The set of arguments for constructing a EnrollmentStatus resource.
        :param pulumi.Input[str] enrollment_status_id: The unique OCID associated with the enrollment status.
        :param pulumi.Input[str] status: (Updatable) The Cloud Advisor enrollment status.
        """
        pulumi.set(__self__, "enrollment_status_id", enrollment_status_id)
        pulumi.set(__self__, "status", status)

    @property
    @pulumi.getter(name="enrollmentStatusId")
    def enrollment_status_id(self) -> pulumi.Input[str]:
        """
        The unique OCID associated with the enrollment status.
        """
        return pulumi.get(self, "enrollment_status_id")

    @enrollment_status_id.setter
    def enrollment_status_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "enrollment_status_id", value)

    @property
    @pulumi.getter
    def status(self) -> pulumi.Input[str]:
        """
        (Updatable) The Cloud Advisor enrollment status.
        """
        return pulumi.get(self, "status")

    @status.setter
    def status(self, value: pulumi.Input[str]):
        pulumi.set(self, "status", value)


@pulumi.input_type
class _EnrollmentStatusState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 enrollment_status_id: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 status: Optional[pulumi.Input[str]] = None,
                 status_reason: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering EnrollmentStatus resources.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment.
        :param pulumi.Input[str] enrollment_status_id: The unique OCID associated with the enrollment status.
        :param pulumi.Input[str] state: The enrollment status' current state.
        :param pulumi.Input[str] status: (Updatable) The Cloud Advisor enrollment status.
        :param pulumi.Input[str] status_reason: The reason for the enrollment status of the tenancy.
        :param pulumi.Input[str] time_created: The date and time the enrollment status was created, in the format defined by RFC3339.
        :param pulumi.Input[str] time_updated: The date and time the enrollment status was last updated, in the format defined by RFC3339.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if enrollment_status_id is not None:
            pulumi.set(__self__, "enrollment_status_id", enrollment_status_id)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if status is not None:
            pulumi.set(__self__, "status", status)
        if status_reason is not None:
            pulumi.set(__self__, "status_reason", status_reason)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="enrollmentStatusId")
    def enrollment_status_id(self) -> Optional[pulumi.Input[str]]:
        """
        The unique OCID associated with the enrollment status.
        """
        return pulumi.get(self, "enrollment_status_id")

    @enrollment_status_id.setter
    def enrollment_status_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "enrollment_status_id", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The enrollment status' current state.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter
    def status(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The Cloud Advisor enrollment status.
        """
        return pulumi.get(self, "status")

    @status.setter
    def status(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "status", value)

    @property
    @pulumi.getter(name="statusReason")
    def status_reason(self) -> Optional[pulumi.Input[str]]:
        """
        The reason for the enrollment status of the tenancy.
        """
        return pulumi.get(self, "status_reason")

    @status_reason.setter
    def status_reason(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "status_reason", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the enrollment status was created, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the enrollment status was last updated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class EnrollmentStatus(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 enrollment_status_id: Optional[pulumi.Input[str]] = None,
                 status: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Enrollment Status resource in Oracle Cloud Infrastructure Optimizer service.

        Updates the enrollment status of the tenancy.

        ## Import

        EnrollmentStatus can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:optimizer/enrollmentStatus:EnrollmentStatus test_enrollment_status "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] enrollment_status_id: The unique OCID associated with the enrollment status.
        :param pulumi.Input[str] status: (Updatable) The Cloud Advisor enrollment status.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: EnrollmentStatusArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Enrollment Status resource in Oracle Cloud Infrastructure Optimizer service.

        Updates the enrollment status of the tenancy.

        ## Import

        EnrollmentStatus can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:optimizer/enrollmentStatus:EnrollmentStatus test_enrollment_status "id"
        ```

        :param str resource_name: The name of the resource.
        :param EnrollmentStatusArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(EnrollmentStatusArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 enrollment_status_id: Optional[pulumi.Input[str]] = None,
                 status: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = EnrollmentStatusArgs.__new__(EnrollmentStatusArgs)

            if enrollment_status_id is None and not opts.urn:
                raise TypeError("Missing required property 'enrollment_status_id'")
            __props__.__dict__["enrollment_status_id"] = enrollment_status_id
            if status is None and not opts.urn:
                raise TypeError("Missing required property 'status'")
            __props__.__dict__["status"] = status
            __props__.__dict__["compartment_id"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["status_reason"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(EnrollmentStatus, __self__).__init__(
            'oci:optimizer/enrollmentStatus:EnrollmentStatus',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            enrollment_status_id: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            status: Optional[pulumi.Input[str]] = None,
            status_reason: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'EnrollmentStatus':
        """
        Get an existing EnrollmentStatus resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment.
        :param pulumi.Input[str] enrollment_status_id: The unique OCID associated with the enrollment status.
        :param pulumi.Input[str] state: The enrollment status' current state.
        :param pulumi.Input[str] status: (Updatable) The Cloud Advisor enrollment status.
        :param pulumi.Input[str] status_reason: The reason for the enrollment status of the tenancy.
        :param pulumi.Input[str] time_created: The date and time the enrollment status was created, in the format defined by RFC3339.
        :param pulumi.Input[str] time_updated: The date and time the enrollment status was last updated, in the format defined by RFC3339.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _EnrollmentStatusState.__new__(_EnrollmentStatusState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["enrollment_status_id"] = enrollment_status_id
        __props__.__dict__["state"] = state
        __props__.__dict__["status"] = status
        __props__.__dict__["status_reason"] = status_reason
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return EnrollmentStatus(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="enrollmentStatusId")
    def enrollment_status_id(self) -> pulumi.Output[str]:
        """
        The unique OCID associated with the enrollment status.
        """
        return pulumi.get(self, "enrollment_status_id")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The enrollment status' current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter
    def status(self) -> pulumi.Output[str]:
        """
        (Updatable) The Cloud Advisor enrollment status.
        """
        return pulumi.get(self, "status")

    @property
    @pulumi.getter(name="statusReason")
    def status_reason(self) -> pulumi.Output[str]:
        """
        The reason for the enrollment status of the tenancy.
        """
        return pulumi.get(self, "status_reason")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the enrollment status was created, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The date and time the enrollment status was last updated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_updated")

