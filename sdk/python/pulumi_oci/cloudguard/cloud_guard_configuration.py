# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['CloudGuardConfigurationArgs', 'CloudGuardConfiguration']

@pulumi.input_type
class CloudGuardConfigurationArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 reporting_region: pulumi.Input[str],
                 status: pulumi.Input[str],
                 self_manage_resources: Optional[pulumi.Input[bool]] = None):
        """
        The set of arguments for constructing a CloudGuardConfiguration resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The ID of the compartment in which to list resources.
        :param pulumi.Input[str] reporting_region: (Updatable) The reporting region value
        :param pulumi.Input[str] status: (Updatable) Status of Cloud Guard Tenant
        :param pulumi.Input[bool] self_manage_resources: (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "reporting_region", reporting_region)
        pulumi.set(__self__, "status", status)
        if self_manage_resources is not None:
            pulumi.set(__self__, "self_manage_resources", self_manage_resources)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="reportingRegion")
    def reporting_region(self) -> pulumi.Input[str]:
        """
        (Updatable) The reporting region value
        """
        return pulumi.get(self, "reporting_region")

    @reporting_region.setter
    def reporting_region(self, value: pulumi.Input[str]):
        pulumi.set(self, "reporting_region", value)

    @property
    @pulumi.getter
    def status(self) -> pulumi.Input[str]:
        """
        (Updatable) Status of Cloud Guard Tenant
        """
        return pulumi.get(self, "status")

    @status.setter
    def status(self, value: pulumi.Input[str]):
        pulumi.set(self, "status", value)

    @property
    @pulumi.getter(name="selfManageResources")
    def self_manage_resources(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        """
        return pulumi.get(self, "self_manage_resources")

    @self_manage_resources.setter
    def self_manage_resources(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "self_manage_resources", value)


@pulumi.input_type
class _CloudGuardConfigurationState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 reporting_region: Optional[pulumi.Input[str]] = None,
                 self_manage_resources: Optional[pulumi.Input[bool]] = None,
                 status: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering CloudGuardConfiguration resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The ID of the compartment in which to list resources.
        :param pulumi.Input[str] reporting_region: (Updatable) The reporting region value
        :param pulumi.Input[bool] self_manage_resources: (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        :param pulumi.Input[str] status: (Updatable) Status of Cloud Guard Tenant
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if reporting_region is not None:
            pulumi.set(__self__, "reporting_region", reporting_region)
        if self_manage_resources is not None:
            pulumi.set(__self__, "self_manage_resources", self_manage_resources)
        if status is not None:
            pulumi.set(__self__, "status", status)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="reportingRegion")
    def reporting_region(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The reporting region value
        """
        return pulumi.get(self, "reporting_region")

    @reporting_region.setter
    def reporting_region(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "reporting_region", value)

    @property
    @pulumi.getter(name="selfManageResources")
    def self_manage_resources(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        """
        return pulumi.get(self, "self_manage_resources")

    @self_manage_resources.setter
    def self_manage_resources(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "self_manage_resources", value)

    @property
    @pulumi.getter
    def status(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Status of Cloud Guard Tenant
        """
        return pulumi.get(self, "status")

    @status.setter
    def status(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "status", value)


class CloudGuardConfiguration(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 reporting_region: Optional[pulumi.Input[str]] = None,
                 self_manage_resources: Optional[pulumi.Input[bool]] = None,
                 status: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Cloud Guard Configuration resource in Oracle Cloud Infrastructure Cloud Guard service.

        Enable/Disable Cloud Guard. The reporting region cannot be updated once created.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_cloud_guard_configuration = oci.cloudguard.CloudGuardConfiguration("testCloudGuardConfiguration",
            compartment_id=var["compartment_id"],
            reporting_region=var["cloud_guard_configuration_reporting_region"],
            status=var["cloud_guard_configuration_status"],
            self_manage_resources=var["cloud_guard_configuration_self_manage_resources"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The ID of the compartment in which to list resources.
        :param pulumi.Input[str] reporting_region: (Updatable) The reporting region value
        :param pulumi.Input[bool] self_manage_resources: (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        :param pulumi.Input[str] status: (Updatable) Status of Cloud Guard Tenant
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CloudGuardConfigurationArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Cloud Guard Configuration resource in Oracle Cloud Infrastructure Cloud Guard service.

        Enable/Disable Cloud Guard. The reporting region cannot be updated once created.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_cloud_guard_configuration = oci.cloudguard.CloudGuardConfiguration("testCloudGuardConfiguration",
            compartment_id=var["compartment_id"],
            reporting_region=var["cloud_guard_configuration_reporting_region"],
            status=var["cloud_guard_configuration_status"],
            self_manage_resources=var["cloud_guard_configuration_self_manage_resources"])
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param CloudGuardConfigurationArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CloudGuardConfigurationArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 reporting_region: Optional[pulumi.Input[str]] = None,
                 self_manage_resources: Optional[pulumi.Input[bool]] = None,
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
            __props__ = CloudGuardConfigurationArgs.__new__(CloudGuardConfigurationArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if reporting_region is None and not opts.urn:
                raise TypeError("Missing required property 'reporting_region'")
            __props__.__dict__["reporting_region"] = reporting_region
            __props__.__dict__["self_manage_resources"] = self_manage_resources
            if status is None and not opts.urn:
                raise TypeError("Missing required property 'status'")
            __props__.__dict__["status"] = status
        super(CloudGuardConfiguration, __self__).__init__(
            'oci:cloudguard/cloudGuardConfiguration:CloudGuardConfiguration',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            reporting_region: Optional[pulumi.Input[str]] = None,
            self_manage_resources: Optional[pulumi.Input[bool]] = None,
            status: Optional[pulumi.Input[str]] = None) -> 'CloudGuardConfiguration':
        """
        Get an existing CloudGuardConfiguration resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The ID of the compartment in which to list resources.
        :param pulumi.Input[str] reporting_region: (Updatable) The reporting region value
        :param pulumi.Input[bool] self_manage_resources: (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        :param pulumi.Input[str] status: (Updatable) Status of Cloud Guard Tenant
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _CloudGuardConfigurationState.__new__(_CloudGuardConfigurationState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["reporting_region"] = reporting_region
        __props__.__dict__["self_manage_resources"] = self_manage_resources
        __props__.__dict__["status"] = status
        return CloudGuardConfiguration(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="reportingRegion")
    def reporting_region(self) -> pulumi.Output[str]:
        """
        (Updatable) The reporting region value
        """
        return pulumi.get(self, "reporting_region")

    @property
    @pulumi.getter(name="selfManageResources")
    def self_manage_resources(self) -> pulumi.Output[bool]:
        """
        (Updatable) Identifies if Oracle managed resources will be created by customers. If no value is specified false is the default.
        """
        return pulumi.get(self, "self_manage_resources")

    @property
    @pulumi.getter
    def status(self) -> pulumi.Output[str]:
        """
        (Updatable) Status of Cloud Guard Tenant
        """
        return pulumi.get(self, "status")
