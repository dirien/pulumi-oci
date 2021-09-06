# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['AutonomousContainerDatabaseDataguardAssociationOperationArgs', 'AutonomousContainerDatabaseDataguardAssociationOperation']

@pulumi.input_type
class AutonomousContainerDatabaseDataguardAssociationOperationArgs:
    def __init__(__self__, *,
                 autonomous_container_database_dataguard_association_id: pulumi.Input[str],
                 autonomous_container_database_id: pulumi.Input[str],
                 operation: pulumi.Input[str]):
        """
        The set of arguments for constructing a AutonomousContainerDatabaseDataguardAssociationOperation resource.
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] operation: There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        pulumi.set(__self__, "autonomous_container_database_dataguard_association_id", autonomous_container_database_dataguard_association_id)
        pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        pulumi.set(__self__, "operation", operation)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociationId")
    def autonomous_container_database_dataguard_association_id(self) -> pulumi.Input[str]:
        """
        The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_association_id")

    @autonomous_container_database_dataguard_association_id.setter
    def autonomous_container_database_dataguard_association_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "autonomous_container_database_dataguard_association_id", value)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> pulumi.Input[str]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @autonomous_container_database_id.setter
    def autonomous_container_database_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "autonomous_container_database_id", value)

    @property
    @pulumi.getter
    def operation(self) -> pulumi.Input[str]:
        """
        There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "operation")

    @operation.setter
    def operation(self, value: pulumi.Input[str]):
        pulumi.set(self, "operation", value)


@pulumi.input_type
class _AutonomousContainerDatabaseDataguardAssociationOperationState:
    def __init__(__self__, *,
                 autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 operation: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering AutonomousContainerDatabaseDataguardAssociationOperation resources.
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] operation: There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        if autonomous_container_database_dataguard_association_id is not None:
            pulumi.set(__self__, "autonomous_container_database_dataguard_association_id", autonomous_container_database_dataguard_association_id)
        if autonomous_container_database_id is not None:
            pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if operation is not None:
            pulumi.set(__self__, "operation", operation)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociationId")
    def autonomous_container_database_dataguard_association_id(self) -> Optional[pulumi.Input[str]]:
        """
        The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_association_id")

    @autonomous_container_database_dataguard_association_id.setter
    def autonomous_container_database_dataguard_association_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "autonomous_container_database_dataguard_association_id", value)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> Optional[pulumi.Input[str]]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @autonomous_container_database_id.setter
    def autonomous_container_database_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "autonomous_container_database_id", value)

    @property
    @pulumi.getter
    def operation(self) -> Optional[pulumi.Input[str]]:
        """
        There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "operation")

    @operation.setter
    def operation(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "operation", value)


class AutonomousContainerDatabaseDataguardAssociationOperation(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 operation: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Autonomous Container Database Dataguard Association Operation resource in Oracle Cloud Infrastructure Database service.

        Perform a new Autonomous Container Database Dataguard Association Operation on an Autonomous Container Database that has Dataguard enabled

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        switchover = oci.database.AutonomousContainerDatabaseDataguardAssociationOperation("switchover",
            operation="switchover",
            autonomous_container_database_id=data["oci_database_autonomous_container_database_dataguard_associations"]["dataguard_associations"]["autonomous_container_database_dataguard_associations"][0]["autonomous_container_database_id"],
            autonomous_container_database_dataguard_association_id=data["oci_database_autonomous_container_database_dataguard_associations"]["dataguard_associations"]["autonomous_container_database_dataguard_associations"][0]["id"])
        ```

        ## Import

        AutonomousContainerDatabaseDataguardAssociationOperation does not support import.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] operation: There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: AutonomousContainerDatabaseDataguardAssociationOperationArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Autonomous Container Database Dataguard Association Operation resource in Oracle Cloud Infrastructure Database service.

        Perform a new Autonomous Container Database Dataguard Association Operation on an Autonomous Container Database that has Dataguard enabled

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        switchover = oci.database.AutonomousContainerDatabaseDataguardAssociationOperation("switchover",
            operation="switchover",
            autonomous_container_database_id=data["oci_database_autonomous_container_database_dataguard_associations"]["dataguard_associations"]["autonomous_container_database_dataguard_associations"][0]["autonomous_container_database_id"],
            autonomous_container_database_dataguard_association_id=data["oci_database_autonomous_container_database_dataguard_associations"]["dataguard_associations"]["autonomous_container_database_dataguard_associations"][0]["id"])
        ```

        ## Import

        AutonomousContainerDatabaseDataguardAssociationOperation does not support import.

        :param str resource_name: The name of the resource.
        :param AutonomousContainerDatabaseDataguardAssociationOperationArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(AutonomousContainerDatabaseDataguardAssociationOperationArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 operation: Optional[pulumi.Input[str]] = None,
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
            __props__ = AutonomousContainerDatabaseDataguardAssociationOperationArgs.__new__(AutonomousContainerDatabaseDataguardAssociationOperationArgs)

            if autonomous_container_database_dataguard_association_id is None and not opts.urn:
                raise TypeError("Missing required property 'autonomous_container_database_dataguard_association_id'")
            __props__.__dict__["autonomous_container_database_dataguard_association_id"] = autonomous_container_database_dataguard_association_id
            if autonomous_container_database_id is None and not opts.urn:
                raise TypeError("Missing required property 'autonomous_container_database_id'")
            __props__.__dict__["autonomous_container_database_id"] = autonomous_container_database_id
            if operation is None and not opts.urn:
                raise TypeError("Missing required property 'operation'")
            __props__.__dict__["operation"] = operation
        super(AutonomousContainerDatabaseDataguardAssociationOperation, __self__).__init__(
            'oci:database/autonomousContainerDatabaseDataguardAssociationOperation:AutonomousContainerDatabaseDataguardAssociationOperation',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
            autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
            operation: Optional[pulumi.Input[str]] = None) -> 'AutonomousContainerDatabaseDataguardAssociationOperation':
        """
        Get an existing AutonomousContainerDatabaseDataguardAssociationOperation resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        :param pulumi.Input[str] operation: There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _AutonomousContainerDatabaseDataguardAssociationOperationState.__new__(_AutonomousContainerDatabaseDataguardAssociationOperationState)

        __props__.__dict__["autonomous_container_database_dataguard_association_id"] = autonomous_container_database_dataguard_association_id
        __props__.__dict__["autonomous_container_database_id"] = autonomous_container_database_id
        __props__.__dict__["operation"] = operation
        return AutonomousContainerDatabaseDataguardAssociationOperation(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociationId")
    def autonomous_container_database_dataguard_association_id(self) -> pulumi.Output[str]:
        """
        The Autonomous Container Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_association_id")

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> pulumi.Output[str]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @property
    @pulumi.getter
    def operation(self) -> pulumi.Output[str]:
        """
        There are three type of supported operations `switchover`, `failover`, `reinstate`. `switchover` can only be used for primary database while `failover` and `reinstate` can only be used for standby database. This attribute is a forcenew attribute.
        """
        return pulumi.get(self, "operation")

