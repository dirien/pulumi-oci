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

__all__ = ['AnalyticsClusterArgs', 'AnalyticsCluster']

@pulumi.input_type
class AnalyticsClusterArgs:
    def __init__(__self__, *,
                 cluster_size: pulumi.Input[int],
                 db_system_id: pulumi.Input[str],
                 shape_name: pulumi.Input[str],
                 state: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a AnalyticsCluster resource.
        :param pulumi.Input[int] cluster_size: (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] db_system_id: The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] shape_name: (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] state: (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        """
        pulumi.set(__self__, "cluster_size", cluster_size)
        pulumi.set(__self__, "db_system_id", db_system_id)
        pulumi.set(__self__, "shape_name", shape_name)
        if state is not None:
            pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="clusterSize")
    def cluster_size(self) -> pulumi.Input[int]:
        """
        (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        """
        return pulumi.get(self, "cluster_size")

    @cluster_size.setter
    def cluster_size(self, value: pulumi.Input[int]):
        pulumi.set(self, "cluster_size", value)

    @property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> pulumi.Input[str]:
        """
        The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "db_system_id")

    @db_system_id.setter
    def db_system_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "db_system_id", value)

    @property
    @pulumi.getter(name="shapeName")
    def shape_name(self) -> pulumi.Input[str]:
        """
        (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        """
        return pulumi.get(self, "shape_name")

    @shape_name.setter
    def shape_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "shape_name", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)


@pulumi.input_type
class _AnalyticsClusterState:
    def __init__(__self__, *,
                 cluster_nodes: Optional[pulumi.Input[Sequence[pulumi.Input['AnalyticsClusterClusterNodeArgs']]]] = None,
                 cluster_size: Optional[pulumi.Input[int]] = None,
                 db_system_id: Optional[pulumi.Input[str]] = None,
                 lifecycle_details: Optional[pulumi.Input[str]] = None,
                 shape_name: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering AnalyticsCluster resources.
        :param pulumi.Input[Sequence[pulumi.Input['AnalyticsClusterClusterNodeArgs']]] cluster_nodes: An Analytics Cluster Node is a compute host that is part of an Analytics Cluster.
        :param pulumi.Input[int] cluster_size: (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] db_system_id: The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] lifecycle_details: Additional information about the current lifecycleState.
        :param pulumi.Input[str] shape_name: (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] state: (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        :param pulumi.Input[str] time_created: The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        :param pulumi.Input[str] time_updated: The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        """
        if cluster_nodes is not None:
            pulumi.set(__self__, "cluster_nodes", cluster_nodes)
        if cluster_size is not None:
            pulumi.set(__self__, "cluster_size", cluster_size)
        if db_system_id is not None:
            pulumi.set(__self__, "db_system_id", db_system_id)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if shape_name is not None:
            pulumi.set(__self__, "shape_name", shape_name)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="clusterNodes")
    def cluster_nodes(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['AnalyticsClusterClusterNodeArgs']]]]:
        """
        An Analytics Cluster Node is a compute host that is part of an Analytics Cluster.
        """
        return pulumi.get(self, "cluster_nodes")

    @cluster_nodes.setter
    def cluster_nodes(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['AnalyticsClusterClusterNodeArgs']]]]):
        pulumi.set(self, "cluster_nodes", value)

    @property
    @pulumi.getter(name="clusterSize")
    def cluster_size(self) -> Optional[pulumi.Input[int]]:
        """
        (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        """
        return pulumi.get(self, "cluster_size")

    @cluster_size.setter
    def cluster_size(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "cluster_size", value)

    @property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> Optional[pulumi.Input[str]]:
        """
        The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "db_system_id")

    @db_system_id.setter
    def db_system_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "db_system_id", value)

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[str]]:
        """
        Additional information about the current lifecycleState.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_details", value)

    @property
    @pulumi.getter(name="shapeName")
    def shape_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        """
        return pulumi.get(self, "shape_name")

    @shape_name.setter
    def shape_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "shape_name", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class AnalyticsCluster(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cluster_size: Optional[pulumi.Input[int]] = None,
                 db_system_id: Optional[pulumi.Input[str]] = None,
                 shape_name: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Analytics Cluster resource in Oracle Cloud Infrastructure MySQL Database service.

        DEPRECATED -- please use HeatWave API instead.
        Updates the Analytics Cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_analytics_cluster = oci.mysql.AnalyticsCluster("testAnalyticsCluster",
            db_system_id=oci_database_db_system["test_db_system"]["id"],
            cluster_size=var["analytics_cluster_cluster_size"],
            shape_name=oci_mysql_shape["test_shape"]["name"])
        ```

        ## Import

        AnalyticsCluster can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:mysql/analyticsCluster:AnalyticsCluster test_analytics_cluster "dbSystems/{dbSystemId}/analyticsCluster"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[int] cluster_size: (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] db_system_id: The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] shape_name: (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] state: (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: AnalyticsClusterArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Analytics Cluster resource in Oracle Cloud Infrastructure MySQL Database service.

        DEPRECATED -- please use HeatWave API instead.
        Updates the Analytics Cluster.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_analytics_cluster = oci.mysql.AnalyticsCluster("testAnalyticsCluster",
            db_system_id=oci_database_db_system["test_db_system"]["id"],
            cluster_size=var["analytics_cluster_cluster_size"],
            shape_name=oci_mysql_shape["test_shape"]["name"])
        ```

        ## Import

        AnalyticsCluster can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:mysql/analyticsCluster:AnalyticsCluster test_analytics_cluster "dbSystems/{dbSystemId}/analyticsCluster"
        ```

        :param str resource_name: The name of the resource.
        :param AnalyticsClusterArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(AnalyticsClusterArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cluster_size: Optional[pulumi.Input[int]] = None,
                 db_system_id: Optional[pulumi.Input[str]] = None,
                 shape_name: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
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
            __props__ = AnalyticsClusterArgs.__new__(AnalyticsClusterArgs)

            if cluster_size is None and not opts.urn:
                raise TypeError("Missing required property 'cluster_size'")
            __props__.__dict__["cluster_size"] = cluster_size
            if db_system_id is None and not opts.urn:
                raise TypeError("Missing required property 'db_system_id'")
            __props__.__dict__["db_system_id"] = db_system_id
            if shape_name is None and not opts.urn:
                raise TypeError("Missing required property 'shape_name'")
            __props__.__dict__["shape_name"] = shape_name
            __props__.__dict__["state"] = state
            __props__.__dict__["cluster_nodes"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(AnalyticsCluster, __self__).__init__(
            'oci:mysql/analyticsCluster:AnalyticsCluster',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            cluster_nodes: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['AnalyticsClusterClusterNodeArgs']]]]] = None,
            cluster_size: Optional[pulumi.Input[int]] = None,
            db_system_id: Optional[pulumi.Input[str]] = None,
            lifecycle_details: Optional[pulumi.Input[str]] = None,
            shape_name: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'AnalyticsCluster':
        """
        Get an existing AnalyticsCluster resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['AnalyticsClusterClusterNodeArgs']]]] cluster_nodes: An Analytics Cluster Node is a compute host that is part of an Analytics Cluster.
        :param pulumi.Input[int] cluster_size: (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] db_system_id: The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] lifecycle_details: Additional information about the current lifecycleState.
        :param pulumi.Input[str] shape_name: (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        :param pulumi.Input[str] state: (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        :param pulumi.Input[str] time_created: The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        :param pulumi.Input[str] time_updated: The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _AnalyticsClusterState.__new__(_AnalyticsClusterState)

        __props__.__dict__["cluster_nodes"] = cluster_nodes
        __props__.__dict__["cluster_size"] = cluster_size
        __props__.__dict__["db_system_id"] = db_system_id
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["shape_name"] = shape_name
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return AnalyticsCluster(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="clusterNodes")
    def cluster_nodes(self) -> pulumi.Output[Sequence['outputs.AnalyticsClusterClusterNode']]:
        """
        An Analytics Cluster Node is a compute host that is part of an Analytics Cluster.
        """
        return pulumi.get(self, "cluster_nodes")

    @property
    @pulumi.getter(name="clusterSize")
    def cluster_size(self) -> pulumi.Output[int]:
        """
        (Updatable) A change to the number of nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with the new cluster of nodes. This may result in a significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        """
        return pulumi.get(self, "cluster_size")

    @property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> pulumi.Output[str]:
        """
        The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "db_system_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[str]:
        """
        Additional information about the current lifecycleState.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="shapeName")
    def shape_name(self) -> pulumi.Output[str]:
        """
        (Updatable) A change to the shape of the nodes in the Analytics Cluster will result in the entire cluster being torn down and re-created with Compute instances of the new Shape. This may result in significant downtime for the analytics capability while the Analytics Cluster is re-provisioned.
        """
        return pulumi.get(self, "shape_name")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        (Updatable) The target state for the Analytics Cluster. Could be set to `ACTIVE` or `INACTIVE`.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the Analytics Cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The time the Analytics Cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
        """
        return pulumi.get(self, "time_updated")

