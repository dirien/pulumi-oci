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
    'GetReplicationSourcesResult',
    'AwaitableGetReplicationSourcesResult',
    'get_replication_sources',
]

@pulumi.output_type
class GetReplicationSourcesResult:
    """
    A collection of values returned by getReplicationSources.
    """
    def __init__(__self__, bucket=None, filters=None, id=None, namespace=None, replication_sources=None):
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if replication_sources and not isinstance(replication_sources, list):
            raise TypeError("Expected argument 'replication_sources' to be a list")
        pulumi.set(__self__, "replication_sources", replication_sources)

    @property
    @pulumi.getter
    def bucket(self) -> str:
        return pulumi.get(self, "bucket")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetReplicationSourcesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def namespace(self) -> str:
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter(name="replicationSources")
    def replication_sources(self) -> Sequence['outputs.GetReplicationSourcesReplicationSourceResult']:
        """
        The list of replication_sources.
        """
        return pulumi.get(self, "replication_sources")


class AwaitableGetReplicationSourcesResult(GetReplicationSourcesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetReplicationSourcesResult(
            bucket=self.bucket,
            filters=self.filters,
            id=self.id,
            namespace=self.namespace,
            replication_sources=self.replication_sources)


def get_replication_sources(bucket: Optional[str] = None,
                            filters: Optional[Sequence[pulumi.InputType['GetReplicationSourcesFilterArgs']]] = None,
                            namespace: Optional[str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetReplicationSourcesResult:
    """
    This data source provides the list of Replication Sources in Oracle Cloud Infrastructure Object Storage service.

    List the replication sources of a destination bucket.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_replication_sources = oci.objectstorage.get_replication_sources(bucket=var["replication_source_bucket"],
        namespace=var["replication_source_namespace"])
    ```


    :param str bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
    :param str namespace: The Object Storage namespace used for the request.
    """
    __args__ = dict()
    __args__['bucket'] = bucket
    __args__['filters'] = filters
    __args__['namespace'] = namespace
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:objectstorage/getReplicationSources:getReplicationSources', __args__, opts=opts, typ=GetReplicationSourcesResult).value

    return AwaitableGetReplicationSourcesResult(
        bucket=__ret__.bucket,
        filters=__ret__.filters,
        id=__ret__.id,
        namespace=__ret__.namespace,
        replication_sources=__ret__.replication_sources)
