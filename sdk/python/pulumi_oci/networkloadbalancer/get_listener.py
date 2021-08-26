# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetListenerResult',
    'AwaitableGetListenerResult',
    'get_listener',
]

@pulumi.output_type
class GetListenerResult:
    """
    A collection of values returned by getListener.
    """
    def __init__(__self__, default_backend_set_name=None, id=None, listener_name=None, name=None, network_load_balancer_id=None, port=None, protocol=None):
        if default_backend_set_name and not isinstance(default_backend_set_name, str):
            raise TypeError("Expected argument 'default_backend_set_name' to be a str")
        pulumi.set(__self__, "default_backend_set_name", default_backend_set_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if listener_name and not isinstance(listener_name, str):
            raise TypeError("Expected argument 'listener_name' to be a str")
        pulumi.set(__self__, "listener_name", listener_name)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if network_load_balancer_id and not isinstance(network_load_balancer_id, str):
            raise TypeError("Expected argument 'network_load_balancer_id' to be a str")
        pulumi.set(__self__, "network_load_balancer_id", network_load_balancer_id)
        if port and not isinstance(port, int):
            raise TypeError("Expected argument 'port' to be a int")
        pulumi.set(__self__, "port", port)
        if protocol and not isinstance(protocol, str):
            raise TypeError("Expected argument 'protocol' to be a str")
        pulumi.set(__self__, "protocol", protocol)

    @property
    @pulumi.getter(name="defaultBackendSetName")
    def default_backend_set_name(self) -> str:
        """
        The name of the associated backend set.  Example: `example_backend_set`
        """
        return pulumi.get(self, "default_backend_set_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="listenerName")
    def listener_name(self) -> str:
        return pulumi.get(self, "listener_name")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="networkLoadBalancerId")
    def network_load_balancer_id(self) -> str:
        return pulumi.get(self, "network_load_balancer_id")

    @property
    @pulumi.getter
    def port(self) -> int:
        """
        The communication port for the listener.  Example: `80`
        """
        return pulumi.get(self, "port")

    @property
    @pulumi.getter
    def protocol(self) -> str:
        """
        The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). To get a list of valid protocols, use the [ListNetworkLoadBalancersProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/NetworkLoadBalancer/20200501/networkLoadBalancerProtocol/ListNetworkLoadBalancersProtocols) operation.  Example: `TCP`
        """
        return pulumi.get(self, "protocol")


class AwaitableGetListenerResult(GetListenerResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetListenerResult(
            default_backend_set_name=self.default_backend_set_name,
            id=self.id,
            listener_name=self.listener_name,
            name=self.name,
            network_load_balancer_id=self.network_load_balancer_id,
            port=self.port,
            protocol=self.protocol)


def get_listener(listener_name: Optional[str] = None,
                 network_load_balancer_id: Optional[str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetListenerResult:
    """
    This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves listener properties associated with a given network load balancer and listener name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_listener = oci.networkloadbalancer.get_listener(listener_name=oci_network_load_balancer_listener["test_listener"]["name"],
        network_load_balancer_id=oci_network_load_balancer_network_load_balancer["test_network_load_balancer"]["id"])
    ```


    :param str listener_name: The name of the listener to get.  Example: `example_listener`
    :param str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['listenerName'] = listener_name
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:networkloadbalancer/getListener:getListener', __args__, opts=opts, typ=GetListenerResult).value

    return AwaitableGetListenerResult(
        default_backend_set_name=__ret__.default_backend_set_name,
        id=__ret__.id,
        listener_name=__ret__.listener_name,
        name=__ret__.name,
        network_load_balancer_id=__ret__.network_load_balancer_id,
        port=__ret__.port,
        protocol=__ret__.protocol)
