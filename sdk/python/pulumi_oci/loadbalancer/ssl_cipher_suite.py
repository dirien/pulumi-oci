# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['SslCipherSuiteArgs', 'SslCipherSuite']

@pulumi.input_type
class SslCipherSuiteArgs:
    def __init__(__self__, *,
                 ciphers: pulumi.Input[Sequence[pulumi.Input[str]]],
                 load_balancer_id: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a SslCipherSuite resource.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] ciphers: A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        :param pulumi.Input[str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        :param pulumi.Input[str] name: A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        pulumi.set(__self__, "ciphers", ciphers)
        if load_balancer_id is not None:
            pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def ciphers(self) -> pulumi.Input[Sequence[pulumi.Input[str]]]:
        """
        A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        """
        return pulumi.get(self, "ciphers")

    @ciphers.setter
    def ciphers(self, value: pulumi.Input[Sequence[pulumi.Input[str]]]):
        pulumi.set(self, "ciphers", value)

    @property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        """
        return pulumi.get(self, "load_balancer_id")

    @load_balancer_id.setter
    def load_balancer_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "load_balancer_id", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class _SslCipherSuiteState:
    def __init__(__self__, *,
                 ciphers: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 load_balancer_id: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering SslCipherSuite resources.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] ciphers: A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        :param pulumi.Input[str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        :param pulumi.Input[str] name: A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        if ciphers is not None:
            pulumi.set(__self__, "ciphers", ciphers)
        if load_balancer_id is not None:
            pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if state is not None:
            pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter
    def ciphers(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        """
        return pulumi.get(self, "ciphers")

    @ciphers.setter
    def ciphers(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "ciphers", value)

    @property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        """
        return pulumi.get(self, "load_balancer_id")

    @load_balancer_id.setter
    def load_balancer_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "load_balancer_id", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)


class SslCipherSuite(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 ciphers: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 load_balancer_id: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Ssl Cipher Suite resource in Oracle Cloud Infrastructure Load Balancer service.

        Creates a custom SSL cipher suite.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_ssl_cipher_suite = oci.loadbalancer.SslCipherSuite("testSslCipherSuite",
            ciphers=var["ssl_cipher_suite_ciphers"],
            load_balancer_id=oci_load_balancer_load_balancer["test_load_balancer"]["id"])
        ```

        ## Import

        SslCipherSuites can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:loadbalancer/sslCipherSuite:SslCipherSuite test_ssl_cipher_suite "loadBalancers/{loadBalancerId}/sslCipherSuites/{name}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] ciphers: A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        :param pulumi.Input[str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        :param pulumi.Input[str] name: A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: SslCipherSuiteArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Ssl Cipher Suite resource in Oracle Cloud Infrastructure Load Balancer service.

        Creates a custom SSL cipher suite.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_ssl_cipher_suite = oci.loadbalancer.SslCipherSuite("testSslCipherSuite",
            ciphers=var["ssl_cipher_suite_ciphers"],
            load_balancer_id=oci_load_balancer_load_balancer["test_load_balancer"]["id"])
        ```

        ## Import

        SslCipherSuites can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:loadbalancer/sslCipherSuite:SslCipherSuite test_ssl_cipher_suite "loadBalancers/{loadBalancerId}/sslCipherSuites/{name}"
        ```

        :param str resource_name: The name of the resource.
        :param SslCipherSuiteArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(SslCipherSuiteArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 ciphers: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 load_balancer_id: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
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
            __props__ = SslCipherSuiteArgs.__new__(SslCipherSuiteArgs)

            if ciphers is None and not opts.urn:
                raise TypeError("Missing required property 'ciphers'")
            __props__.__dict__["ciphers"] = ciphers
            __props__.__dict__["load_balancer_id"] = load_balancer_id
            __props__.__dict__["name"] = name
            __props__.__dict__["state"] = None
        super(SslCipherSuite, __self__).__init__(
            'oci:loadbalancer/sslCipherSuite:SslCipherSuite',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            ciphers: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            load_balancer_id: Optional[pulumi.Input[str]] = None,
            name: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None) -> 'SslCipherSuite':
        """
        Get an existing SslCipherSuite resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] ciphers: A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        :param pulumi.Input[str] load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        :param pulumi.Input[str] name: A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _SslCipherSuiteState.__new__(_SslCipherSuiteState)

        __props__.__dict__["ciphers"] = ciphers
        __props__.__dict__["load_balancer_id"] = load_balancer_id
        __props__.__dict__["name"] = name
        __props__.__dict__["state"] = state
        return SslCipherSuite(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def ciphers(self) -> pulumi.Output[Sequence[str]]:
        """
        A list of SSL ciphers the load balancer must support for HTTPS or SSL connections.
        """
        return pulumi.get(self, "ciphers")

    @property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        """
        return pulumi.get(self, "load_balancer_id")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        return pulumi.get(self, "state")

