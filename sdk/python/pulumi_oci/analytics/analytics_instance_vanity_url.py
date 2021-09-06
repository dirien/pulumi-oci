# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['AnalyticsInstanceVanityUrlArgs', 'AnalyticsInstanceVanityUrl']

@pulumi.input_type
class AnalyticsInstanceVanityUrlArgs:
    def __init__(__self__, *,
                 analytics_instance_id: pulumi.Input[str],
                 ca_certificate: pulumi.Input[str],
                 hosts: pulumi.Input[Sequence[pulumi.Input[str]]],
                 private_key: pulumi.Input[str],
                 public_certificate: pulumi.Input[str],
                 description: Optional[pulumi.Input[str]] = None,
                 passphrase: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a AnalyticsInstanceVanityUrl resource.
        :param pulumi.Input[str] analytics_instance_id: The OCID of the AnalyticsInstance.
        :param pulumi.Input[str] ca_certificate: (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        :param pulumi.Input[str] private_key: (Updatable) PEM Private key for HTTPS connections.
        :param pulumi.Input[str] public_certificate: (Updatable) PEM certificate for HTTPS connections.
        :param pulumi.Input[str] description: Optional description.
        :param pulumi.Input[str] passphrase: (Updatable) Passphrase for the PEM Private key (if any).
        """
        pulumi.set(__self__, "analytics_instance_id", analytics_instance_id)
        pulumi.set(__self__, "ca_certificate", ca_certificate)
        pulumi.set(__self__, "hosts", hosts)
        pulumi.set(__self__, "private_key", private_key)
        pulumi.set(__self__, "public_certificate", public_certificate)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if passphrase is not None:
            pulumi.set(__self__, "passphrase", passphrase)

    @property
    @pulumi.getter(name="analyticsInstanceId")
    def analytics_instance_id(self) -> pulumi.Input[str]:
        """
        The OCID of the AnalyticsInstance.
        """
        return pulumi.get(self, "analytics_instance_id")

    @analytics_instance_id.setter
    def analytics_instance_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "analytics_instance_id", value)

    @property
    @pulumi.getter(name="caCertificate")
    def ca_certificate(self) -> pulumi.Input[str]:
        """
        (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        """
        return pulumi.get(self, "ca_certificate")

    @ca_certificate.setter
    def ca_certificate(self, value: pulumi.Input[str]):
        pulumi.set(self, "ca_certificate", value)

    @property
    @pulumi.getter
    def hosts(self) -> pulumi.Input[Sequence[pulumi.Input[str]]]:
        """
        List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        """
        return pulumi.get(self, "hosts")

    @hosts.setter
    def hosts(self, value: pulumi.Input[Sequence[pulumi.Input[str]]]):
        pulumi.set(self, "hosts", value)

    @property
    @pulumi.getter(name="privateKey")
    def private_key(self) -> pulumi.Input[str]:
        """
        (Updatable) PEM Private key for HTTPS connections.
        """
        return pulumi.get(self, "private_key")

    @private_key.setter
    def private_key(self, value: pulumi.Input[str]):
        pulumi.set(self, "private_key", value)

    @property
    @pulumi.getter(name="publicCertificate")
    def public_certificate(self) -> pulumi.Input[str]:
        """
        (Updatable) PEM certificate for HTTPS connections.
        """
        return pulumi.get(self, "public_certificate")

    @public_certificate.setter
    def public_certificate(self, value: pulumi.Input[str]):
        pulumi.set(self, "public_certificate", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        Optional description.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter
    def passphrase(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Passphrase for the PEM Private key (if any).
        """
        return pulumi.get(self, "passphrase")

    @passphrase.setter
    def passphrase(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "passphrase", value)


@pulumi.input_type
class _AnalyticsInstanceVanityUrlState:
    def __init__(__self__, *,
                 analytics_instance_id: Optional[pulumi.Input[str]] = None,
                 ca_certificate: Optional[pulumi.Input[str]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 passphrase: Optional[pulumi.Input[str]] = None,
                 private_key: Optional[pulumi.Input[str]] = None,
                 public_certificate: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering AnalyticsInstanceVanityUrl resources.
        :param pulumi.Input[str] analytics_instance_id: The OCID of the AnalyticsInstance.
        :param pulumi.Input[str] ca_certificate: (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        :param pulumi.Input[str] description: Optional description.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        :param pulumi.Input[str] passphrase: (Updatable) Passphrase for the PEM Private key (if any).
        :param pulumi.Input[str] private_key: (Updatable) PEM Private key for HTTPS connections.
        :param pulumi.Input[str] public_certificate: (Updatable) PEM certificate for HTTPS connections.
        """
        if analytics_instance_id is not None:
            pulumi.set(__self__, "analytics_instance_id", analytics_instance_id)
        if ca_certificate is not None:
            pulumi.set(__self__, "ca_certificate", ca_certificate)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if hosts is not None:
            pulumi.set(__self__, "hosts", hosts)
        if passphrase is not None:
            pulumi.set(__self__, "passphrase", passphrase)
        if private_key is not None:
            pulumi.set(__self__, "private_key", private_key)
        if public_certificate is not None:
            pulumi.set(__self__, "public_certificate", public_certificate)

    @property
    @pulumi.getter(name="analyticsInstanceId")
    def analytics_instance_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the AnalyticsInstance.
        """
        return pulumi.get(self, "analytics_instance_id")

    @analytics_instance_id.setter
    def analytics_instance_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "analytics_instance_id", value)

    @property
    @pulumi.getter(name="caCertificate")
    def ca_certificate(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        """
        return pulumi.get(self, "ca_certificate")

    @ca_certificate.setter
    def ca_certificate(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "ca_certificate", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        Optional description.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter
    def hosts(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        """
        return pulumi.get(self, "hosts")

    @hosts.setter
    def hosts(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "hosts", value)

    @property
    @pulumi.getter
    def passphrase(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Passphrase for the PEM Private key (if any).
        """
        return pulumi.get(self, "passphrase")

    @passphrase.setter
    def passphrase(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "passphrase", value)

    @property
    @pulumi.getter(name="privateKey")
    def private_key(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) PEM Private key for HTTPS connections.
        """
        return pulumi.get(self, "private_key")

    @private_key.setter
    def private_key(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "private_key", value)

    @property
    @pulumi.getter(name="publicCertificate")
    def public_certificate(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) PEM certificate for HTTPS connections.
        """
        return pulumi.get(self, "public_certificate")

    @public_certificate.setter
    def public_certificate(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "public_certificate", value)


class AnalyticsInstanceVanityUrl(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 analytics_instance_id: Optional[pulumi.Input[str]] = None,
                 ca_certificate: Optional[pulumi.Input[str]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 passphrase: Optional[pulumi.Input[str]] = None,
                 private_key: Optional[pulumi.Input[str]] = None,
                 public_certificate: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Analytics Instance Vanity Url resource in Oracle Cloud Infrastructure Analytics service.

        Allows specifying a custom host name to be used to access the analytics instance.  This requires prior setup of DNS entry and certificate
        for this host.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_analytics_instance_vanity_url = oci.analytics.AnalyticsInstanceVanityUrl("testAnalyticsInstanceVanityUrl",
            analytics_instance_id=oci_analytics_analytics_instance["test_analytics_instance"]["id"],
            ca_certificate=var["analytics_instance_vanity_url_ca_certificate"],
            hosts=var["analytics_instance_vanity_url_hosts"],
            private_key=var["analytics_instance_vanity_url_private_key"],
            public_certificate=var["analytics_instance_vanity_url_public_certificate"],
            description=var["analytics_instance_vanity_url_description"],
            passphrase=var["analytics_instance_vanity_url_passphrase"])
        ```

        ## Import

        AnalyticsInstanceVanityUrls can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl test_analytics_instance_vanity_url "analyticsInstances/{analyticsInstanceId}/vanityUrls/{vanityUrlKey}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] analytics_instance_id: The OCID of the AnalyticsInstance.
        :param pulumi.Input[str] ca_certificate: (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        :param pulumi.Input[str] description: Optional description.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        :param pulumi.Input[str] passphrase: (Updatable) Passphrase for the PEM Private key (if any).
        :param pulumi.Input[str] private_key: (Updatable) PEM Private key for HTTPS connections.
        :param pulumi.Input[str] public_certificate: (Updatable) PEM certificate for HTTPS connections.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: AnalyticsInstanceVanityUrlArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Analytics Instance Vanity Url resource in Oracle Cloud Infrastructure Analytics service.

        Allows specifying a custom host name to be used to access the analytics instance.  This requires prior setup of DNS entry and certificate
        for this host.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_analytics_instance_vanity_url = oci.analytics.AnalyticsInstanceVanityUrl("testAnalyticsInstanceVanityUrl",
            analytics_instance_id=oci_analytics_analytics_instance["test_analytics_instance"]["id"],
            ca_certificate=var["analytics_instance_vanity_url_ca_certificate"],
            hosts=var["analytics_instance_vanity_url_hosts"],
            private_key=var["analytics_instance_vanity_url_private_key"],
            public_certificate=var["analytics_instance_vanity_url_public_certificate"],
            description=var["analytics_instance_vanity_url_description"],
            passphrase=var["analytics_instance_vanity_url_passphrase"])
        ```

        ## Import

        AnalyticsInstanceVanityUrls can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl test_analytics_instance_vanity_url "analyticsInstances/{analyticsInstanceId}/vanityUrls/{vanityUrlKey}"
        ```

        :param str resource_name: The name of the resource.
        :param AnalyticsInstanceVanityUrlArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(AnalyticsInstanceVanityUrlArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 analytics_instance_id: Optional[pulumi.Input[str]] = None,
                 ca_certificate: Optional[pulumi.Input[str]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 passphrase: Optional[pulumi.Input[str]] = None,
                 private_key: Optional[pulumi.Input[str]] = None,
                 public_certificate: Optional[pulumi.Input[str]] = None,
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
            __props__ = AnalyticsInstanceVanityUrlArgs.__new__(AnalyticsInstanceVanityUrlArgs)

            if analytics_instance_id is None and not opts.urn:
                raise TypeError("Missing required property 'analytics_instance_id'")
            __props__.__dict__["analytics_instance_id"] = analytics_instance_id
            if ca_certificate is None and not opts.urn:
                raise TypeError("Missing required property 'ca_certificate'")
            __props__.__dict__["ca_certificate"] = ca_certificate
            __props__.__dict__["description"] = description
            if hosts is None and not opts.urn:
                raise TypeError("Missing required property 'hosts'")
            __props__.__dict__["hosts"] = hosts
            __props__.__dict__["passphrase"] = passphrase
            if private_key is None and not opts.urn:
                raise TypeError("Missing required property 'private_key'")
            __props__.__dict__["private_key"] = private_key
            if public_certificate is None and not opts.urn:
                raise TypeError("Missing required property 'public_certificate'")
            __props__.__dict__["public_certificate"] = public_certificate
        super(AnalyticsInstanceVanityUrl, __self__).__init__(
            'oci:analytics/analyticsInstanceVanityUrl:AnalyticsInstanceVanityUrl',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            analytics_instance_id: Optional[pulumi.Input[str]] = None,
            ca_certificate: Optional[pulumi.Input[str]] = None,
            description: Optional[pulumi.Input[str]] = None,
            hosts: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
            passphrase: Optional[pulumi.Input[str]] = None,
            private_key: Optional[pulumi.Input[str]] = None,
            public_certificate: Optional[pulumi.Input[str]] = None) -> 'AnalyticsInstanceVanityUrl':
        """
        Get an existing AnalyticsInstanceVanityUrl resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] analytics_instance_id: The OCID of the AnalyticsInstance.
        :param pulumi.Input[str] ca_certificate: (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        :param pulumi.Input[str] description: Optional description.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] hosts: List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        :param pulumi.Input[str] passphrase: (Updatable) Passphrase for the PEM Private key (if any).
        :param pulumi.Input[str] private_key: (Updatable) PEM Private key for HTTPS connections.
        :param pulumi.Input[str] public_certificate: (Updatable) PEM certificate for HTTPS connections.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _AnalyticsInstanceVanityUrlState.__new__(_AnalyticsInstanceVanityUrlState)

        __props__.__dict__["analytics_instance_id"] = analytics_instance_id
        __props__.__dict__["ca_certificate"] = ca_certificate
        __props__.__dict__["description"] = description
        __props__.__dict__["hosts"] = hosts
        __props__.__dict__["passphrase"] = passphrase
        __props__.__dict__["private_key"] = private_key
        __props__.__dict__["public_certificate"] = public_certificate
        return AnalyticsInstanceVanityUrl(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="analyticsInstanceId")
    def analytics_instance_id(self) -> pulumi.Output[str]:
        """
        The OCID of the AnalyticsInstance.
        """
        return pulumi.get(self, "analytics_instance_id")

    @property
    @pulumi.getter(name="caCertificate")
    def ca_certificate(self) -> pulumi.Output[str]:
        """
        (Updatable) PEM CA certificate(s) for HTTPS connections. This may include multiple PEM certificates.
        """
        return pulumi.get(self, "ca_certificate")

    @property
    @pulumi.getter
    def description(self) -> pulumi.Output[Optional[str]]:
        """
        Optional description.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter
    def hosts(self) -> pulumi.Output[Sequence[str]]:
        """
        List of fully qualified hostnames supported by this vanity URL definition (max of 3).
        """
        return pulumi.get(self, "hosts")

    @property
    @pulumi.getter
    def passphrase(self) -> pulumi.Output[Optional[str]]:
        """
        (Updatable) Passphrase for the PEM Private key (if any).
        """
        return pulumi.get(self, "passphrase")

    @property
    @pulumi.getter(name="privateKey")
    def private_key(self) -> pulumi.Output[str]:
        """
        (Updatable) PEM Private key for HTTPS connections.
        """
        return pulumi.get(self, "private_key")

    @property
    @pulumi.getter(name="publicCertificate")
    def public_certificate(self) -> pulumi.Output[str]:
        """
        (Updatable) PEM certificate for HTTPS connections.
        """
        return pulumi.get(self, "public_certificate")

