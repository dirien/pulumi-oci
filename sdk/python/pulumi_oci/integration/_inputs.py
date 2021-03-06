# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'IntegrationInstanceAlternateCustomEndpointArgs',
    'IntegrationInstanceCustomEndpointArgs',
    'IntegrationInstanceNetworkEndpointDetailsArgs',
    'IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs',
    'GetIntegrationInstancesFilterArgs',
]

@pulumi.input_type
class IntegrationInstanceAlternateCustomEndpointArgs:
    def __init__(__self__, *,
                 hostname: pulumi.Input[str],
                 certificate_secret_id: Optional[pulumi.Input[str]] = None,
                 certificate_secret_version: Optional[pulumi.Input[int]] = None):
        """
        :param pulumi.Input[str] hostname: (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        :param pulumi.Input[str] certificate_secret_id: (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        :param pulumi.Input[int] certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        pulumi.set(__self__, "hostname", hostname)
        if certificate_secret_id is not None:
            pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        if certificate_secret_version is not None:
            pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)

    @property
    @pulumi.getter
    def hostname(self) -> pulumi.Input[str]:
        """
        (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")

    @hostname.setter
    def hostname(self, value: pulumi.Input[str]):
        pulumi.set(self, "hostname", value)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        """
        return pulumi.get(self, "certificate_secret_id")

    @certificate_secret_id.setter
    def certificate_secret_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "certificate_secret_id", value)

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> Optional[pulumi.Input[int]]:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @certificate_secret_version.setter
    def certificate_secret_version(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "certificate_secret_version", value)


@pulumi.input_type
class IntegrationInstanceCustomEndpointArgs:
    def __init__(__self__, *,
                 hostname: pulumi.Input[str],
                 certificate_secret_id: Optional[pulumi.Input[str]] = None,
                 certificate_secret_version: Optional[pulumi.Input[int]] = None):
        """
        :param pulumi.Input[str] hostname: (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        :param pulumi.Input[str] certificate_secret_id: (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        :param pulumi.Input[int] certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        pulumi.set(__self__, "hostname", hostname)
        if certificate_secret_id is not None:
            pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        if certificate_secret_version is not None:
            pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)

    @property
    @pulumi.getter
    def hostname(self) -> pulumi.Input[str]:
        """
        (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")

    @hostname.setter
    def hostname(self, value: pulumi.Input[str]):
        pulumi.set(self, "hostname", value)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        """
        return pulumi.get(self, "certificate_secret_id")

    @certificate_secret_id.setter
    def certificate_secret_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "certificate_secret_id", value)

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> Optional[pulumi.Input[int]]:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @certificate_secret_version.setter
    def certificate_secret_version(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "certificate_secret_version", value)


@pulumi.input_type
class IntegrationInstanceNetworkEndpointDetailsArgs:
    def __init__(__self__, *,
                 network_endpoint_type: pulumi.Input[str],
                 allowlisted_http_ips: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 allowlisted_http_vcns: Optional[pulumi.Input[Sequence[pulumi.Input['IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs']]]] = None,
                 is_integration_vcn_allowlisted: Optional[pulumi.Input[bool]] = None):
        """
        :param pulumi.Input[str] network_endpoint_type: The type of network endpoint.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] allowlisted_http_ips: Source IP addresses or IP address ranges ingress rules.
        :param pulumi.Input[Sequence[pulumi.Input['IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs']]] allowlisted_http_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        :param pulumi.Input[bool] is_integration_vcn_allowlisted: The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        """
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)
        if allowlisted_http_ips is not None:
            pulumi.set(__self__, "allowlisted_http_ips", allowlisted_http_ips)
        if allowlisted_http_vcns is not None:
            pulumi.set(__self__, "allowlisted_http_vcns", allowlisted_http_vcns)
        if is_integration_vcn_allowlisted is not None:
            pulumi.set(__self__, "is_integration_vcn_allowlisted", is_integration_vcn_allowlisted)

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> pulumi.Input[str]:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")

    @network_endpoint_type.setter
    def network_endpoint_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "network_endpoint_type", value)

    @property
    @pulumi.getter(name="allowlistedHttpIps")
    def allowlisted_http_ips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_http_ips")

    @allowlisted_http_ips.setter
    def allowlisted_http_ips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "allowlisted_http_ips", value)

    @property
    @pulumi.getter(name="allowlistedHttpVcns")
    def allowlisted_http_vcns(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs']]]]:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "allowlisted_http_vcns")

    @allowlisted_http_vcns.setter
    def allowlisted_http_vcns(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs']]]]):
        pulumi.set(self, "allowlisted_http_vcns", value)

    @property
    @pulumi.getter(name="isIntegrationVcnAllowlisted")
    def is_integration_vcn_allowlisted(self) -> Optional[pulumi.Input[bool]]:
        """
        The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        """
        return pulumi.get(self, "is_integration_vcn_allowlisted")

    @is_integration_vcn_allowlisted.setter
    def is_integration_vcn_allowlisted(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_integration_vcn_allowlisted", value)


@pulumi.input_type
class IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs:
    def __init__(__self__, *,
                 id: pulumi.Input[str],
                 allowlisted_ips: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None):
        """
        :param pulumi.Input[str] id: The Virtual Cloud Network OCID.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] allowlisted_ips: Source IP addresses or IP address ranges ingress rules.
        """
        pulumi.set(__self__, "id", id)
        if allowlisted_ips is not None:
            pulumi.set(__self__, "allowlisted_ips", allowlisted_ips)

    @property
    @pulumi.getter
    def id(self) -> pulumi.Input[str]:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @id.setter
    def id(self, value: pulumi.Input[str]):
        pulumi.set(self, "id", value)

    @property
    @pulumi.getter(name="allowlistedIps")
    def allowlisted_ips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_ips")

    @allowlisted_ips.setter
    def allowlisted_ips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "allowlisted_ips", value)


@pulumi.input_type
class GetIntegrationInstancesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


