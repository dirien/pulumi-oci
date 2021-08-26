# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'IntegrationInstanceAlternateCustomEndpoint',
    'IntegrationInstanceCustomEndpoint',
    'IntegrationInstanceNetworkEndpointDetails',
    'IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn',
    'GetIntegrationInstanceAlternateCustomEndpointResult',
    'GetIntegrationInstanceCustomEndpointResult',
    'GetIntegrationInstanceNetworkEndpointDetailsResult',
    'GetIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult',
    'GetIntegrationInstancesFilterResult',
    'GetIntegrationInstancesIntegrationInstanceResult',
    'GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointResult',
    'GetIntegrationInstancesIntegrationInstanceCustomEndpointResult',
    'GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsResult',
    'GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult',
]

@pulumi.output_type
class IntegrationInstanceAlternateCustomEndpoint(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "certificateSecretId":
            suggest = "certificate_secret_id"
        elif key == "certificateSecretVersion":
            suggest = "certificate_secret_version"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in IntegrationInstanceAlternateCustomEndpoint. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        IntegrationInstanceAlternateCustomEndpoint.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        IntegrationInstanceAlternateCustomEndpoint.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 hostname: str,
                 certificate_secret_id: Optional[str] = None,
                 certificate_secret_version: Optional[int] = None):
        """
        :param str hostname: (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        :param str certificate_secret_id: (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        :param int certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        pulumi.set(__self__, "hostname", hostname)
        if certificate_secret_id is not None:
            pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        if certificate_secret_version is not None:
            pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> Optional[str]:
        """
        (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        """
        return pulumi.get(self, "certificate_secret_id")

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> Optional[int]:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")


@pulumi.output_type
class IntegrationInstanceCustomEndpoint(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "certificateSecretId":
            suggest = "certificate_secret_id"
        elif key == "certificateSecretVersion":
            suggest = "certificate_secret_version"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in IntegrationInstanceCustomEndpoint. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        IntegrationInstanceCustomEndpoint.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        IntegrationInstanceCustomEndpoint.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 hostname: str,
                 certificate_secret_id: Optional[str] = None,
                 certificate_secret_version: Optional[int] = None):
        """
        :param str hostname: (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        :param str certificate_secret_id: (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        :param int certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        pulumi.set(__self__, "hostname", hostname)
        if certificate_secret_id is not None:
            pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        if certificate_secret_version is not None:
            pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        (Updatable) A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> Optional[str]:
        """
        (Updatable) Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname. All certificates should be stored in a single base64 encoded secret Note the update will fail if this is not a valid certificate.
        """
        return pulumi.get(self, "certificate_secret_id")

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> Optional[int]:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")


@pulumi.output_type
class IntegrationInstanceNetworkEndpointDetails(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "networkEndpointType":
            suggest = "network_endpoint_type"
        elif key == "allowlistedHttpIps":
            suggest = "allowlisted_http_ips"
        elif key == "allowlistedHttpVcns":
            suggest = "allowlisted_http_vcns"
        elif key == "isIntegrationVcnAllowlisted":
            suggest = "is_integration_vcn_allowlisted"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in IntegrationInstanceNetworkEndpointDetails. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        IntegrationInstanceNetworkEndpointDetails.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        IntegrationInstanceNetworkEndpointDetails.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 network_endpoint_type: str,
                 allowlisted_http_ips: Optional[Sequence[str]] = None,
                 allowlisted_http_vcns: Optional[Sequence['outputs.IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn']] = None,
                 is_integration_vcn_allowlisted: Optional[bool] = None):
        """
        :param str network_endpoint_type: The type of network endpoint.
        :param Sequence[str] allowlisted_http_ips: Source IP addresses or IP address ranges ingress rules.
        :param Sequence['IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs'] allowlisted_http_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        :param bool is_integration_vcn_allowlisted: The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
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
    def network_endpoint_type(self) -> str:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")

    @property
    @pulumi.getter(name="allowlistedHttpIps")
    def allowlisted_http_ips(self) -> Optional[Sequence[str]]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_http_ips")

    @property
    @pulumi.getter(name="allowlistedHttpVcns")
    def allowlisted_http_vcns(self) -> Optional[Sequence['outputs.IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn']]:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "allowlisted_http_vcns")

    @property
    @pulumi.getter(name="isIntegrationVcnAllowlisted")
    def is_integration_vcn_allowlisted(self) -> Optional[bool]:
        """
        The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        """
        return pulumi.get(self, "is_integration_vcn_allowlisted")


@pulumi.output_type
class IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "allowlistedIps":
            suggest = "allowlisted_ips"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 id: str,
                 allowlisted_ips: Optional[Sequence[str]] = None):
        """
        :param str id: The Virtual Cloud Network OCID.
        :param Sequence[str] allowlisted_ips: Source IP addresses or IP address ranges ingress rules.
        """
        pulumi.set(__self__, "id", id)
        if allowlisted_ips is not None:
            pulumi.set(__self__, "allowlisted_ips", allowlisted_ips)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="allowlistedIps")
    def allowlisted_ips(self) -> Optional[Sequence[str]]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_ips")


@pulumi.output_type
class GetIntegrationInstanceAlternateCustomEndpointResult(dict):
    def __init__(__self__, *,
                 certificate_secret_id: str,
                 certificate_secret_version: int,
                 hostname: str):
        """
        :param str certificate_secret_id: Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        :param int certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        :param str hostname: A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)
        pulumi.set(__self__, "hostname", hostname)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> str:
        """
        Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        """
        return pulumi.get(self, "certificate_secret_id")

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> int:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")


@pulumi.output_type
class GetIntegrationInstanceCustomEndpointResult(dict):
    def __init__(__self__, *,
                 certificate_secret_id: str,
                 certificate_secret_version: int,
                 hostname: str):
        """
        :param str certificate_secret_id: Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        :param int certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        :param str hostname: A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)
        pulumi.set(__self__, "hostname", hostname)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> str:
        """
        Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        """
        return pulumi.get(self, "certificate_secret_id")

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> int:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")


@pulumi.output_type
class GetIntegrationInstanceNetworkEndpointDetailsResult(dict):
    def __init__(__self__, *,
                 allowlisted_http_ips: Sequence[str],
                 allowlisted_http_vcns: Sequence['outputs.GetIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult'],
                 is_integration_vcn_allowlisted: bool,
                 network_endpoint_type: str):
        """
        :param Sequence[str] allowlisted_http_ips: Source IP addresses or IP address ranges ingress rules.
        :param Sequence['GetIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs'] allowlisted_http_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        :param bool is_integration_vcn_allowlisted: The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        :param str network_endpoint_type: The type of network endpoint.
        """
        pulumi.set(__self__, "allowlisted_http_ips", allowlisted_http_ips)
        pulumi.set(__self__, "allowlisted_http_vcns", allowlisted_http_vcns)
        pulumi.set(__self__, "is_integration_vcn_allowlisted", is_integration_vcn_allowlisted)
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)

    @property
    @pulumi.getter(name="allowlistedHttpIps")
    def allowlisted_http_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_http_ips")

    @property
    @pulumi.getter(name="allowlistedHttpVcns")
    def allowlisted_http_vcns(self) -> Sequence['outputs.GetIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult']:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "allowlisted_http_vcns")

    @property
    @pulumi.getter(name="isIntegrationVcnAllowlisted")
    def is_integration_vcn_allowlisted(self) -> bool:
        """
        The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        """
        return pulumi.get(self, "is_integration_vcn_allowlisted")

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> str:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")


@pulumi.output_type
class GetIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult(dict):
    def __init__(__self__, *,
                 allowlisted_ips: Sequence[str],
                 id: str):
        """
        :param Sequence[str] allowlisted_ips: Source IP addresses or IP address ranges ingress rules.
        :param str id: The Virtual Cloud Network OCID.
        """
        pulumi.set(__self__, "allowlisted_ips", allowlisted_ips)
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="allowlistedIps")
    def allowlisted_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_ips")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class GetIntegrationInstancesFilterResult(dict):
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

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetIntegrationInstancesIntegrationInstanceResult(dict):
    def __init__(__self__, *,
                 alternate_custom_endpoints: Sequence['outputs.GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointResult'],
                 compartment_id: str,
                 consumption_model: str,
                 custom_endpoint: 'outputs.GetIntegrationInstancesIntegrationInstanceCustomEndpointResult',
                 defined_tags: Mapping[str, Any],
                 display_name: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 idcs_at: str,
                 instance_url: str,
                 integration_instance_type: str,
                 is_byol: bool,
                 is_file_server_enabled: bool,
                 is_visual_builder_enabled: bool,
                 message_packs: int,
                 network_endpoint_details: 'outputs.GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsResult',
                 state: str,
                 state_message: str,
                 time_created: str,
                 time_updated: str):
        """
        :param Sequence['GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointArgs'] alternate_custom_endpoints: A list of alternate custom endpoints used for the integration instance URL.
        :param str compartment_id: The ID of the compartment in which to list resources.
        :param str consumption_model: The entitlement used for billing purposes.
        :param 'GetIntegrationInstancesIntegrationInstanceCustomEndpointArgs' custom_endpoint: Details for a custom endpoint for the integration instance.
        :param Mapping[str, Any] defined_tags: Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param str display_name: A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: The Virtual Cloud Network OCID.
        :param str instance_url: The Integration Instance URL.
        :param str integration_instance_type: Standard or Enterprise type
        :param bool is_byol: Bring your own license.
        :param bool is_file_server_enabled: The file server is enabled or not.
        :param bool is_visual_builder_enabled: Visual Builder is enabled or not.
        :param int message_packs: The number of configured message packs (if any)
        :param 'GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsArgs' network_endpoint_details: Base representation of a network endpoint.
        :param str state: Life cycle state to query on.
        :param str state_message: An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param str time_created: The time the the Integration Instance was created. An RFC3339 formatted datetime string.
        :param str time_updated: The time the IntegrationInstance was updated. An RFC3339 formatted datetime string.
        """
        pulumi.set(__self__, "alternate_custom_endpoints", alternate_custom_endpoints)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "consumption_model", consumption_model)
        pulumi.set(__self__, "custom_endpoint", custom_endpoint)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idcs_at", idcs_at)
        pulumi.set(__self__, "instance_url", instance_url)
        pulumi.set(__self__, "integration_instance_type", integration_instance_type)
        pulumi.set(__self__, "is_byol", is_byol)
        pulumi.set(__self__, "is_file_server_enabled", is_file_server_enabled)
        pulumi.set(__self__, "is_visual_builder_enabled", is_visual_builder_enabled)
        pulumi.set(__self__, "message_packs", message_packs)
        pulumi.set(__self__, "network_endpoint_details", network_endpoint_details)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "state_message", state_message)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="alternateCustomEndpoints")
    def alternate_custom_endpoints(self) -> Sequence['outputs.GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointResult']:
        """
        A list of alternate custom endpoints used for the integration instance URL.
        """
        return pulumi.get(self, "alternate_custom_endpoints")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="consumptionModel")
    def consumption_model(self) -> str:
        """
        The entitlement used for billing purposes.
        """
        return pulumi.get(self, "consumption_model")

    @property
    @pulumi.getter(name="customEndpoint")
    def custom_endpoint(self) -> 'outputs.GetIntegrationInstancesIntegrationInstanceCustomEndpointResult':
        """
        Details for a custom endpoint for the integration instance.
        """
        return pulumi.get(self, "custom_endpoint")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAt")
    def idcs_at(self) -> str:
        return pulumi.get(self, "idcs_at")

    @property
    @pulumi.getter(name="instanceUrl")
    def instance_url(self) -> str:
        """
        The Integration Instance URL.
        """
        return pulumi.get(self, "instance_url")

    @property
    @pulumi.getter(name="integrationInstanceType")
    def integration_instance_type(self) -> str:
        """
        Standard or Enterprise type
        """
        return pulumi.get(self, "integration_instance_type")

    @property
    @pulumi.getter(name="isByol")
    def is_byol(self) -> bool:
        """
        Bring your own license.
        """
        return pulumi.get(self, "is_byol")

    @property
    @pulumi.getter(name="isFileServerEnabled")
    def is_file_server_enabled(self) -> bool:
        """
        The file server is enabled or not.
        """
        return pulumi.get(self, "is_file_server_enabled")

    @property
    @pulumi.getter(name="isVisualBuilderEnabled")
    def is_visual_builder_enabled(self) -> bool:
        """
        Visual Builder is enabled or not.
        """
        return pulumi.get(self, "is_visual_builder_enabled")

    @property
    @pulumi.getter(name="messagePacks")
    def message_packs(self) -> int:
        """
        The number of configured message packs (if any)
        """
        return pulumi.get(self, "message_packs")

    @property
    @pulumi.getter(name="networkEndpointDetails")
    def network_endpoint_details(self) -> 'outputs.GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsResult':
        """
        Base representation of a network endpoint.
        """
        return pulumi.get(self, "network_endpoint_details")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Life cycle state to query on.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="stateMessage")
    def state_message(self) -> str:
        """
        An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "state_message")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the Integration Instance was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the IntegrationInstance was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


@pulumi.output_type
class GetIntegrationInstancesIntegrationInstanceAlternateCustomEndpointResult(dict):
    def __init__(__self__, *,
                 certificate_secret_id: str,
                 certificate_secret_version: int,
                 hostname: str):
        """
        :param str certificate_secret_id: Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        :param int certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        :param str hostname: A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)
        pulumi.set(__self__, "hostname", hostname)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> str:
        """
        Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        """
        return pulumi.get(self, "certificate_secret_id")

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> int:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")


@pulumi.output_type
class GetIntegrationInstancesIntegrationInstanceCustomEndpointResult(dict):
    def __init__(__self__, *,
                 certificate_secret_id: str,
                 certificate_secret_version: int,
                 hostname: str):
        """
        :param str certificate_secret_id: Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        :param int certificate_secret_version: The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        :param str hostname: A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        pulumi.set(__self__, "certificate_secret_id", certificate_secret_id)
        pulumi.set(__self__, "certificate_secret_version", certificate_secret_version)
        pulumi.set(__self__, "hostname", hostname)

    @property
    @pulumi.getter(name="certificateSecretId")
    def certificate_secret_id(self) -> str:
        """
        Optional OCID of a vault/secret containing a private SSL certificate bundle to be used for the custom hostname.
        """
        return pulumi.get(self, "certificate_secret_id")

    @property
    @pulumi.getter(name="certificateSecretVersion")
    def certificate_secret_version(self) -> int:
        """
        The secret version used for the certificate-secret-id (if certificate-secret-id is specified).
        """
        return pulumi.get(self, "certificate_secret_version")

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        A custom hostname to be used for the integration instance URL, in FQDN format.
        """
        return pulumi.get(self, "hostname")


@pulumi.output_type
class GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsResult(dict):
    def __init__(__self__, *,
                 allowlisted_http_ips: Sequence[str],
                 allowlisted_http_vcns: Sequence['outputs.GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult'],
                 is_integration_vcn_allowlisted: bool,
                 network_endpoint_type: str):
        """
        :param Sequence[str] allowlisted_http_ips: Source IP addresses or IP address ranges ingress rules.
        :param Sequence['GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs'] allowlisted_http_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        :param bool is_integration_vcn_allowlisted: The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        :param str network_endpoint_type: The type of network endpoint.
        """
        pulumi.set(__self__, "allowlisted_http_ips", allowlisted_http_ips)
        pulumi.set(__self__, "allowlisted_http_vcns", allowlisted_http_vcns)
        pulumi.set(__self__, "is_integration_vcn_allowlisted", is_integration_vcn_allowlisted)
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)

    @property
    @pulumi.getter(name="allowlistedHttpIps")
    def allowlisted_http_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_http_ips")

    @property
    @pulumi.getter(name="allowlistedHttpVcns")
    def allowlisted_http_vcns(self) -> Sequence['outputs.GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult']:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "allowlisted_http_vcns")

    @property
    @pulumi.getter(name="isIntegrationVcnAllowlisted")
    def is_integration_vcn_allowlisted(self) -> bool:
        """
        The Integration service's VCN is allow-listed to allow integrations to call back into other integrations
        """
        return pulumi.get(self, "is_integration_vcn_allowlisted")

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> str:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")


@pulumi.output_type
class GetIntegrationInstancesIntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnResult(dict):
    def __init__(__self__, *,
                 allowlisted_ips: Sequence[str],
                 id: str):
        """
        :param Sequence[str] allowlisted_ips: Source IP addresses or IP address ranges ingress rules.
        :param str id: The Virtual Cloud Network OCID.
        """
        pulumi.set(__self__, "allowlisted_ips", allowlisted_ips)
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="allowlistedIps")
    def allowlisted_ips(self) -> Sequence[str]:
        """
        Source IP addresses or IP address ranges ingress rules.
        """
        return pulumi.get(self, "allowlisted_ips")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")


