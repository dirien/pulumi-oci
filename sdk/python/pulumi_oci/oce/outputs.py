# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetOceInstancesFilterResult',
    'GetOceInstancesOceInstanceResult',
]

@pulumi.output_type
class GetOceInstancesFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: OceInstance Name
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        OceInstance Name
        """
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
class GetOceInstancesOceInstanceResult(dict):
    def __init__(__self__, *,
                 admin_email: str,
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 freeform_tags: Mapping[str, Any],
                 guid: str,
                 id: str,
                 idcs_access_token: str,
                 idcs_tenancy: str,
                 instance_access_type: str,
                 instance_license_type: str,
                 instance_usage_type: str,
                 name: str,
                 object_storage_namespace: str,
                 service: Mapping[str, Any],
                 state: str,
                 state_message: str,
                 system_tags: Mapping[str, Any],
                 tenancy_id: str,
                 tenancy_name: str,
                 time_created: str,
                 time_updated: str,
                 upgrade_schedule: str,
                 waf_primary_domain: str):
        """
        :param str admin_email: Admin Email for Notification
        :param str compartment_id: The ID of the compartment in which to list resources.
        :param Mapping[str, Any] defined_tags: Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param str description: OceInstance description, can be updated
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str guid: Unique GUID identifier that is immutable on creation
        :param str id: Unique identifier that is immutable on creation
        :param str idcs_tenancy: IDCS Tenancy Identifier
        :param str instance_access_type: Flag indicating whether the instance access is private or public
        :param str instance_license_type: Flag indicating whether the instance license is new cloud or bring your own license
        :param str instance_usage_type: Instance type based on its usage
        :param str name: OceInstance Name
        :param str object_storage_namespace: Object Storage Namespace of tenancy
        :param Mapping[str, Any] service: SERVICE data. Example: `{"service": {"IDCS": "value"}}`
        :param str state: Filter results on lifecycleState.
        :param str state_message: An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param Mapping[str, Any] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param str tenancy_id: The ID of the tenancy in which to list resources.
        :param str tenancy_name: Tenancy Name
        :param str time_created: The time the the OceInstance was created. An RFC3339 formatted datetime string
        :param str time_updated: The time the OceInstance was updated. An RFC3339 formatted datetime string
        :param str upgrade_schedule: Upgrade schedule type representing service to be upgraded immediately whenever latest version is released or delay upgrade of the service to previous released version
        :param str waf_primary_domain: Web Application Firewall(WAF) primary domain
        """
        pulumi.set(__self__, "admin_email", admin_email)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "guid", guid)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "idcs_access_token", idcs_access_token)
        pulumi.set(__self__, "idcs_tenancy", idcs_tenancy)
        pulumi.set(__self__, "instance_access_type", instance_access_type)
        pulumi.set(__self__, "instance_license_type", instance_license_type)
        pulumi.set(__self__, "instance_usage_type", instance_usage_type)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "object_storage_namespace", object_storage_namespace)
        pulumi.set(__self__, "service", service)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "state_message", state_message)
        pulumi.set(__self__, "system_tags", system_tags)
        pulumi.set(__self__, "tenancy_id", tenancy_id)
        pulumi.set(__self__, "tenancy_name", tenancy_name)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "upgrade_schedule", upgrade_schedule)
        pulumi.set(__self__, "waf_primary_domain", waf_primary_domain)

    @property
    @pulumi.getter(name="adminEmail")
    def admin_email(self) -> str:
        """
        Admin Email for Notification
        """
        return pulumi.get(self, "admin_email")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The ID of the compartment in which to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        OceInstance description, can be updated
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def guid(self) -> str:
        """
        Unique GUID identifier that is immutable on creation
        """
        return pulumi.get(self, "guid")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="idcsAccessToken")
    def idcs_access_token(self) -> str:
        return pulumi.get(self, "idcs_access_token")

    @property
    @pulumi.getter(name="idcsTenancy")
    def idcs_tenancy(self) -> str:
        """
        IDCS Tenancy Identifier
        """
        return pulumi.get(self, "idcs_tenancy")

    @property
    @pulumi.getter(name="instanceAccessType")
    def instance_access_type(self) -> str:
        """
        Flag indicating whether the instance access is private or public
        """
        return pulumi.get(self, "instance_access_type")

    @property
    @pulumi.getter(name="instanceLicenseType")
    def instance_license_type(self) -> str:
        """
        Flag indicating whether the instance license is new cloud or bring your own license
        """
        return pulumi.get(self, "instance_license_type")

    @property
    @pulumi.getter(name="instanceUsageType")
    def instance_usage_type(self) -> str:
        """
        Instance type based on its usage
        """
        return pulumi.get(self, "instance_usage_type")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        OceInstance Name
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="objectStorageNamespace")
    def object_storage_namespace(self) -> str:
        """
        Object Storage Namespace of tenancy
        """
        return pulumi.get(self, "object_storage_namespace")

    @property
    @pulumi.getter
    def service(self) -> Mapping[str, Any]:
        """
        SERVICE data. Example: `{"service": {"IDCS": "value"}}`
        """
        return pulumi.get(self, "service")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Filter results on lifecycleState.
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
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> str:
        """
        The ID of the tenancy in which to list resources.
        """
        return pulumi.get(self, "tenancy_id")

    @property
    @pulumi.getter(name="tenancyName")
    def tenancy_name(self) -> str:
        """
        Tenancy Name
        """
        return pulumi.get(self, "tenancy_name")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the OceInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the OceInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="upgradeSchedule")
    def upgrade_schedule(self) -> str:
        """
        Upgrade schedule type representing service to be upgraded immediately whenever latest version is released or delay upgrade of the service to previous released version
        """
        return pulumi.get(self, "upgrade_schedule")

    @property
    @pulumi.getter(name="wafPrimaryDomain")
    def waf_primary_domain(self) -> str:
        """
        Web Application Firewall(WAF) primary domain
        """
        return pulumi.get(self, "waf_primary_domain")


