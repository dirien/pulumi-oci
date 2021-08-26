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
    'GetDkimsDkimCollectionResult',
    'GetDkimsDkimCollectionItemResult',
    'GetDkimsFilterResult',
    'GetEmailDomainsEmailDomainCollectionResult',
    'GetEmailDomainsEmailDomainCollectionItemResult',
    'GetEmailDomainsFilterResult',
    'GetSendersFilterResult',
    'GetSendersSenderResult',
    'GetSuppressionsFilterResult',
    'GetSuppressionsSuppressionResult',
]

@pulumi.output_type
class GetDkimsDkimCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetDkimsDkimCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetDkimsDkimCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetDkimsDkimCollectionItemResult(dict):
    def __init__(__self__, *,
                 cname_record_value: str,
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 dns_subdomain_name: str,
                 email_domain_id: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 lifecycle_details: str,
                 name: str,
                 state: str,
                 system_tags: Mapping[str, Any],
                 time_created: str,
                 time_updated: str,
                 txt_record_value: str):
        """
        :param str cname_record_value: The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
        :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param str description: The description of the DKIM. Avoid entering confidential information.
        :param str dns_subdomain_name: The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue
        :param str email_domain_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
        :param Mapping[str, Any] freeform_tags: Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param str id: A filter to only return resources that match the given id exactly.
        :param str lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
        :param str name: A filter to only return resources that match the given name exactly.
        :param str state: Filter returned list by specified lifecycle state. This parameter is case-insensitive.
        :param Mapping[str, Any] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param str time_created: The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".  Example: `2021-02-12T22:47:12.613Z`
        :param str time_updated: The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".
        :param str txt_record_value: The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME can not be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. This can also be used by customers who have an existing procedure to directly provision TXT records for DKIM. Be aware that many DNS APIs will require you to break this string into segments of less than 255 characters.
        """
        pulumi.set(__self__, "cname_record_value", cname_record_value)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "dns_subdomain_name", dns_subdomain_name)
        pulumi.set(__self__, "email_domain_id", email_domain_id)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "system_tags", system_tags)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "txt_record_value", txt_record_value)

    @property
    @pulumi.getter(name="cnameRecordValue")
    def cname_record_value(self) -> str:
        """
        The DNS CNAME record value to provision to the DKIM DNS subdomain, when using the CNAME method for DKIM setup (preferred).
        """
        return pulumi.get(self, "cname_record_value")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this DKIM.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        The description of the DKIM. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="dnsSubdomainName")
    def dns_subdomain_name(self) -> str:
        """
        The name of the DNS subdomain that must be provisioned to enable email recipients to verify DKIM signatures. It is usually created with a CNAME record set to the cnameRecordValue
        """
        return pulumi.get(self, "dns_subdomain_name")

    @property
    @pulumi.getter(name="emailDomainId")
    def email_domain_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
        """
        return pulumi.get(self, "email_domain_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        A filter to only return resources that match the given id exactly.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to only return resources that match the given name exactly.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Filter returned list by specified lifecycle state. This parameter is case-insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the DKIM was created. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".  Example: `2021-02-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time of the last change to the DKIM configuration, due to a state change or an update operation. Times are expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="txtRecordValue")
    def txt_record_value(self) -> str:
        """
        The DNS TXT record value to provision to the DKIM DNS subdomain in place of using a CNAME record. This is used in cases where a CNAME can not be used, such as when the cnameRecordValue would exceed the maximum length for a DNS entry. This can also be used by customers who have an existing procedure to directly provision TXT records for DKIM. Be aware that many DNS APIs will require you to break this string into segments of less than 255 characters.
        """
        return pulumi.get(self, "txt_record_value")


@pulumi.output_type
class GetDkimsFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to only return resources that match the given name exactly.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to only return resources that match the given name exactly.
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
class GetEmailDomainsEmailDomainCollectionResult(dict):
    def __init__(__self__, *,
                 items: Sequence['outputs.GetEmailDomainsEmailDomainCollectionItemResult']):
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetEmailDomainsEmailDomainCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetEmailDomainsEmailDomainCollectionItemResult(dict):
    def __init__(__self__, *,
                 active_dkim_id: str,
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 description: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 is_spf: bool,
                 name: str,
                 state: str,
                 system_tags: Mapping[str, Any],
                 time_created: str):
        """
        :param str active_dkim_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM key that will be used to sign mail sent from this email domain.
        :param str compartment_id: The OCID for the compartment.
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param str description: The description of a email domain.
        :param Mapping[str, Any] freeform_tags: Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param str id: A filter to only return resources that match the given id exactly.
        :param bool is_spf: Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        :param str name: A filter to only return resources that match the given name exactly.
        :param str state: Filter returned list by specified lifecycle state. This parameter is case-insensitive.
        :param Mapping[str, Any] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param str time_created: The time the email domain was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".  Example: `2021-02-12T22:47:12.613Z`
        """
        pulumi.set(__self__, "active_dkim_id", active_dkim_id)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "is_spf", is_spf)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "system_tags", system_tags)
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="activeDkimId")
    def active_dkim_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM key that will be used to sign mail sent from this email domain.
        """
        return pulumi.get(self, "active_dkim_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        The description of a email domain.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        A filter to only return resources that match the given id exactly.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isSpf")
    def is_spf(self) -> bool:
        """
        Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        """
        return pulumi.get(self, "is_spf")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to only return resources that match the given name exactly.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Filter returned list by specified lifecycle state. This parameter is case-insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the email domain was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".  Example: `2021-02-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")


@pulumi.output_type
class GetEmailDomainsFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to only return resources that match the given name exactly.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to only return resources that match the given name exactly.
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
class GetSendersFilterResult(dict):
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
class GetSendersSenderResult(dict):
    def __init__(__self__, *,
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 email_address: str,
                 email_domain_id: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 is_spf: bool,
                 state: str,
                 time_created: str):
        """
        :param str compartment_id: The OCID for the compartment.
        :param Mapping[str, Any] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param str email_address: The email address of the approved sender.
        :param str email_domain_id: The email domain used to assert responsibility for emails sent from this sender.
        :param Mapping[str, Any] freeform_tags: Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param str id: The unique OCID of the sender.
        :param bool is_spf: Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        :param str state: The current state of a sender.
        :param str time_created: The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "email_address", email_address)
        pulumi.set(__self__, "email_domain_id", email_domain_id)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "is_spf", is_spf)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="emailAddress")
    def email_address(self) -> str:
        """
        The email address of the approved sender.
        """
        return pulumi.get(self, "email_address")

    @property
    @pulumi.getter(name="emailDomainId")
    def email_domain_id(self) -> str:
        """
        The email domain used to assert responsibility for emails sent from this sender.
        """
        return pulumi.get(self, "email_domain_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The unique OCID of the sender.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isSpf")
    def is_spf(self) -> bool:
        """
        Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        """
        return pulumi.get(self, "is_spf")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of a sender.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")


@pulumi.output_type
class GetSuppressionsFilterResult(dict):
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
class GetSuppressionsSuppressionResult(dict):
    def __init__(__self__, *,
                 compartment_id: str,
                 email_address: str,
                 error_detail: str,
                 error_source: str,
                 id: str,
                 message_id: str,
                 reason: str,
                 time_created: str,
                 time_last_suppressed: str):
        """
        :param str compartment_id: The OCID for the compartment.
        :param str email_address: The email address of the suppression.
        :param str error_detail: The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        :param str error_source: DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        :param str id: The unique OCID of the suppression.
        :param str message_id: The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        :param str reason: The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        :param str time_created: The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        :param str time_last_suppressed: The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "email_address", email_address)
        pulumi.set(__self__, "error_detail", error_detail)
        pulumi.set(__self__, "error_source", error_source)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "message_id", message_id)
        pulumi.set(__self__, "reason", reason)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_last_suppressed", time_last_suppressed)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="emailAddress")
    def email_address(self) -> str:
        """
        The email address of the suppression.
        """
        return pulumi.get(self, "email_address")

    @property
    @pulumi.getter(name="errorDetail")
    def error_detail(self) -> str:
        """
        The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        """
        return pulumi.get(self, "error_detail")

    @property
    @pulumi.getter(name="errorSource")
    def error_source(self) -> str:
        """
        DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        """
        return pulumi.get(self, "error_source")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The unique OCID of the suppression.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="messageId")
    def message_id(self) -> str:
        """
        The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        """
        return pulumi.get(self, "message_id")

    @property
    @pulumi.getter
    def reason(self) -> str:
        """
        The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        """
        return pulumi.get(self, "reason")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastSuppressed")
    def time_last_suppressed(self) -> str:
        """
        The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_last_suppressed")


