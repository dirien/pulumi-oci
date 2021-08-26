# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['SuppressionArgs', 'Suppression']

@pulumi.input_type
class SuppressionArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 email_address: pulumi.Input[str]):
        """
        The set of arguments for constructing a Suppression resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        :param pulumi.Input[str] email_address: The recipient email address of the suppression.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "email_address", email_address)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="emailAddress")
    def email_address(self) -> pulumi.Input[str]:
        """
        The recipient email address of the suppression.
        """
        return pulumi.get(self, "email_address")

    @email_address.setter
    def email_address(self, value: pulumi.Input[str]):
        pulumi.set(self, "email_address", value)


@pulumi.input_type
class _SuppressionState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 email_address: Optional[pulumi.Input[str]] = None,
                 error_detail: Optional[pulumi.Input[str]] = None,
                 error_source: Optional[pulumi.Input[str]] = None,
                 message_id: Optional[pulumi.Input[str]] = None,
                 reason: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_last_suppressed: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering Suppression resources.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        :param pulumi.Input[str] email_address: The recipient email address of the suppression.
        :param pulumi.Input[str] error_detail: The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        :param pulumi.Input[str] error_source: DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        :param pulumi.Input[str] message_id: The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        :param pulumi.Input[str] reason: The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        :param pulumi.Input[str] time_created: The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        :param pulumi.Input[str] time_last_suppressed: The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if email_address is not None:
            pulumi.set(__self__, "email_address", email_address)
        if error_detail is not None:
            pulumi.set(__self__, "error_detail", error_detail)
        if error_source is not None:
            pulumi.set(__self__, "error_source", error_source)
        if message_id is not None:
            pulumi.set(__self__, "message_id", message_id)
        if reason is not None:
            pulumi.set(__self__, "reason", reason)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_last_suppressed is not None:
            pulumi.set(__self__, "time_last_suppressed", time_last_suppressed)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="emailAddress")
    def email_address(self) -> Optional[pulumi.Input[str]]:
        """
        The recipient email address of the suppression.
        """
        return pulumi.get(self, "email_address")

    @email_address.setter
    def email_address(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "email_address", value)

    @property
    @pulumi.getter(name="errorDetail")
    def error_detail(self) -> Optional[pulumi.Input[str]]:
        """
        The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        """
        return pulumi.get(self, "error_detail")

    @error_detail.setter
    def error_detail(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "error_detail", value)

    @property
    @pulumi.getter(name="errorSource")
    def error_source(self) -> Optional[pulumi.Input[str]]:
        """
        DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        """
        return pulumi.get(self, "error_source")

    @error_source.setter
    def error_source(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "error_source", value)

    @property
    @pulumi.getter(name="messageId")
    def message_id(self) -> Optional[pulumi.Input[str]]:
        """
        The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        """
        return pulumi.get(self, "message_id")

    @message_id.setter
    def message_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "message_id", value)

    @property
    @pulumi.getter
    def reason(self) -> Optional[pulumi.Input[str]]:
        """
        The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        """
        return pulumi.get(self, "reason")

    @reason.setter
    def reason(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "reason", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeLastSuppressed")
    def time_last_suppressed(self) -> Optional[pulumi.Input[str]]:
        """
        The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_last_suppressed")

    @time_last_suppressed.setter
    def time_last_suppressed(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_last_suppressed", value)


class Suppression(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 email_address: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Suppression resource in Oracle Cloud Infrastructure Email service.

        Adds recipient email addresses to the suppression list for a tenancy.
        Addresses added to the suppression list via the API are denoted as
        "MANUAL" in the `reason` field. *Note:* All email addresses added to the
        suppression list are normalized to include only lowercase letters.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_suppression = oci.email.Suppression("testSuppression",
            compartment_id=var["tenancy_ocid"],
            email_address=var["suppression_email_address"])
        ```

        ## Import

        Suppressions can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:email/suppression:Suppression test_suppression "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        :param pulumi.Input[str] email_address: The recipient email address of the suppression.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: SuppressionArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Suppression resource in Oracle Cloud Infrastructure Email service.

        Adds recipient email addresses to the suppression list for a tenancy.
        Addresses added to the suppression list via the API are denoted as
        "MANUAL" in the `reason` field. *Note:* All email addresses added to the
        suppression list are normalized to include only lowercase letters.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_suppression = oci.email.Suppression("testSuppression",
            compartment_id=var["tenancy_ocid"],
            email_address=var["suppression_email_address"])
        ```

        ## Import

        Suppressions can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:email/suppression:Suppression test_suppression "id"
        ```

        :param str resource_name: The name of the resource.
        :param SuppressionArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(SuppressionArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 email_address: Optional[pulumi.Input[str]] = None,
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
            __props__ = SuppressionArgs.__new__(SuppressionArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if email_address is None and not opts.urn:
                raise TypeError("Missing required property 'email_address'")
            __props__.__dict__["email_address"] = email_address
            __props__.__dict__["error_detail"] = None
            __props__.__dict__["error_source"] = None
            __props__.__dict__["message_id"] = None
            __props__.__dict__["reason"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_last_suppressed"] = None
        super(Suppression, __self__).__init__(
            'oci:email/suppression:Suppression',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            email_address: Optional[pulumi.Input[str]] = None,
            error_detail: Optional[pulumi.Input[str]] = None,
            error_source: Optional[pulumi.Input[str]] = None,
            message_id: Optional[pulumi.Input[str]] = None,
            reason: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_last_suppressed: Optional[pulumi.Input[str]] = None) -> 'Suppression':
        """
        Get an existing Suppression resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        :param pulumi.Input[str] email_address: The recipient email address of the suppression.
        :param pulumi.Input[str] error_detail: The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        :param pulumi.Input[str] error_source: DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        :param pulumi.Input[str] message_id: The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        :param pulumi.Input[str] reason: The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        :param pulumi.Input[str] time_created: The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        :param pulumi.Input[str] time_last_suppressed: The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _SuppressionState.__new__(_SuppressionState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["email_address"] = email_address
        __props__.__dict__["error_detail"] = error_detail
        __props__.__dict__["error_source"] = error_source
        __props__.__dict__["message_id"] = message_id
        __props__.__dict__["reason"] = reason
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_last_suppressed"] = time_last_suppressed
        return Suppression(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="emailAddress")
    def email_address(self) -> pulumi.Output[str]:
        """
        The recipient email address of the suppression.
        """
        return pulumi.get(self, "email_address")

    @property
    @pulumi.getter(name="errorDetail")
    def error_detail(self) -> pulumi.Output[str]:
        """
        The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        """
        return pulumi.get(self, "error_detail")

    @property
    @pulumi.getter(name="errorSource")
    def error_source(self) -> pulumi.Output[str]:
        """
        DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        """
        return pulumi.get(self, "error_source")

    @property
    @pulumi.getter(name="messageId")
    def message_id(self) -> pulumi.Output[str]:
        """
        The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        """
        return pulumi.get(self, "message_id")

    @property
    @pulumi.getter
    def reason(self) -> pulumi.Output[str]:
        """
        The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        """
        return pulumi.get(self, "reason")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastSuppressed")
    def time_last_suppressed(self) -> pulumi.Output[str]:
        """
        The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        """
        return pulumi.get(self, "time_last_suppressed")
