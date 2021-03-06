# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'MonitorConfigurationArgs',
    'MonitorConfigurationReqAuthenticationDetailsArgs',
    'MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs',
    'MonitorConfigurationRequestHeaderArgs',
    'MonitorConfigurationRequestQueryParamArgs',
    'MonitorConfigurationVerifyTextArgs',
    'MonitorScriptParameterArgs',
    'MonitorScriptParameterMonitorScriptParameterArgs',
    'ScriptMonitorStatusCountMapArgs',
    'ScriptParameterArgs',
    'ScriptParameterScriptParameterArgs',
    'GetMonitorsFilterArgs',
    'GetPublicVantagePointsFilterArgs',
    'GetScriptsFilterArgs',
]

@pulumi.input_type
class MonitorConfigurationArgs:
    def __init__(__self__, *,
                 config_type: Optional[pulumi.Input[str]] = None,
                 is_certificate_validation_enabled: Optional[pulumi.Input[bool]] = None,
                 is_failure_retried: Optional[pulumi.Input[bool]] = None,
                 is_redirection_enabled: Optional[pulumi.Input[bool]] = None,
                 req_authentication_details: Optional[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsArgs']] = None,
                 req_authentication_scheme: Optional[pulumi.Input[str]] = None,
                 request_headers: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestHeaderArgs']]]] = None,
                 request_method: Optional[pulumi.Input[str]] = None,
                 request_post_body: Optional[pulumi.Input[str]] = None,
                 request_query_params: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestQueryParamArgs']]]] = None,
                 verify_response_codes: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 verify_response_content: Optional[pulumi.Input[str]] = None,
                 verify_texts: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationVerifyTextArgs']]]] = None):
        """
        :param pulumi.Input[str] config_type: (Updatable) Type of configuration.
        :param pulumi.Input[bool] is_certificate_validation_enabled: (Updatable) If certificate validation is enabled, then the call will fail in case of certification errors.
        :param pulumi.Input[bool] is_failure_retried: (Updatable) If isFailureRetried is enabled, then a failed call will be retried.
        :param pulumi.Input[bool] is_redirection_enabled: (Updatable) If redirection enabled, then redirects will be allowed while accessing target URL.
        :param pulumi.Input['MonitorConfigurationReqAuthenticationDetailsArgs'] req_authentication_details: (Updatable) Details for request HTTP authentication.
        :param pulumi.Input[str] req_authentication_scheme: (Updatable) Request http authentication scheme.
        :param pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestHeaderArgs']]] request_headers: (Updatable) List of request headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        :param pulumi.Input[str] request_method: (Updatable) Request HTTP method.
        :param pulumi.Input[str] request_post_body: (Updatable) Request post body content.
        :param pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestQueryParamArgs']]] request_query_params: (Updatable) List of request query params. Example: `[{"paramName": "sortOrder", "paramValue": "asc"}]`
        :param pulumi.Input[Sequence[pulumi.Input[str]]] verify_response_codes: (Updatable) Expected HTTP response codes. For status code range, set values such as 2xx, 3xx.
        :param pulumi.Input[str] verify_response_content: (Updatable) Verify response content against regular expression based string. If response content does not match the verifyResponseContent value, then it will be considered a failure.
        :param pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationVerifyTextArgs']]] verify_texts: (Updatable) Verify all the search strings present in response. If any search string is not present in the response, then it will be considered as a failure.
        """
        if config_type is not None:
            pulumi.set(__self__, "config_type", config_type)
        if is_certificate_validation_enabled is not None:
            pulumi.set(__self__, "is_certificate_validation_enabled", is_certificate_validation_enabled)
        if is_failure_retried is not None:
            pulumi.set(__self__, "is_failure_retried", is_failure_retried)
        if is_redirection_enabled is not None:
            pulumi.set(__self__, "is_redirection_enabled", is_redirection_enabled)
        if req_authentication_details is not None:
            pulumi.set(__self__, "req_authentication_details", req_authentication_details)
        if req_authentication_scheme is not None:
            pulumi.set(__self__, "req_authentication_scheme", req_authentication_scheme)
        if request_headers is not None:
            pulumi.set(__self__, "request_headers", request_headers)
        if request_method is not None:
            pulumi.set(__self__, "request_method", request_method)
        if request_post_body is not None:
            pulumi.set(__self__, "request_post_body", request_post_body)
        if request_query_params is not None:
            pulumi.set(__self__, "request_query_params", request_query_params)
        if verify_response_codes is not None:
            pulumi.set(__self__, "verify_response_codes", verify_response_codes)
        if verify_response_content is not None:
            pulumi.set(__self__, "verify_response_content", verify_response_content)
        if verify_texts is not None:
            pulumi.set(__self__, "verify_texts", verify_texts)

    @property
    @pulumi.getter(name="configType")
    def config_type(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Type of configuration.
        """
        return pulumi.get(self, "config_type")

    @config_type.setter
    def config_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "config_type", value)

    @property
    @pulumi.getter(name="isCertificateValidationEnabled")
    def is_certificate_validation_enabled(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If certificate validation is enabled, then the call will fail in case of certification errors.
        """
        return pulumi.get(self, "is_certificate_validation_enabled")

    @is_certificate_validation_enabled.setter
    def is_certificate_validation_enabled(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_certificate_validation_enabled", value)

    @property
    @pulumi.getter(name="isFailureRetried")
    def is_failure_retried(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If isFailureRetried is enabled, then a failed call will be retried.
        """
        return pulumi.get(self, "is_failure_retried")

    @is_failure_retried.setter
    def is_failure_retried(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_failure_retried", value)

    @property
    @pulumi.getter(name="isRedirectionEnabled")
    def is_redirection_enabled(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If redirection enabled, then redirects will be allowed while accessing target URL.
        """
        return pulumi.get(self, "is_redirection_enabled")

    @is_redirection_enabled.setter
    def is_redirection_enabled(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_redirection_enabled", value)

    @property
    @pulumi.getter(name="reqAuthenticationDetails")
    def req_authentication_details(self) -> Optional[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsArgs']]:
        """
        (Updatable) Details for request HTTP authentication.
        """
        return pulumi.get(self, "req_authentication_details")

    @req_authentication_details.setter
    def req_authentication_details(self, value: Optional[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsArgs']]):
        pulumi.set(self, "req_authentication_details", value)

    @property
    @pulumi.getter(name="reqAuthenticationScheme")
    def req_authentication_scheme(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Request http authentication scheme.
        """
        return pulumi.get(self, "req_authentication_scheme")

    @req_authentication_scheme.setter
    def req_authentication_scheme(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "req_authentication_scheme", value)

    @property
    @pulumi.getter(name="requestHeaders")
    def request_headers(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestHeaderArgs']]]]:
        """
        (Updatable) List of request headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        """
        return pulumi.get(self, "request_headers")

    @request_headers.setter
    def request_headers(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestHeaderArgs']]]]):
        pulumi.set(self, "request_headers", value)

    @property
    @pulumi.getter(name="requestMethod")
    def request_method(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Request HTTP method.
        """
        return pulumi.get(self, "request_method")

    @request_method.setter
    def request_method(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "request_method", value)

    @property
    @pulumi.getter(name="requestPostBody")
    def request_post_body(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Request post body content.
        """
        return pulumi.get(self, "request_post_body")

    @request_post_body.setter
    def request_post_body(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "request_post_body", value)

    @property
    @pulumi.getter(name="requestQueryParams")
    def request_query_params(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestQueryParamArgs']]]]:
        """
        (Updatable) List of request query params. Example: `[{"paramName": "sortOrder", "paramValue": "asc"}]`
        """
        return pulumi.get(self, "request_query_params")

    @request_query_params.setter
    def request_query_params(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationRequestQueryParamArgs']]]]):
        pulumi.set(self, "request_query_params", value)

    @property
    @pulumi.getter(name="verifyResponseCodes")
    def verify_response_codes(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) Expected HTTP response codes. For status code range, set values such as 2xx, 3xx.
        """
        return pulumi.get(self, "verify_response_codes")

    @verify_response_codes.setter
    def verify_response_codes(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "verify_response_codes", value)

    @property
    @pulumi.getter(name="verifyResponseContent")
    def verify_response_content(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Verify response content against regular expression based string. If response content does not match the verifyResponseContent value, then it will be considered a failure.
        """
        return pulumi.get(self, "verify_response_content")

    @verify_response_content.setter
    def verify_response_content(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "verify_response_content", value)

    @property
    @pulumi.getter(name="verifyTexts")
    def verify_texts(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationVerifyTextArgs']]]]:
        """
        (Updatable) Verify all the search strings present in response. If any search string is not present in the response, then it will be considered as a failure.
        """
        return pulumi.get(self, "verify_texts")

    @verify_texts.setter
    def verify_texts(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationVerifyTextArgs']]]]):
        pulumi.set(self, "verify_texts", value)


@pulumi.input_type
class MonitorConfigurationReqAuthenticationDetailsArgs:
    def __init__(__self__, *,
                 auth_headers: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs']]]] = None,
                 auth_request_method: Optional[pulumi.Input[str]] = None,
                 auth_request_post_body: Optional[pulumi.Input[str]] = None,
                 auth_token: Optional[pulumi.Input[str]] = None,
                 auth_url: Optional[pulumi.Input[str]] = None,
                 auth_user_name: Optional[pulumi.Input[str]] = None,
                 auth_user_password: Optional[pulumi.Input[str]] = None,
                 oauth_scheme: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs']]] auth_headers: (Updatable) List of authentication headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        :param pulumi.Input[str] auth_request_method: (Updatable) Request method.
        :param pulumi.Input[str] auth_request_post_body: (Updatable) Request post body.
        :param pulumi.Input[str] auth_token: (Updatable) Authentication token.
        :param pulumi.Input[str] auth_url: (Updatable) URL to get authetication token.
        :param pulumi.Input[str] auth_user_name: (Updatable) Username for authentication.
        :param pulumi.Input[str] auth_user_password: (Updatable) User password for authentication.
        :param pulumi.Input[str] oauth_scheme: (Updatable) Request http oauth scheme.
        """
        if auth_headers is not None:
            pulumi.set(__self__, "auth_headers", auth_headers)
        if auth_request_method is not None:
            pulumi.set(__self__, "auth_request_method", auth_request_method)
        if auth_request_post_body is not None:
            pulumi.set(__self__, "auth_request_post_body", auth_request_post_body)
        if auth_token is not None:
            pulumi.set(__self__, "auth_token", auth_token)
        if auth_url is not None:
            pulumi.set(__self__, "auth_url", auth_url)
        if auth_user_name is not None:
            pulumi.set(__self__, "auth_user_name", auth_user_name)
        if auth_user_password is not None:
            pulumi.set(__self__, "auth_user_password", auth_user_password)
        if oauth_scheme is not None:
            pulumi.set(__self__, "oauth_scheme", oauth_scheme)

    @property
    @pulumi.getter(name="authHeaders")
    def auth_headers(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs']]]]:
        """
        (Updatable) List of authentication headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        """
        return pulumi.get(self, "auth_headers")

    @auth_headers.setter
    def auth_headers(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs']]]]):
        pulumi.set(self, "auth_headers", value)

    @property
    @pulumi.getter(name="authRequestMethod")
    def auth_request_method(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Request method.
        """
        return pulumi.get(self, "auth_request_method")

    @auth_request_method.setter
    def auth_request_method(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "auth_request_method", value)

    @property
    @pulumi.getter(name="authRequestPostBody")
    def auth_request_post_body(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Request post body.
        """
        return pulumi.get(self, "auth_request_post_body")

    @auth_request_post_body.setter
    def auth_request_post_body(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "auth_request_post_body", value)

    @property
    @pulumi.getter(name="authToken")
    def auth_token(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Authentication token.
        """
        return pulumi.get(self, "auth_token")

    @auth_token.setter
    def auth_token(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "auth_token", value)

    @property
    @pulumi.getter(name="authUrl")
    def auth_url(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) URL to get authetication token.
        """
        return pulumi.get(self, "auth_url")

    @auth_url.setter
    def auth_url(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "auth_url", value)

    @property
    @pulumi.getter(name="authUserName")
    def auth_user_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Username for authentication.
        """
        return pulumi.get(self, "auth_user_name")

    @auth_user_name.setter
    def auth_user_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "auth_user_name", value)

    @property
    @pulumi.getter(name="authUserPassword")
    def auth_user_password(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) User password for authentication.
        """
        return pulumi.get(self, "auth_user_password")

    @auth_user_password.setter
    def auth_user_password(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "auth_user_password", value)

    @property
    @pulumi.getter(name="oauthScheme")
    def oauth_scheme(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Request http oauth scheme.
        """
        return pulumi.get(self, "oauth_scheme")

    @oauth_scheme.setter
    def oauth_scheme(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "oauth_scheme", value)


@pulumi.input_type
class MonitorConfigurationReqAuthenticationDetailsAuthHeaderArgs:
    def __init__(__self__, *,
                 header_name: Optional[pulumi.Input[str]] = None,
                 header_value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] header_name: (Updatable) Name of the header.
        :param pulumi.Input[str] header_value: (Updatable) Value of the header.
        """
        if header_name is not None:
            pulumi.set(__self__, "header_name", header_name)
        if header_value is not None:
            pulumi.set(__self__, "header_value", header_value)

    @property
    @pulumi.getter(name="headerName")
    def header_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Name of the header.
        """
        return pulumi.get(self, "header_name")

    @header_name.setter
    def header_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "header_name", value)

    @property
    @pulumi.getter(name="headerValue")
    def header_value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value of the header.
        """
        return pulumi.get(self, "header_value")

    @header_value.setter
    def header_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "header_value", value)


@pulumi.input_type
class MonitorConfigurationRequestHeaderArgs:
    def __init__(__self__, *,
                 header_name: Optional[pulumi.Input[str]] = None,
                 header_value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] header_name: (Updatable) Name of the header.
        :param pulumi.Input[str] header_value: (Updatable) Value of the header.
        """
        if header_name is not None:
            pulumi.set(__self__, "header_name", header_name)
        if header_value is not None:
            pulumi.set(__self__, "header_value", header_value)

    @property
    @pulumi.getter(name="headerName")
    def header_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Name of the header.
        """
        return pulumi.get(self, "header_name")

    @header_name.setter
    def header_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "header_name", value)

    @property
    @pulumi.getter(name="headerValue")
    def header_value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value of the header.
        """
        return pulumi.get(self, "header_value")

    @header_value.setter
    def header_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "header_value", value)


@pulumi.input_type
class MonitorConfigurationRequestQueryParamArgs:
    def __init__(__self__, *,
                 param_name: Optional[pulumi.Input[str]] = None,
                 param_value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] param_name: (Updatable) Name of the parameter.
        :param pulumi.Input[str] param_value: (Updatable) Value of the parameter.
        """
        if param_name is not None:
            pulumi.set(__self__, "param_name", param_name)
        if param_value is not None:
            pulumi.set(__self__, "param_value", param_value)

    @property
    @pulumi.getter(name="paramName")
    def param_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Name of the parameter.
        """
        return pulumi.get(self, "param_name")

    @param_name.setter
    def param_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_name", value)

    @property
    @pulumi.getter(name="paramValue")
    def param_value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value of the parameter.
        """
        return pulumi.get(self, "param_value")

    @param_value.setter
    def param_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_value", value)


@pulumi.input_type
class MonitorConfigurationVerifyTextArgs:
    def __init__(__self__, *,
                 text: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] text: (Updatable) Verification text in the response.
        """
        if text is not None:
            pulumi.set(__self__, "text", text)

    @property
    @pulumi.getter
    def text(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Verification text in the response.
        """
        return pulumi.get(self, "text")

    @text.setter
    def text(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "text", value)


@pulumi.input_type
class MonitorScriptParameterArgs:
    def __init__(__self__, *,
                 param_name: pulumi.Input[str],
                 param_value: pulumi.Input[str],
                 is_overwritten: Optional[pulumi.Input[bool]] = None,
                 is_secret: Optional[pulumi.Input[bool]] = None,
                 monitor_script_parameter: Optional[pulumi.Input['MonitorScriptParameterMonitorScriptParameterArgs']] = None):
        """
        :param pulumi.Input[str] param_name: (Updatable) Name of the parameter.
        :param pulumi.Input[str] param_value: (Updatable) Value of the parameter.
        :param pulumi.Input[bool] is_overwritten: If parameter value is default or overwritten.
        :param pulumi.Input[bool] is_secret: Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
        :param pulumi.Input['MonitorScriptParameterMonitorScriptParameterArgs'] monitor_script_parameter: Details of the script parameter that can be used to overwrite the parameter present in the script.
        """
        pulumi.set(__self__, "param_name", param_name)
        pulumi.set(__self__, "param_value", param_value)
        if is_overwritten is not None:
            pulumi.set(__self__, "is_overwritten", is_overwritten)
        if is_secret is not None:
            pulumi.set(__self__, "is_secret", is_secret)
        if monitor_script_parameter is not None:
            pulumi.set(__self__, "monitor_script_parameter", monitor_script_parameter)

    @property
    @pulumi.getter(name="paramName")
    def param_name(self) -> pulumi.Input[str]:
        """
        (Updatable) Name of the parameter.
        """
        return pulumi.get(self, "param_name")

    @param_name.setter
    def param_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "param_name", value)

    @property
    @pulumi.getter(name="paramValue")
    def param_value(self) -> pulumi.Input[str]:
        """
        (Updatable) Value of the parameter.
        """
        return pulumi.get(self, "param_value")

    @param_value.setter
    def param_value(self, value: pulumi.Input[str]):
        pulumi.set(self, "param_value", value)

    @property
    @pulumi.getter(name="isOverwritten")
    def is_overwritten(self) -> Optional[pulumi.Input[bool]]:
        """
        If parameter value is default or overwritten.
        """
        return pulumi.get(self, "is_overwritten")

    @is_overwritten.setter
    def is_overwritten(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_overwritten", value)

    @property
    @pulumi.getter(name="isSecret")
    def is_secret(self) -> Optional[pulumi.Input[bool]]:
        """
        Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
        """
        return pulumi.get(self, "is_secret")

    @is_secret.setter
    def is_secret(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_secret", value)

    @property
    @pulumi.getter(name="monitorScriptParameter")
    def monitor_script_parameter(self) -> Optional[pulumi.Input['MonitorScriptParameterMonitorScriptParameterArgs']]:
        """
        Details of the script parameter that can be used to overwrite the parameter present in the script.
        """
        return pulumi.get(self, "monitor_script_parameter")

    @monitor_script_parameter.setter
    def monitor_script_parameter(self, value: Optional[pulumi.Input['MonitorScriptParameterMonitorScriptParameterArgs']]):
        pulumi.set(self, "monitor_script_parameter", value)


@pulumi.input_type
class MonitorScriptParameterMonitorScriptParameterArgs:
    def __init__(__self__, *,
                 param_name: Optional[pulumi.Input[str]] = None,
                 param_value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] param_name: (Updatable) Name of the parameter.
        :param pulumi.Input[str] param_value: (Updatable) Value of the parameter.
        """
        if param_name is not None:
            pulumi.set(__self__, "param_name", param_name)
        if param_value is not None:
            pulumi.set(__self__, "param_value", param_value)

    @property
    @pulumi.getter(name="paramName")
    def param_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Name of the parameter.
        """
        return pulumi.get(self, "param_name")

    @param_name.setter
    def param_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_name", value)

    @property
    @pulumi.getter(name="paramValue")
    def param_value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value of the parameter.
        """
        return pulumi.get(self, "param_value")

    @param_value.setter
    def param_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_value", value)


@pulumi.input_type
class ScriptMonitorStatusCountMapArgs:
    def __init__(__self__, *,
                 disabled: Optional[pulumi.Input[int]] = None,
                 enabled: Optional[pulumi.Input[int]] = None,
                 invalid: Optional[pulumi.Input[int]] = None,
                 total: Optional[pulumi.Input[int]] = None):
        """
        :param pulumi.Input[int] disabled: Number of disabled monitors using the script.
        :param pulumi.Input[int] enabled: Number of enabled monitors using the script.
        :param pulumi.Input[int] invalid: Number of invalid monitors using the script.
        :param pulumi.Input[int] total: Total number of monitors using the script.
        """
        if disabled is not None:
            pulumi.set(__self__, "disabled", disabled)
        if enabled is not None:
            pulumi.set(__self__, "enabled", enabled)
        if invalid is not None:
            pulumi.set(__self__, "invalid", invalid)
        if total is not None:
            pulumi.set(__self__, "total", total)

    @property
    @pulumi.getter
    def disabled(self) -> Optional[pulumi.Input[int]]:
        """
        Number of disabled monitors using the script.
        """
        return pulumi.get(self, "disabled")

    @disabled.setter
    def disabled(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "disabled", value)

    @property
    @pulumi.getter
    def enabled(self) -> Optional[pulumi.Input[int]]:
        """
        Number of enabled monitors using the script.
        """
        return pulumi.get(self, "enabled")

    @enabled.setter
    def enabled(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "enabled", value)

    @property
    @pulumi.getter
    def invalid(self) -> Optional[pulumi.Input[int]]:
        """
        Number of invalid monitors using the script.
        """
        return pulumi.get(self, "invalid")

    @invalid.setter
    def invalid(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "invalid", value)

    @property
    @pulumi.getter
    def total(self) -> Optional[pulumi.Input[int]]:
        """
        Total number of monitors using the script.
        """
        return pulumi.get(self, "total")

    @total.setter
    def total(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "total", value)


@pulumi.input_type
class ScriptParameterArgs:
    def __init__(__self__, *,
                 param_name: pulumi.Input[str],
                 is_overwritten: Optional[pulumi.Input[bool]] = None,
                 is_secret: Optional[pulumi.Input[bool]] = None,
                 param_value: Optional[pulumi.Input[str]] = None,
                 script_parameter: Optional[pulumi.Input['ScriptParameterScriptParameterArgs']] = None):
        """
        :param pulumi.Input[str] param_name: (Updatable) Name of the parameter.
        :param pulumi.Input[bool] is_overwritten: If parameter value is default or overwritten.
        :param pulumi.Input[bool] is_secret: (Updatable) If the parameter value is secret and should be kept confidential, then set isSecret to true.
        :param pulumi.Input[str] param_value: (Updatable) Value of the parameter.
        :param pulumi.Input['ScriptParameterScriptParameterArgs'] script_parameter: Details of the script parameters, paramName must be from the script content and these details can be used to overwrite the default parameter present in the script content.
        """
        pulumi.set(__self__, "param_name", param_name)
        if is_overwritten is not None:
            pulumi.set(__self__, "is_overwritten", is_overwritten)
        if is_secret is not None:
            pulumi.set(__self__, "is_secret", is_secret)
        if param_value is not None:
            pulumi.set(__self__, "param_value", param_value)
        if script_parameter is not None:
            pulumi.set(__self__, "script_parameter", script_parameter)

    @property
    @pulumi.getter(name="paramName")
    def param_name(self) -> pulumi.Input[str]:
        """
        (Updatable) Name of the parameter.
        """
        return pulumi.get(self, "param_name")

    @param_name.setter
    def param_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "param_name", value)

    @property
    @pulumi.getter(name="isOverwritten")
    def is_overwritten(self) -> Optional[pulumi.Input[bool]]:
        """
        If parameter value is default or overwritten.
        """
        return pulumi.get(self, "is_overwritten")

    @is_overwritten.setter
    def is_overwritten(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_overwritten", value)

    @property
    @pulumi.getter(name="isSecret")
    def is_secret(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If the parameter value is secret and should be kept confidential, then set isSecret to true.
        """
        return pulumi.get(self, "is_secret")

    @is_secret.setter
    def is_secret(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_secret", value)

    @property
    @pulumi.getter(name="paramValue")
    def param_value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value of the parameter.
        """
        return pulumi.get(self, "param_value")

    @param_value.setter
    def param_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_value", value)

    @property
    @pulumi.getter(name="scriptParameter")
    def script_parameter(self) -> Optional[pulumi.Input['ScriptParameterScriptParameterArgs']]:
        """
        Details of the script parameters, paramName must be from the script content and these details can be used to overwrite the default parameter present in the script content.
        """
        return pulumi.get(self, "script_parameter")

    @script_parameter.setter
    def script_parameter(self, value: Optional[pulumi.Input['ScriptParameterScriptParameterArgs']]):
        pulumi.set(self, "script_parameter", value)


@pulumi.input_type
class ScriptParameterScriptParameterArgs:
    def __init__(__self__, *,
                 is_secret: Optional[pulumi.Input[bool]] = None,
                 param_name: Optional[pulumi.Input[str]] = None,
                 param_value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[bool] is_secret: (Updatable) If the parameter value is secret and should be kept confidential, then set isSecret to true.
        :param pulumi.Input[str] param_name: (Updatable) Name of the parameter.
        :param pulumi.Input[str] param_value: (Updatable) Value of the parameter.
        """
        if is_secret is not None:
            pulumi.set(__self__, "is_secret", is_secret)
        if param_name is not None:
            pulumi.set(__self__, "param_name", param_name)
        if param_value is not None:
            pulumi.set(__self__, "param_value", param_value)

    @property
    @pulumi.getter(name="isSecret")
    def is_secret(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) If the parameter value is secret and should be kept confidential, then set isSecret to true.
        """
        return pulumi.get(self, "is_secret")

    @is_secret.setter
    def is_secret(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_secret", value)

    @property
    @pulumi.getter(name="paramName")
    def param_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Name of the parameter.
        """
        return pulumi.get(self, "param_name")

    @param_name.setter
    def param_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_name", value)

    @property
    @pulumi.getter(name="paramValue")
    def param_value(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value of the parameter.
        """
        return pulumi.get(self, "param_value")

    @param_value.setter
    def param_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "param_value", value)


@pulumi.input_type
class GetMonitorsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Name of the vantage point.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the vantage point.
        """
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


@pulumi.input_type
class GetPublicVantagePointsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only resources that match the entire name given.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the entire name given.
        """
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


@pulumi.input_type
class GetScriptsFilterArgs:
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


