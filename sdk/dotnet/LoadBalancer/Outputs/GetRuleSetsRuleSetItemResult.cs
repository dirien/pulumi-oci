// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetRuleSetsRuleSetItemResult
    {
        /// <summary>
        /// The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
        /// </summary>
        public readonly string Action;
        /// <summary>
        /// The list of HTTP methods allowed for this listener.
        /// </summary>
        public readonly ImmutableArray<string> AllowedMethods;
        /// <summary>
        /// Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If "true", invalid characters are allowed in the HTTP header. If "false", invalid characters are not allowed in the HTTP header 
        /// * `conditions` -
        /// </summary>
        public readonly bool AreInvalidCharactersAllowed;
        public readonly ImmutableArray<Outputs.GetRuleSetsRuleSetItemConditionResult> Conditions;
        /// <summary>
        /// A brief description of the access control rule. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A header name that conforms to RFC 7230.  Example: `example_header_name`
        /// </summary>
        public readonly string Header;
        /// <summary>
        /// The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
        /// </summary>
        public readonly int HttpLargeHeaderSizeInKb;
        /// <summary>
        /// A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
        /// *  value cannot contain `$`
        /// *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
        /// </summary>
        public readonly string Prefix;
        /// <summary>
        /// An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
        /// </summary>
        public readonly Outputs.GetRuleSetsRuleSetItemRedirectUriResult RedirectUri;
        /// <summary>
        /// The HTTP status code to return when the incoming request is redirected.
        /// </summary>
        public readonly int ResponseCode;
        /// <summary>
        /// The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
        /// </summary>
        public readonly int StatusCode;
        /// <summary>
        /// A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
        /// *  value cannot contain `$`
        /// *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
        /// </summary>
        public readonly string Suffix;
        /// <summary>
        /// A header value that conforms to RFC 7230. With the following exceptions:
        /// *  value cannot contain `$`
        /// *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetRuleSetsRuleSetItemResult(
            string action,

            ImmutableArray<string> allowedMethods,

            bool areInvalidCharactersAllowed,

            ImmutableArray<Outputs.GetRuleSetsRuleSetItemConditionResult> conditions,

            string description,

            string header,

            int httpLargeHeaderSizeInKb,

            string prefix,

            Outputs.GetRuleSetsRuleSetItemRedirectUriResult redirectUri,

            int responseCode,

            int statusCode,

            string suffix,

            string value)
        {
            Action = action;
            AllowedMethods = allowedMethods;
            AreInvalidCharactersAllowed = areInvalidCharactersAllowed;
            Conditions = conditions;
            Description = description;
            Header = header;
            HttpLargeHeaderSizeInKb = httpLargeHeaderSizeInKb;
            Prefix = prefix;
            RedirectUri = redirectUri;
            ResponseCode = responseCode;
            StatusCode = statusCode;
            Suffix = suffix;
            Value = value;
        }
    }
}
