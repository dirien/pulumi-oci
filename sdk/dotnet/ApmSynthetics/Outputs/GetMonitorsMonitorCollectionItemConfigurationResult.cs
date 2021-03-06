// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class GetMonitorsMonitorCollectionItemConfigurationResult
    {
        /// <summary>
        /// Type of configuration.
        /// </summary>
        public readonly string ConfigType;
        /// <summary>
        /// If certificate validation is enabled, then the call will fail in case of certification errors.
        /// </summary>
        public readonly bool IsCertificateValidationEnabled;
        /// <summary>
        /// If isFailureRetried is enabled, then a failed call will be retried.
        /// </summary>
        public readonly bool IsFailureRetried;
        /// <summary>
        /// If redirection enabled, then redirects will be allowed while accessing target URL.
        /// </summary>
        public readonly bool IsRedirectionEnabled;
        /// <summary>
        /// Details for request HTTP authentication.
        /// </summary>
        public readonly Outputs.GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsResult ReqAuthenticationDetails;
        /// <summary>
        /// Request http authentication scheme.
        /// </summary>
        public readonly string ReqAuthenticationScheme;
        /// <summary>
        /// List of request headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationRequestHeaderResult> RequestHeaders;
        /// <summary>
        /// Request HTTP method.
        /// </summary>
        public readonly string RequestMethod;
        /// <summary>
        /// Request post body content.
        /// </summary>
        public readonly string RequestPostBody;
        /// <summary>
        /// List of request query params. Example: `[{"paramName": "sortOrder", "paramValue": "asc"}]`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationRequestQueryParamResult> RequestQueryParams;
        /// <summary>
        /// Expected HTTP response codes. For status code range, set values such as 2xx, 3xx.
        /// </summary>
        public readonly ImmutableArray<string> VerifyResponseCodes;
        /// <summary>
        /// Verify response content against regular expression based string. If response content does not match the verifyResponseContent value, then it will be considered a failure.
        /// </summary>
        public readonly string VerifyResponseContent;
        /// <summary>
        /// Verify all the search strings present in response. If any search string is not present in the response, then it will be considered as a failure.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationVerifyTextResult> VerifyTexts;

        [OutputConstructor]
        private GetMonitorsMonitorCollectionItemConfigurationResult(
            string configType,

            bool isCertificateValidationEnabled,

            bool isFailureRetried,

            bool isRedirectionEnabled,

            Outputs.GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsResult reqAuthenticationDetails,

            string reqAuthenticationScheme,

            ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationRequestHeaderResult> requestHeaders,

            string requestMethod,

            string requestPostBody,

            ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationRequestQueryParamResult> requestQueryParams,

            ImmutableArray<string> verifyResponseCodes,

            string verifyResponseContent,

            ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationVerifyTextResult> verifyTexts)
        {
            ConfigType = configType;
            IsCertificateValidationEnabled = isCertificateValidationEnabled;
            IsFailureRetried = isFailureRetried;
            IsRedirectionEnabled = isRedirectionEnabled;
            ReqAuthenticationDetails = reqAuthenticationDetails;
            ReqAuthenticationScheme = reqAuthenticationScheme;
            RequestHeaders = requestHeaders;
            RequestMethod = requestMethod;
            RequestPostBody = requestPostBody;
            RequestQueryParams = requestQueryParams;
            VerifyResponseCodes = verifyResponseCodes;
            VerifyResponseContent = verifyResponseContent;
            VerifyTexts = verifyTexts;
        }
    }
}
