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
    public sealed class GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsResult
    {
        /// <summary>
        /// List of authentication headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsAuthHeaderResult> AuthHeaders;
        /// <summary>
        /// Request method.
        /// </summary>
        public readonly string AuthRequestMethod;
        /// <summary>
        /// Request post body.
        /// </summary>
        public readonly string AuthRequestPostBody;
        /// <summary>
        /// Authentication token.
        /// </summary>
        public readonly string AuthToken;
        /// <summary>
        /// URL to get authetication token.
        /// </summary>
        public readonly string AuthUrl;
        /// <summary>
        /// Username for authentication.
        /// </summary>
        public readonly string AuthUserName;
        /// <summary>
        /// User password for authentication.
        /// </summary>
        public readonly string AuthUserPassword;
        /// <summary>
        /// Request http oauth scheme.
        /// </summary>
        public readonly string OauthScheme;

        [OutputConstructor]
        private GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsResult(
            ImmutableArray<Outputs.GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsAuthHeaderResult> authHeaders,

            string authRequestMethod,

            string authRequestPostBody,

            string authToken,

            string authUrl,

            string authUserName,

            string authUserPassword,

            string oauthScheme)
        {
            AuthHeaders = authHeaders;
            AuthRequestMethod = authRequestMethod;
            AuthRequestPostBody = authRequestPostBody;
            AuthToken = authToken;
            AuthUrl = authUrl;
            AuthUserName = authUserName;
            AuthUserPassword = authUserPassword;
            OauthScheme = oauthScheme;
        }
    }
}
