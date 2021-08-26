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
    public sealed class MonitorConfigurationReqAuthenticationDetails
    {
        /// <summary>
        /// (Updatable) List of authentication headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        /// </summary>
        public readonly ImmutableArray<Outputs.MonitorConfigurationReqAuthenticationDetailsAuthHeader> AuthHeaders;
        /// <summary>
        /// (Updatable) Request method.
        /// </summary>
        public readonly string? AuthRequestMethod;
        /// <summary>
        /// (Updatable) Request post body.
        /// </summary>
        public readonly string? AuthRequestPostBody;
        /// <summary>
        /// (Updatable) Authentication token.
        /// </summary>
        public readonly string? AuthToken;
        /// <summary>
        /// (Updatable) URL to get authetication token.
        /// </summary>
        public readonly string? AuthUrl;
        /// <summary>
        /// (Updatable) Username for authentication.
        /// </summary>
        public readonly string? AuthUserName;
        /// <summary>
        /// (Updatable) User password for authentication.
        /// </summary>
        public readonly string? AuthUserPassword;
        /// <summary>
        /// (Updatable) Request http oauth scheme.
        /// </summary>
        public readonly string? OauthScheme;

        [OutputConstructor]
        private MonitorConfigurationReqAuthenticationDetails(
            ImmutableArray<Outputs.MonitorConfigurationReqAuthenticationDetailsAuthHeader> authHeaders,

            string? authRequestMethod,

            string? authRequestPostBody,

            string? authToken,

            string? authUrl,

            string? authUserName,

            string? authUserPassword,

            string? oauthScheme)
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
