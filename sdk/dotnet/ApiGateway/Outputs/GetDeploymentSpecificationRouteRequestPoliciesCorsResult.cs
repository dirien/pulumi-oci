// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetDeploymentSpecificationRouteRequestPoliciesCorsResult
    {
        /// <summary>
        /// The list of headers that will be allowed from the client via the Access-Control-Allow-Headers header. '*' will allow all headers.
        /// </summary>
        public readonly ImmutableArray<string> AllowedHeaders;
        /// <summary>
        /// The list of allowed HTTP methods that will be returned for the preflight OPTIONS request in the Access-Control-Allow-Methods header. '*' will allow all methods.
        /// </summary>
        public readonly ImmutableArray<string> AllowedMethods;
        /// <summary>
        /// The list of allowed origins that the CORS handler will use to respond to CORS requests. The gateway will send the Access-Control-Allow-Origin header with the best origin match for the circumstances. '*' will match any origins, and 'null' will match queries from 'file:' origins. All other origins must be qualified with the scheme, full hostname, and port if necessary.
        /// </summary>
        public readonly ImmutableArray<string> AllowedOrigins;
        /// <summary>
        /// The list of headers that the client will be allowed to see from the response as indicated by the Access-Control-Expose-Headers header. '*' will expose all headers.
        /// </summary>
        public readonly ImmutableArray<string> ExposedHeaders;
        /// <summary>
        /// Whether to send the Access-Control-Allow-Credentials header to allow CORS requests with cookies.
        /// </summary>
        public readonly bool IsAllowCredentialsEnabled;
        /// <summary>
        /// The time in seconds for the client to cache preflight responses. This is sent as the Access-Control-Max-Age if greater than 0.
        /// </summary>
        public readonly int MaxAgeInSeconds;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteRequestPoliciesCorsResult(
            ImmutableArray<string> allowedHeaders,

            ImmutableArray<string> allowedMethods,

            ImmutableArray<string> allowedOrigins,

            ImmutableArray<string> exposedHeaders,

            bool isAllowCredentialsEnabled,

            int maxAgeInSeconds)
        {
            AllowedHeaders = allowedHeaders;
            AllowedMethods = allowedMethods;
            AllowedOrigins = allowedOrigins;
            ExposedHeaders = exposedHeaders;
            IsAllowCredentialsEnabled = isAllowCredentialsEnabled;
            MaxAgeInSeconds = maxAgeInSeconds;
        }
    }
}
