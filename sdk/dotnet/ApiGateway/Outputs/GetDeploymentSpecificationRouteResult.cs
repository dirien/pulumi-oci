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
    public sealed class GetDeploymentSpecificationRouteResult
    {
        /// <summary>
        /// The backend to forward requests to.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRouteBackendResult Backend;
        /// <summary>
        /// Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRouteLoggingPoliciesResult LoggingPolicies;
        /// <summary>
        /// A list of allowed methods on this route.
        /// </summary>
        public readonly ImmutableArray<string> Methods;
        /// <summary>
        /// A URL path pattern that must be matched on this route. The path pattern may contain a subset of RFC 6570 identifiers to allow wildcard and parameterized matching.
        /// </summary>
        public readonly string Path;
        /// <summary>
        /// Behavior applied to any requests received by the API on this route.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRouteRequestPoliciesResult RequestPolicies;
        /// <summary>
        /// Behavior applied to any responses sent by the API for requests on this route.
        /// </summary>
        public readonly Outputs.GetDeploymentSpecificationRouteResponsePoliciesResult ResponsePolicies;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteResult(
            Outputs.GetDeploymentSpecificationRouteBackendResult backend,

            Outputs.GetDeploymentSpecificationRouteLoggingPoliciesResult loggingPolicies,

            ImmutableArray<string> methods,

            string path,

            Outputs.GetDeploymentSpecificationRouteRequestPoliciesResult requestPolicies,

            Outputs.GetDeploymentSpecificationRouteResponsePoliciesResult responsePolicies)
        {
            Backend = backend;
            LoggingPolicies = loggingPolicies;
            Methods = methods;
            Path = path;
            RequestPolicies = requestPolicies;
            ResponsePolicies = responsePolicies;
        }
    }
}
