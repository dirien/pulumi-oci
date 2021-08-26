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
    public sealed class DeploymentSpecificationRouteBackend
    {
        /// <summary>
        /// (Updatable) The body of the stock response from the mock backend.
        /// </summary>
        public readonly string? Body;
        /// <summary>
        /// (Updatable) Defines a timeout for establishing a connection with a proxied server.
        /// </summary>
        public readonly double? ConnectTimeoutInSeconds;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
        /// </summary>
        public readonly string? FunctionId;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly ImmutableArray<Outputs.DeploymentSpecificationRouteBackendHeader> Headers;
        /// <summary>
        /// (Updatable) Defines whether or not to uphold SSL verification.
        /// </summary>
        public readonly bool? IsSslVerifyDisabled;
        /// <summary>
        /// (Updatable) Defines a timeout for reading a response from the proxied server.
        /// </summary>
        public readonly double? ReadTimeoutInSeconds;
        /// <summary>
        /// (Updatable) Defines a timeout for transmitting a request to the proxied server.
        /// </summary>
        public readonly double? SendTimeoutInSeconds;
        /// <summary>
        /// (Updatable) The status code of the stock response from the mock backend.
        /// </summary>
        public readonly int? Status;
        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly string? Url;

        [OutputConstructor]
        private DeploymentSpecificationRouteBackend(
            string? body,

            double? connectTimeoutInSeconds,

            string? functionId,

            ImmutableArray<Outputs.DeploymentSpecificationRouteBackendHeader> headers,

            bool? isSslVerifyDisabled,

            double? readTimeoutInSeconds,

            double? sendTimeoutInSeconds,

            int? status,

            string type,

            string? url)
        {
            Body = body;
            ConnectTimeoutInSeconds = connectTimeoutInSeconds;
            FunctionId = functionId;
            Headers = headers;
            IsSslVerifyDisabled = isSslVerifyDisabled;
            ReadTimeoutInSeconds = readTimeoutInSeconds;
            SendTimeoutInSeconds = sendTimeoutInSeconds;
            Status = status;
            Type = type;
            Url = url;
        }
    }
}
