// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetAuditEventsAuditEventDataRequestResult
    {
        /// <summary>
        /// The HTTP method of the request.  Example: `GET`
        /// </summary>
        public readonly string Action;
        /// <summary>
        /// The headers of the response.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Headers;
        /// <summary>
        /// The opc-request-id of the request.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The parameters supplied by the caller during this operation.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Parameters;
        /// <summary>
        /// The full path of the API request.  Example: `/20160918/instances/ocid1.instance.oc1.phx.&lt;unique_ID&gt;`
        /// </summary>
        public readonly string Path;

        [OutputConstructor]
        private GetAuditEventsAuditEventDataRequestResult(
            string action,

            ImmutableDictionary<string, object> headers,

            string id,

            ImmutableDictionary<string, object> parameters,

            string path)
        {
            Action = action;
            Headers = headers;
            Id = id;
            Parameters = parameters;
            Path = path;
        }
    }
}