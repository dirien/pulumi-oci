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
    public sealed class GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsAuthHeaderResult
    {
        /// <summary>
        /// Name of the header.
        /// </summary>
        public readonly string HeaderName;
        /// <summary>
        /// Value of the header.
        /// </summary>
        public readonly string HeaderValue;

        [OutputConstructor]
        private GetMonitorsMonitorCollectionItemConfigurationReqAuthenticationDetailsAuthHeaderResult(
            string headerName,

            string headerValue)
        {
            HeaderName = headerName;
            HeaderValue = headerValue;
        }
    }
}
