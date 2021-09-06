// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Audit.Outputs
{

    [OutputType]
    public sealed class GetEventsAuditEventDataStateChangeResult
    {
        /// <summary>
        /// Provides the current state of fields that may have changed during an operation. To determine how the current operation changed a resource, compare the information in this attribute to  `previous`.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Current;
        /// <summary>
        /// Provides the previous state of fields that may have changed during an operation. To determine how the current operation changed a resource, compare the information in this attribute to  `current`.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Previous;

        [OutputConstructor]
        private GetEventsAuditEventDataStateChangeResult(
            ImmutableDictionary<string, object> current,

            ImmutableDictionary<string, object> previous)
        {
            Current = current;
            Previous = previous;
        }
    }
}
