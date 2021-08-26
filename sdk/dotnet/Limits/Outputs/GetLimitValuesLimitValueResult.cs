// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Limits.Outputs
{

    [OutputType]
    public sealed class GetLimitValuesLimitValueResult
    {
        /// <summary>
        /// Filter entries by availability domain. This implies that only AD-specific values are returned.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// Optional field, can be used to see a specific resource limit value.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Filter entries by scope type.
        /// </summary>
        public readonly string ScopeType;
        /// <summary>
        /// The resource limit value.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetLimitValuesLimitValueResult(
            string availabilityDomain,

            string name,

            string scopeType,

            string value)
        {
            AvailabilityDomain = availabilityDomain;
            Name = name;
            ScopeType = scopeType;
            Value = value;
        }
    }
}
