// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Nosql.Outputs
{

    [OutputType]
    public sealed class GetTablesTableCollectionTableLimitsResult
    {
        /// <summary>
        /// Maximum sustained read throughput limit for the table.
        /// </summary>
        public readonly int MaxReadUnits;
        /// <summary>
        /// Maximum size of storage used by the table.
        /// </summary>
        public readonly int MaxStorageInGbs;
        /// <summary>
        /// Maximum sustained write throughput limit for the table.
        /// </summary>
        public readonly int MaxWriteUnits;

        [OutputConstructor]
        private GetTablesTableCollectionTableLimitsResult(
            int maxReadUnits,

            int maxStorageInGbs,

            int maxWriteUnits)
        {
            MaxReadUnits = maxReadUnits;
            MaxStorageInGbs = maxStorageInGbs;
            MaxWriteUnits = maxWriteUnits;
        }
    }
}
