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
    public sealed class GetMysqlShapesShapeResult
    {
        /// <summary>
        /// The number of CPU Cores the Instance provides. These are "OCPU"s.
        /// </summary>
        public readonly int CpuCoreCount;
        /// <summary>
        /// Return shapes that are supported by the service feature.
        /// </summary>
        public readonly ImmutableArray<string> IsSupportedFors;
        /// <summary>
        /// The amount of RAM the Instance provides. This is an IEC base-2 number.
        /// </summary>
        public readonly int MemorySizeInGbs;
        /// <summary>
        /// Name
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetMysqlShapesShapeResult(
            int cpuCoreCount,

            ImmutableArray<string> isSupportedFors,

            int memorySizeInGbs,

            string name)
        {
            CpuCoreCount = cpuCoreCount;
            IsSupportedFors = isSupportedFors;
            MemorySizeInGbs = memorySizeInGbs;
            Name = name;
        }
    }
}