// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig
    {
        /// <summary>
        /// The baseline OCPU utilization for a subcore burstable VM instance. Leave this attribute blank for a non-burstable instance, or explicitly specify non-burstable with `BASELINE_1_1`.
        /// </summary>
        public readonly string? BaselineOcpuUtilization;
        /// <summary>
        /// The total amount of memory available to the instance, in gigabytes.
        /// </summary>
        public readonly double? MemoryInGbs;
        /// <summary>
        /// The total number of OCPUs available to the instance.
        /// </summary>
        public readonly double? Ocpus;

        [OutputConstructor]
        private InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfig(
            string? baselineOcpuUtilization,

            double? memoryInGbs,

            double? ocpus)
        {
            BaselineOcpuUtilization = baselineOcpuUtilization;
            MemoryInGbs = memoryInGbs;
            Ocpus = ocpus;
        }
    }
}
