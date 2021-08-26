// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class JobProgress
    {
        /// <summary>
        /// Current phase of the job.
        /// </summary>
        public readonly string? CurrentPhase;
        /// <summary>
        /// Current status of the job.
        /// </summary>
        public readonly string? CurrentStatus;
        /// <summary>
        /// List of phase status for the job.
        /// </summary>
        public readonly ImmutableArray<Outputs.JobProgressPhase> Phases;

        [OutputConstructor]
        private JobProgress(
            string? currentPhase,

            string? currentStatus,

            ImmutableArray<Outputs.JobProgressPhase> phases)
        {
            CurrentPhase = currentPhase;
            CurrentStatus = currentStatus;
            Phases = phases;
        }
    }
}
