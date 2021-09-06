// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetCloudVmClusterIormConfigCacheResult
    {
        /// <summary>
        /// An array of IORM settings for all the database in the Exadata DB system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCloudVmClusterIormConfigCacheDbPlanResult> DbPlans;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current value for the IORM objective. The default is `AUTO`.
        /// </summary>
        public readonly string Objective;
        /// <summary>
        /// The current state of the cloud VM cluster.
        /// </summary>
        public readonly string State;

        [OutputConstructor]
        private GetCloudVmClusterIormConfigCacheResult(
            ImmutableArray<Outputs.GetCloudVmClusterIormConfigCacheDbPlanResult> dbPlans,

            string lifecycleDetails,

            string objective,

            string state)
        {
            DbPlans = dbPlans;
            LifecycleDetails = lifecycleDetails;
            Objective = objective;
            State = state;
        }
    }
}
