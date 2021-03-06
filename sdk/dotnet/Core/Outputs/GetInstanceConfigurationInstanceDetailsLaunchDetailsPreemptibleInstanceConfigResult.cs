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
    public sealed class GetInstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigResult
    {
        /// <summary>
        /// The action to run when the preemptible instance is interrupted for eviction.
        /// </summary>
        public readonly Outputs.GetInstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigPreemptionActionResult PreemptionAction;

        [OutputConstructor]
        private GetInstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigResult(Outputs.GetInstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigPreemptionActionResult preemptionAction)
        {
            PreemptionAction = preemptionAction;
        }
    }
}
