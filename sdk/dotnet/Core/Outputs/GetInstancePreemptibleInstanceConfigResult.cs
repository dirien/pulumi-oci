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
    public sealed class GetInstancePreemptibleInstanceConfigResult
    {
        /// <summary>
        /// (Required) The action to run when the preemptible instance is interrupted for eviction.
        /// </summary>
        public readonly Outputs.GetInstancePreemptibleInstanceConfigPreemptionActionResult PreemptionAction;

        [OutputConstructor]
        private GetInstancePreemptibleInstanceConfigResult(Outputs.GetInstancePreemptibleInstanceConfigPreemptionActionResult preemptionAction)
        {
            PreemptionAction = preemptionAction;
        }
    }
}
