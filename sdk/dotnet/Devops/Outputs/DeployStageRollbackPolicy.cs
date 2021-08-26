// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Outputs
{

    [OutputType]
    public sealed class DeployStageRollbackPolicy
    {
        /// <summary>
        /// (Updatable) The type of policy used for rolling out a deployment stage.
        /// </summary>
        public readonly string? PolicyType;

        [OutputConstructor]
        private DeployStageRollbackPolicy(string? policyType)
        {
            PolicyType = policyType;
        }
    }
}
