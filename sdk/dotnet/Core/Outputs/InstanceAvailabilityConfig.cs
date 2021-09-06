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
    public sealed class InstanceAvailabilityConfig
    {
        /// <summary>
        /// (Updatable) Whether live migration is preferred for infrastructure maintenance.  If null preference is specified, live migration will be preferred for infrastructure maintenance for applicable instances.
        /// </summary>
        public readonly bool? IsLiveMigrationPreferred;
        /// <summary>
        /// (Updatable) The lifecycle state for an instance when it is recovered after infrastructure maintenance.
        /// </summary>
        public readonly string? RecoveryAction;

        [OutputConstructor]
        private InstanceAvailabilityConfig(
            bool? isLiveMigrationPreferred,

            string? recoveryAction)
        {
            IsLiveMigrationPreferred = isLiveMigrationPreferred;
            RecoveryAction = recoveryAction;
        }
    }
}
