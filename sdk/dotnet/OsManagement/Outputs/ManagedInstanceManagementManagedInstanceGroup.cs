// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Outputs
{

    [OutputType]
    public sealed class ManagedInstanceManagementManagedInstanceGroup
    {
        /// <summary>
        /// User friendly name
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// software source identifier
        /// </summary>
        public readonly string? Id;

        [OutputConstructor]
        private ManagedInstanceManagementManagedInstanceGroup(
            string? displayName,

            string? id)
        {
            DisplayName = displayName;
            Id = id;
        }
    }
}
