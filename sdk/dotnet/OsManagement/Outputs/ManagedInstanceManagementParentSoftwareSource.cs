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
    public sealed class ManagedInstanceManagementParentSoftwareSource
    {
        /// <summary>
        /// software source identifier
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// software source name
        /// </summary>
        public readonly string? Name;

        [OutputConstructor]
        private ManagedInstanceManagementParentSoftwareSource(
            string? id,

            string? name)
        {
            Id = id;
            Name = name;
        }
    }
}
