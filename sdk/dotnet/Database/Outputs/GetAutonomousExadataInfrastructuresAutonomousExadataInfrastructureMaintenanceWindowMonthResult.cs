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
    public sealed class GetAutonomousExadataInfrastructuresAutonomousExadataInfrastructureMaintenanceWindowMonthResult
    {
        /// <summary>
        /// Name of the month of the year.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetAutonomousExadataInfrastructuresAutonomousExadataInfrastructureMaintenanceWindowMonthResult(string name)
        {
            Name = name;
        }
    }
}
