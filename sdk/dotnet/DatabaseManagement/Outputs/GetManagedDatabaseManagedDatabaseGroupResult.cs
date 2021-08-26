// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseManagedDatabaseGroupResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the Managed Database.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetManagedDatabaseManagedDatabaseGroupResult(
            string compartmentId,

            string id,

            string name)
        {
            CompartmentId = compartmentId;
            Id = id;
            Name = name;
        }
    }
}
