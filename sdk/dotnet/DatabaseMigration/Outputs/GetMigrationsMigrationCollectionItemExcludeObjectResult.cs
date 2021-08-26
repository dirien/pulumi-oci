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
    public sealed class GetMigrationsMigrationCollectionItemExcludeObjectResult
    {
        /// <summary>
        /// Name of the object (regular expression is allowed)
        /// </summary>
        public readonly string Object;
        /// <summary>
        /// Owner of the object (regular expression is allowed)
        /// </summary>
        public readonly string Owner;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemExcludeObjectResult(
            string @object,

            string owner)
        {
            Object = @object;
            Owner = owner;
        }
    }
}