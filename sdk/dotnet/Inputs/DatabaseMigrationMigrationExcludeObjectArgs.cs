// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Inputs
{

    public sealed class DatabaseMigrationMigrationExcludeObjectArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the object (regular expression is allowed)
        /// </summary>
        [Input("object", required: true)]
        public Input<string> Object { get; set; } = null!;

        /// <summary>
        /// (Updatable) Owner of the object (regular expression is allowed)
        /// </summary>
        [Input("owner", required: true)]
        public Input<string> Owner { get; set; } = null!;

        public DatabaseMigrationMigrationExcludeObjectArgs()
        {
        }
    }
}