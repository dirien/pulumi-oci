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
    public sealed class ManagedDatabasesChangeDatabaseParameterParameter
    {
        /// <summary>
        /// The parameter name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// A comment string to associate with the change in parameter value. It cannot contain control characters or a line break.
        /// </summary>
        public readonly string? UpdateComment;
        /// <summary>
        /// The parameter value.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private ManagedDatabasesChangeDatabaseParameterParameter(
            string name,

            string? updateComment,

            string value)
        {
            Name = name;
            UpdateComment = updateComment;
            Value = value;
        }
    }
}