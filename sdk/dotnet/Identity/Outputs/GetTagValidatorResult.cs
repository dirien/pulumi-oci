// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetTagValidatorResult
    {
        /// <summary>
        /// Specifies the type of validation: a static value (no validation) or a list.
        /// </summary>
        public readonly string ValidatorType;
        /// <summary>
        /// The list of allowed values for a definedTag value.
        /// </summary>
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetTagValidatorResult(
            string validatorType,

            ImmutableArray<string> values)
        {
            ValidatorType = validatorType;
            Values = values;
        }
    }
}
