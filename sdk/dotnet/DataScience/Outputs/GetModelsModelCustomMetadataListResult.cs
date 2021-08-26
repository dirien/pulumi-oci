// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetModelsModelCustomMetadataListResult
    {
        /// <summary>
        /// Category of model metadata which should be null for defined metadata.For custom metadata is should be one of the following values "Performance,Training Profile,Training and Validation Datasets,Training Environment,other".
        /// </summary>
        public readonly string Category;
        /// <summary>
        /// A short description of the model.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// key of the model Metadata. This can be custom key(user defined) as well as Oracle Cloud Infrastructure defined. Example of Oracle defined keys - useCaseType, libraryName, libraryVersion, estimatorClass, hyperParameters. Example of user defined keys - BaseModel
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Value of model metadata
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetModelsModelCustomMetadataListResult(
            string category,

            string description,

            string key,

            string value)
        {
            Category = category;
            Description = description;
            Key = key;
            Value = value;
        }
    }
}
