// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class ModelDefinedMetadataListGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Category of model metadata which should be null for defined metadata.For custom metadata is should be one of the following values "Performance,Training Profile,Training and Validation Datasets,Training Environment,other".
        /// </summary>
        [Input("category")]
        public Input<string>? Category { get; set; }

        /// <summary>
        /// (Updatable) A short description of the model.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) key of the model Metadata. This can be custom key(user defined) as well as Oracle Cloud Infrastructure defined. Example of Oracle defined keys - useCaseType, libraryName, libraryVersion, estimatorClass, hyperParameters. Example of user defined keys - BaseModel
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) Value of model metadata
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public ModelDefinedMetadataListGetArgs()
        {
        }
    }
}
