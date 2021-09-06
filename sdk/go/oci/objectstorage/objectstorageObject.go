// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package objectstorage

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Object resource in Oracle Cloud Infrastructure Object Storage service.
//
// Creates a new object or overwrites an existing object with the same name. The maximum object size allowed by
// PutObject is 50 GiB.
//
// See [Object Names](https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/managingobjects.htm#namerequirements)
// for object naming requirements.
//
// See [Special Instructions for Object Storage PUT](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/signingrequests.htm#ObjectStoragePut)
// for request signature requirements.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/objectstorage"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := objectstorage.NewObjectstorageObject(ctx, "testObject", &objectstorage.ObjectstorageObjectArgs{
// 			Bucket:                  pulumi.Any(_var.Object_bucket),
// 			Content:                 pulumi.Any(_var.Object_content),
// 			Namespace:               pulumi.Any(_var.Object_namespace),
// 			Object:                  pulumi.Any(_var.Object_object),
// 			CacheControl:            pulumi.Any(_var.Object_cache_control),
// 			ContentDisposition:      pulumi.Any(_var.Object_content_disposition),
// 			ContentEncoding:         pulumi.Any(_var.Object_content_encoding),
// 			ContentLanguage:         pulumi.Any(_var.Object_content_language),
// 			ContentType:             pulumi.Any(_var.Object_content_type),
// 			DeleteAllObjectVersions: pulumi.Any(_var.Object_delete_all_object_versions),
// 			Metadata:                pulumi.Any(_var.Object_metadata),
// 			StorageTier:             pulumi.Any(_var.Object_storage_tier),
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// Objects can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:objectstorage/objectstorageObject:ObjectstorageObject test_object "n/{namespaceName}/b/{bucketName}/o/{objectName}"
// ```
type ObjectstorageObject struct {
	pulumi.CustomResourceState

	// The name of the bucket for the source object.
	Bucket pulumi.StringOutput `pulumi:"bucket"`
	// The optional Cache-Control header that defines the caching behavior value to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify objects that require caching restrictions.
	CacheControl pulumi.StringPtrOutput `pulumi:"cacheControl"`
	// The object to upload to the object store. Cannot be defined if `source` or `sourceUriDetails` is defined.
	Content pulumi.StringPtrOutput `pulumi:"content"`
	// The optional Content-Disposition header that defines presentational information for the object to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to let users download objects with custom filenames in a browser.
	ContentDisposition pulumi.StringPtrOutput `pulumi:"contentDisposition"`
	// The optional Content-Encoding header that defines the content encodings that were applied to the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to determine what decoding mechanisms need to be applied to obtain the media-type specified by the Content-Type header of the object.
	ContentEncoding pulumi.StringPtrOutput `pulumi:"contentEncoding"`
	// The optional Content-Language header that defines the content language of the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and differentiate objects based on a particular language.
	ContentLanguage pulumi.StringPtrOutput `pulumi:"contentLanguage"`
	// (Updatable) The content length of the body.
	ContentLength pulumi.StringOutput `pulumi:"contentLength"`
	// (Updatable) The optional base-64 header that defines the encoded MD5 hash of the body. If the optional Content-MD5 header is present, Object Storage performs an integrity check on the body of the HTTP request by computing the MD5 hash for the body and comparing it to the MD5 hash supplied in the header. If the two hashes do not match, the object is rejected and an HTTP-400 Unmatched Content MD5 error is returned with the message:
	ContentMd5 pulumi.StringOutput `pulumi:"contentMd5"`
	// The optional Content-Type header that defines the standard MIME type format of the object. Content type defaults to 'application/octet-stream' if not specified in the PutObject call. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and perform special operations on text only objects.
	ContentType pulumi.StringOutput `pulumi:"contentType"`
	// (Updatable) A boolean to delete all object versions for an object in a bucket that has or ever had versioning enabled.
	DeleteAllObjectVersions pulumi.BoolPtrOutput `pulumi:"deleteAllObjectVersions"`
	// Optional user-defined metadata key and value.
	// Note: All specified keys must be in lower case.
	Metadata pulumi.MapOutput `pulumi:"metadata"`
	// The top-level namespace of the source object.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// The name of the source object.
	Object pulumi.StringOutput `pulumi:"object"`
	// An absolute path to a file on the local system. Cannot be defined if `content` or `sourceUriDetails` is defined.
	Source pulumi.StringPtrOutput `pulumi:"source"`
	// Details of the source URI of the object in the cloud. Cannot be defined if `content` or `source` is defined.
	// Note: To enable object copy, you must authorize the service to manage objects on your behalf.
	SourceUriDetails ObjectstorageObjectSourceUriDetailsPtrOutput `pulumi:"sourceUriDetails"`
	State            pulumi.StringOutput                          `pulumi:"state"`
	// (Updatable) The storage tier that the object should be stored in. If not specified, the object will be stored in the same storage tier as the bucket.
	StorageTier   pulumi.StringOutput `pulumi:"storageTier"`
	VersionId     pulumi.StringOutput `pulumi:"versionId"`
	WorkRequestId pulumi.StringOutput `pulumi:"workRequestId"`
}

// NewObjectstorageObject registers a new resource with the given unique name, arguments, and options.
func NewObjectstorageObject(ctx *pulumi.Context,
	name string, args *ObjectstorageObjectArgs, opts ...pulumi.ResourceOption) (*ObjectstorageObject, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Bucket == nil {
		return nil, errors.New("invalid value for required argument 'Bucket'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	if args.Object == nil {
		return nil, errors.New("invalid value for required argument 'Object'")
	}
	var resource ObjectstorageObject
	err := ctx.RegisterResource("oci:objectstorage/objectstorageObject:ObjectstorageObject", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetObjectstorageObject gets an existing ObjectstorageObject resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetObjectstorageObject(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ObjectstorageObjectState, opts ...pulumi.ResourceOption) (*ObjectstorageObject, error) {
	var resource ObjectstorageObject
	err := ctx.ReadResource("oci:objectstorage/objectstorageObject:ObjectstorageObject", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ObjectstorageObject resources.
type objectstorageObjectState struct {
	// The name of the bucket for the source object.
	Bucket *string `pulumi:"bucket"`
	// The optional Cache-Control header that defines the caching behavior value to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify objects that require caching restrictions.
	CacheControl *string `pulumi:"cacheControl"`
	// The object to upload to the object store. Cannot be defined if `source` or `sourceUriDetails` is defined.
	Content *string `pulumi:"content"`
	// The optional Content-Disposition header that defines presentational information for the object to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to let users download objects with custom filenames in a browser.
	ContentDisposition *string `pulumi:"contentDisposition"`
	// The optional Content-Encoding header that defines the content encodings that were applied to the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to determine what decoding mechanisms need to be applied to obtain the media-type specified by the Content-Type header of the object.
	ContentEncoding *string `pulumi:"contentEncoding"`
	// The optional Content-Language header that defines the content language of the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and differentiate objects based on a particular language.
	ContentLanguage *string `pulumi:"contentLanguage"`
	// (Updatable) The content length of the body.
	ContentLength *string `pulumi:"contentLength"`
	// (Updatable) The optional base-64 header that defines the encoded MD5 hash of the body. If the optional Content-MD5 header is present, Object Storage performs an integrity check on the body of the HTTP request by computing the MD5 hash for the body and comparing it to the MD5 hash supplied in the header. If the two hashes do not match, the object is rejected and an HTTP-400 Unmatched Content MD5 error is returned with the message:
	ContentMd5 *string `pulumi:"contentMd5"`
	// The optional Content-Type header that defines the standard MIME type format of the object. Content type defaults to 'application/octet-stream' if not specified in the PutObject call. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and perform special operations on text only objects.
	ContentType *string `pulumi:"contentType"`
	// (Updatable) A boolean to delete all object versions for an object in a bucket that has or ever had versioning enabled.
	DeleteAllObjectVersions *bool `pulumi:"deleteAllObjectVersions"`
	// Optional user-defined metadata key and value.
	// Note: All specified keys must be in lower case.
	Metadata map[string]interface{} `pulumi:"metadata"`
	// The top-level namespace of the source object.
	Namespace *string `pulumi:"namespace"`
	// The name of the source object.
	Object *string `pulumi:"object"`
	// An absolute path to a file on the local system. Cannot be defined if `content` or `sourceUriDetails` is defined.
	Source *string `pulumi:"source"`
	// Details of the source URI of the object in the cloud. Cannot be defined if `content` or `source` is defined.
	// Note: To enable object copy, you must authorize the service to manage objects on your behalf.
	SourceUriDetails *ObjectstorageObjectSourceUriDetails `pulumi:"sourceUriDetails"`
	State            *string                              `pulumi:"state"`
	// (Updatable) The storage tier that the object should be stored in. If not specified, the object will be stored in the same storage tier as the bucket.
	StorageTier   *string `pulumi:"storageTier"`
	VersionId     *string `pulumi:"versionId"`
	WorkRequestId *string `pulumi:"workRequestId"`
}

type ObjectstorageObjectState struct {
	// The name of the bucket for the source object.
	Bucket pulumi.StringPtrInput
	// The optional Cache-Control header that defines the caching behavior value to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify objects that require caching restrictions.
	CacheControl pulumi.StringPtrInput
	// The object to upload to the object store. Cannot be defined if `source` or `sourceUriDetails` is defined.
	Content pulumi.StringPtrInput
	// The optional Content-Disposition header that defines presentational information for the object to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to let users download objects with custom filenames in a browser.
	ContentDisposition pulumi.StringPtrInput
	// The optional Content-Encoding header that defines the content encodings that were applied to the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to determine what decoding mechanisms need to be applied to obtain the media-type specified by the Content-Type header of the object.
	ContentEncoding pulumi.StringPtrInput
	// The optional Content-Language header that defines the content language of the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and differentiate objects based on a particular language.
	ContentLanguage pulumi.StringPtrInput
	// (Updatable) The content length of the body.
	ContentLength pulumi.StringPtrInput
	// (Updatable) The optional base-64 header that defines the encoded MD5 hash of the body. If the optional Content-MD5 header is present, Object Storage performs an integrity check on the body of the HTTP request by computing the MD5 hash for the body and comparing it to the MD5 hash supplied in the header. If the two hashes do not match, the object is rejected and an HTTP-400 Unmatched Content MD5 error is returned with the message:
	ContentMd5 pulumi.StringPtrInput
	// The optional Content-Type header that defines the standard MIME type format of the object. Content type defaults to 'application/octet-stream' if not specified in the PutObject call. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and perform special operations on text only objects.
	ContentType pulumi.StringPtrInput
	// (Updatable) A boolean to delete all object versions for an object in a bucket that has or ever had versioning enabled.
	DeleteAllObjectVersions pulumi.BoolPtrInput
	// Optional user-defined metadata key and value.
	// Note: All specified keys must be in lower case.
	Metadata pulumi.MapInput
	// The top-level namespace of the source object.
	Namespace pulumi.StringPtrInput
	// The name of the source object.
	Object pulumi.StringPtrInput
	// An absolute path to a file on the local system. Cannot be defined if `content` or `sourceUriDetails` is defined.
	Source pulumi.StringPtrInput
	// Details of the source URI of the object in the cloud. Cannot be defined if `content` or `source` is defined.
	// Note: To enable object copy, you must authorize the service to manage objects on your behalf.
	SourceUriDetails ObjectstorageObjectSourceUriDetailsPtrInput
	State            pulumi.StringPtrInput
	// (Updatable) The storage tier that the object should be stored in. If not specified, the object will be stored in the same storage tier as the bucket.
	StorageTier   pulumi.StringPtrInput
	VersionId     pulumi.StringPtrInput
	WorkRequestId pulumi.StringPtrInput
}

func (ObjectstorageObjectState) ElementType() reflect.Type {
	return reflect.TypeOf((*objectstorageObjectState)(nil)).Elem()
}

type objectstorageObjectArgs struct {
	// The name of the bucket for the source object.
	Bucket string `pulumi:"bucket"`
	// The optional Cache-Control header that defines the caching behavior value to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify objects that require caching restrictions.
	CacheControl *string `pulumi:"cacheControl"`
	// The object to upload to the object store. Cannot be defined if `source` or `sourceUriDetails` is defined.
	Content *string `pulumi:"content"`
	// The optional Content-Disposition header that defines presentational information for the object to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to let users download objects with custom filenames in a browser.
	ContentDisposition *string `pulumi:"contentDisposition"`
	// The optional Content-Encoding header that defines the content encodings that were applied to the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to determine what decoding mechanisms need to be applied to obtain the media-type specified by the Content-Type header of the object.
	ContentEncoding *string `pulumi:"contentEncoding"`
	// The optional Content-Language header that defines the content language of the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and differentiate objects based on a particular language.
	ContentLanguage *string `pulumi:"contentLanguage"`
	// (Updatable) The optional base-64 header that defines the encoded MD5 hash of the body. If the optional Content-MD5 header is present, Object Storage performs an integrity check on the body of the HTTP request by computing the MD5 hash for the body and comparing it to the MD5 hash supplied in the header. If the two hashes do not match, the object is rejected and an HTTP-400 Unmatched Content MD5 error is returned with the message:
	ContentMd5 *string `pulumi:"contentMd5"`
	// The optional Content-Type header that defines the standard MIME type format of the object. Content type defaults to 'application/octet-stream' if not specified in the PutObject call. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and perform special operations on text only objects.
	ContentType *string `pulumi:"contentType"`
	// (Updatable) A boolean to delete all object versions for an object in a bucket that has or ever had versioning enabled.
	DeleteAllObjectVersions *bool `pulumi:"deleteAllObjectVersions"`
	// Optional user-defined metadata key and value.
	// Note: All specified keys must be in lower case.
	Metadata map[string]interface{} `pulumi:"metadata"`
	// The top-level namespace of the source object.
	Namespace string `pulumi:"namespace"`
	// The name of the source object.
	Object string `pulumi:"object"`
	// An absolute path to a file on the local system. Cannot be defined if `content` or `sourceUriDetails` is defined.
	Source *string `pulumi:"source"`
	// Details of the source URI of the object in the cloud. Cannot be defined if `content` or `source` is defined.
	// Note: To enable object copy, you must authorize the service to manage objects on your behalf.
	SourceUriDetails *ObjectstorageObjectSourceUriDetails `pulumi:"sourceUriDetails"`
	// (Updatable) The storage tier that the object should be stored in. If not specified, the object will be stored in the same storage tier as the bucket.
	StorageTier *string `pulumi:"storageTier"`
}

// The set of arguments for constructing a ObjectstorageObject resource.
type ObjectstorageObjectArgs struct {
	// The name of the bucket for the source object.
	Bucket pulumi.StringInput
	// The optional Cache-Control header that defines the caching behavior value to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify objects that require caching restrictions.
	CacheControl pulumi.StringPtrInput
	// The object to upload to the object store. Cannot be defined if `source` or `sourceUriDetails` is defined.
	Content pulumi.StringPtrInput
	// The optional Content-Disposition header that defines presentational information for the object to be returned in GetObject and HeadObject responses. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to let users download objects with custom filenames in a browser.
	ContentDisposition pulumi.StringPtrInput
	// The optional Content-Encoding header that defines the content encodings that were applied to the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to determine what decoding mechanisms need to be applied to obtain the media-type specified by the Content-Type header of the object.
	ContentEncoding pulumi.StringPtrInput
	// The optional Content-Language header that defines the content language of the object to upload. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and differentiate objects based on a particular language.
	ContentLanguage pulumi.StringPtrInput
	// (Updatable) The optional base-64 header that defines the encoded MD5 hash of the body. If the optional Content-MD5 header is present, Object Storage performs an integrity check on the body of the HTTP request by computing the MD5 hash for the body and comparing it to the MD5 hash supplied in the header. If the two hashes do not match, the object is rejected and an HTTP-400 Unmatched Content MD5 error is returned with the message:
	ContentMd5 pulumi.StringPtrInput
	// The optional Content-Type header that defines the standard MIME type format of the object. Content type defaults to 'application/octet-stream' if not specified in the PutObject call. Specifying values for this header has no effect on Object Storage behavior. Programs that read the object determine what to do based on the value provided. For example, you could use this header to identify and perform special operations on text only objects.
	ContentType pulumi.StringPtrInput
	// (Updatable) A boolean to delete all object versions for an object in a bucket that has or ever had versioning enabled.
	DeleteAllObjectVersions pulumi.BoolPtrInput
	// Optional user-defined metadata key and value.
	// Note: All specified keys must be in lower case.
	Metadata pulumi.MapInput
	// The top-level namespace of the source object.
	Namespace pulumi.StringInput
	// The name of the source object.
	Object pulumi.StringInput
	// An absolute path to a file on the local system. Cannot be defined if `content` or `sourceUriDetails` is defined.
	Source pulumi.StringPtrInput
	// Details of the source URI of the object in the cloud. Cannot be defined if `content` or `source` is defined.
	// Note: To enable object copy, you must authorize the service to manage objects on your behalf.
	SourceUriDetails ObjectstorageObjectSourceUriDetailsPtrInput
	// (Updatable) The storage tier that the object should be stored in. If not specified, the object will be stored in the same storage tier as the bucket.
	StorageTier pulumi.StringPtrInput
}

func (ObjectstorageObjectArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*objectstorageObjectArgs)(nil)).Elem()
}

type ObjectstorageObjectInput interface {
	pulumi.Input

	ToObjectstorageObjectOutput() ObjectstorageObjectOutput
	ToObjectstorageObjectOutputWithContext(ctx context.Context) ObjectstorageObjectOutput
}

func (*ObjectstorageObject) ElementType() reflect.Type {
	return reflect.TypeOf((*ObjectstorageObject)(nil))
}

func (i *ObjectstorageObject) ToObjectstorageObjectOutput() ObjectstorageObjectOutput {
	return i.ToObjectstorageObjectOutputWithContext(context.Background())
}

func (i *ObjectstorageObject) ToObjectstorageObjectOutputWithContext(ctx context.Context) ObjectstorageObjectOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectstorageObjectOutput)
}

func (i *ObjectstorageObject) ToObjectstorageObjectPtrOutput() ObjectstorageObjectPtrOutput {
	return i.ToObjectstorageObjectPtrOutputWithContext(context.Background())
}

func (i *ObjectstorageObject) ToObjectstorageObjectPtrOutputWithContext(ctx context.Context) ObjectstorageObjectPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectstorageObjectPtrOutput)
}

type ObjectstorageObjectPtrInput interface {
	pulumi.Input

	ToObjectstorageObjectPtrOutput() ObjectstorageObjectPtrOutput
	ToObjectstorageObjectPtrOutputWithContext(ctx context.Context) ObjectstorageObjectPtrOutput
}

type objectstorageObjectPtrType ObjectstorageObjectArgs

func (*objectstorageObjectPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**ObjectstorageObject)(nil))
}

func (i *objectstorageObjectPtrType) ToObjectstorageObjectPtrOutput() ObjectstorageObjectPtrOutput {
	return i.ToObjectstorageObjectPtrOutputWithContext(context.Background())
}

func (i *objectstorageObjectPtrType) ToObjectstorageObjectPtrOutputWithContext(ctx context.Context) ObjectstorageObjectPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectstorageObjectPtrOutput)
}

// ObjectstorageObjectArrayInput is an input type that accepts ObjectstorageObjectArray and ObjectstorageObjectArrayOutput values.
// You can construct a concrete instance of `ObjectstorageObjectArrayInput` via:
//
//          ObjectstorageObjectArray{ ObjectstorageObjectArgs{...} }
type ObjectstorageObjectArrayInput interface {
	pulumi.Input

	ToObjectstorageObjectArrayOutput() ObjectstorageObjectArrayOutput
	ToObjectstorageObjectArrayOutputWithContext(context.Context) ObjectstorageObjectArrayOutput
}

type ObjectstorageObjectArray []ObjectstorageObjectInput

func (ObjectstorageObjectArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ObjectstorageObject)(nil)).Elem()
}

func (i ObjectstorageObjectArray) ToObjectstorageObjectArrayOutput() ObjectstorageObjectArrayOutput {
	return i.ToObjectstorageObjectArrayOutputWithContext(context.Background())
}

func (i ObjectstorageObjectArray) ToObjectstorageObjectArrayOutputWithContext(ctx context.Context) ObjectstorageObjectArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectstorageObjectArrayOutput)
}

// ObjectstorageObjectMapInput is an input type that accepts ObjectstorageObjectMap and ObjectstorageObjectMapOutput values.
// You can construct a concrete instance of `ObjectstorageObjectMapInput` via:
//
//          ObjectstorageObjectMap{ "key": ObjectstorageObjectArgs{...} }
type ObjectstorageObjectMapInput interface {
	pulumi.Input

	ToObjectstorageObjectMapOutput() ObjectstorageObjectMapOutput
	ToObjectstorageObjectMapOutputWithContext(context.Context) ObjectstorageObjectMapOutput
}

type ObjectstorageObjectMap map[string]ObjectstorageObjectInput

func (ObjectstorageObjectMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ObjectstorageObject)(nil)).Elem()
}

func (i ObjectstorageObjectMap) ToObjectstorageObjectMapOutput() ObjectstorageObjectMapOutput {
	return i.ToObjectstorageObjectMapOutputWithContext(context.Background())
}

func (i ObjectstorageObjectMap) ToObjectstorageObjectMapOutputWithContext(ctx context.Context) ObjectstorageObjectMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ObjectstorageObjectMapOutput)
}

type ObjectstorageObjectOutput struct {
	*pulumi.OutputState
}

func (ObjectstorageObjectOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*ObjectstorageObject)(nil))
}

func (o ObjectstorageObjectOutput) ToObjectstorageObjectOutput() ObjectstorageObjectOutput {
	return o
}

func (o ObjectstorageObjectOutput) ToObjectstorageObjectOutputWithContext(ctx context.Context) ObjectstorageObjectOutput {
	return o
}

func (o ObjectstorageObjectOutput) ToObjectstorageObjectPtrOutput() ObjectstorageObjectPtrOutput {
	return o.ToObjectstorageObjectPtrOutputWithContext(context.Background())
}

func (o ObjectstorageObjectOutput) ToObjectstorageObjectPtrOutputWithContext(ctx context.Context) ObjectstorageObjectPtrOutput {
	return o.ApplyT(func(v ObjectstorageObject) *ObjectstorageObject {
		return &v
	}).(ObjectstorageObjectPtrOutput)
}

type ObjectstorageObjectPtrOutput struct {
	*pulumi.OutputState
}

func (ObjectstorageObjectPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ObjectstorageObject)(nil))
}

func (o ObjectstorageObjectPtrOutput) ToObjectstorageObjectPtrOutput() ObjectstorageObjectPtrOutput {
	return o
}

func (o ObjectstorageObjectPtrOutput) ToObjectstorageObjectPtrOutputWithContext(ctx context.Context) ObjectstorageObjectPtrOutput {
	return o
}

type ObjectstorageObjectArrayOutput struct{ *pulumi.OutputState }

func (ObjectstorageObjectArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]ObjectstorageObject)(nil))
}

func (o ObjectstorageObjectArrayOutput) ToObjectstorageObjectArrayOutput() ObjectstorageObjectArrayOutput {
	return o
}

func (o ObjectstorageObjectArrayOutput) ToObjectstorageObjectArrayOutputWithContext(ctx context.Context) ObjectstorageObjectArrayOutput {
	return o
}

func (o ObjectstorageObjectArrayOutput) Index(i pulumi.IntInput) ObjectstorageObjectOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) ObjectstorageObject {
		return vs[0].([]ObjectstorageObject)[vs[1].(int)]
	}).(ObjectstorageObjectOutput)
}

type ObjectstorageObjectMapOutput struct{ *pulumi.OutputState }

func (ObjectstorageObjectMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]ObjectstorageObject)(nil))
}

func (o ObjectstorageObjectMapOutput) ToObjectstorageObjectMapOutput() ObjectstorageObjectMapOutput {
	return o
}

func (o ObjectstorageObjectMapOutput) ToObjectstorageObjectMapOutputWithContext(ctx context.Context) ObjectstorageObjectMapOutput {
	return o
}

func (o ObjectstorageObjectMapOutput) MapIndex(k pulumi.StringInput) ObjectstorageObjectOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) ObjectstorageObject {
		return vs[0].(map[string]ObjectstorageObject)[vs[1].(string)]
	}).(ObjectstorageObjectOutput)
}

func init() {
	pulumi.RegisterOutputType(ObjectstorageObjectOutput{})
	pulumi.RegisterOutputType(ObjectstorageObjectPtrOutput{})
	pulumi.RegisterOutputType(ObjectstorageObjectArrayOutput{})
	pulumi.RegisterOutputType(ObjectstorageObjectMapOutput{})
}
