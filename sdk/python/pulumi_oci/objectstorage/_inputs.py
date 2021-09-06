# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'ObjectstorageBucketRetentionRuleArgs',
    'ObjectstorageBucketRetentionRuleDurationArgs',
    'ObjectstorageObjectLifecyclePolicyRuleArgs',
    'ObjectstorageObjectLifecyclePolicyRuleObjectNameFilterArgs',
    'ObjectstorageObjectSourceUriDetailsArgs',
    'GetBucketSummariesFilterArgs',
    'GetObjectVersionsFilterArgs',
    'GetObjectsFilterArgs',
    'GetPreauthrequestsFilterArgs',
    'GetReplicationPoliciesFilterArgs',
    'GetReplicationSourcesFilterArgs',
]

@pulumi.input_type
class ObjectstorageBucketRetentionRuleArgs:
    def __init__(__self__, *,
                 display_name: pulumi.Input[str],
                 duration: Optional[pulumi.Input['ObjectstorageBucketRetentionRuleDurationArgs']] = None,
                 retention_rule_id: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_modified: Optional[pulumi.Input[str]] = None,
                 time_rule_locked: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] display_name: A user-specified name for the retention rule. Names can be helpful in identifying retention rules. The name should be unique. This attribute is a forcenew attribute
        :param pulumi.Input['ObjectstorageBucketRetentionRuleDurationArgs'] duration: (Updatable)
        :param pulumi.Input[str] retention_rule_id: Unique identifier for the retention rule.
        :param pulumi.Input[str] time_created: The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        :param pulumi.Input[str] time_modified: The date and time that the retention rule was modified as per [RFC3339](https://tools.ietf.org/html/rfc3339).
        :param pulumi.Input[str] time_rule_locked: (Updatable) The date and time as per [RFC 3339](https://tools.ietf.org/html/rfc3339) after which this rule is locked and can only be deleted by deleting the bucket. Once a rule is locked, only increases in the duration are allowed and no other properties can be changed. This property cannot be updated for rules that are in a locked state. Specifying it when a duration is not specified is considered an error.
        """
        pulumi.set(__self__, "display_name", display_name)
        if duration is not None:
            pulumi.set(__self__, "duration", duration)
        if retention_rule_id is not None:
            pulumi.set(__self__, "retention_rule_id", retention_rule_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_modified is not None:
            pulumi.set(__self__, "time_modified", time_modified)
        if time_rule_locked is not None:
            pulumi.set(__self__, "time_rule_locked", time_rule_locked)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        A user-specified name for the retention rule. Names can be helpful in identifying retention rules. The name should be unique. This attribute is a forcenew attribute
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter
    def duration(self) -> Optional[pulumi.Input['ObjectstorageBucketRetentionRuleDurationArgs']]:
        """
        (Updatable)
        """
        return pulumi.get(self, "duration")

    @duration.setter
    def duration(self, value: Optional[pulumi.Input['ObjectstorageBucketRetentionRuleDurationArgs']]):
        pulumi.set(self, "duration", value)

    @property
    @pulumi.getter(name="retentionRuleId")
    def retention_rule_id(self) -> Optional[pulumi.Input[str]]:
        """
        Unique identifier for the retention rule.
        """
        return pulumi.get(self, "retention_rule_id")

    @retention_rule_id.setter
    def retention_rule_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "retention_rule_id", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeModified")
    def time_modified(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time that the retention rule was modified as per [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_modified")

    @time_modified.setter
    def time_modified(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_modified", value)

    @property
    @pulumi.getter(name="timeRuleLocked")
    def time_rule_locked(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The date and time as per [RFC 3339](https://tools.ietf.org/html/rfc3339) after which this rule is locked and can only be deleted by deleting the bucket. Once a rule is locked, only increases in the duration are allowed and no other properties can be changed. This property cannot be updated for rules that are in a locked state. Specifying it when a duration is not specified is considered an error.
        """
        return pulumi.get(self, "time_rule_locked")

    @time_rule_locked.setter
    def time_rule_locked(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_rule_locked", value)


@pulumi.input_type
class ObjectstorageBucketRetentionRuleDurationArgs:
    def __init__(__self__, *,
                 time_amount: pulumi.Input[str],
                 time_unit: pulumi.Input[str]):
        """
        :param pulumi.Input[str] time_amount: (Updatable) The timeAmount is interpreted in units defined by the timeUnit parameter, and is calculated in relation to each object's Last-Modified timestamp.
        :param pulumi.Input[str] time_unit: (Updatable) The unit that should be used to interpret timeAmount.
        """
        pulumi.set(__self__, "time_amount", time_amount)
        pulumi.set(__self__, "time_unit", time_unit)

    @property
    @pulumi.getter(name="timeAmount")
    def time_amount(self) -> pulumi.Input[str]:
        """
        (Updatable) The timeAmount is interpreted in units defined by the timeUnit parameter, and is calculated in relation to each object's Last-Modified timestamp.
        """
        return pulumi.get(self, "time_amount")

    @time_amount.setter
    def time_amount(self, value: pulumi.Input[str]):
        pulumi.set(self, "time_amount", value)

    @property
    @pulumi.getter(name="timeUnit")
    def time_unit(self) -> pulumi.Input[str]:
        """
        (Updatable) The unit that should be used to interpret timeAmount.
        """
        return pulumi.get(self, "time_unit")

    @time_unit.setter
    def time_unit(self, value: pulumi.Input[str]):
        pulumi.set(self, "time_unit", value)


@pulumi.input_type
class ObjectstorageObjectLifecyclePolicyRuleArgs:
    def __init__(__self__, *,
                 action: pulumi.Input[str],
                 is_enabled: pulumi.Input[bool],
                 name: pulumi.Input[str],
                 time_amount: pulumi.Input[str],
                 time_unit: pulumi.Input[str],
                 object_name_filter: Optional[pulumi.Input['ObjectstorageObjectLifecyclePolicyRuleObjectNameFilterArgs']] = None,
                 target: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] action: (Updatable) The action of the object lifecycle policy rule. Rules using the action 'ARCHIVE' move objects from Standard and InfrequentAccess storage tiers into the [Archive storage tier](https://docs.cloud.oracle.com/iaas/Content/Archive/Concepts/archivestorageoverview.htm). Rules using the action 'INFREQUENT_ACCESS' move objects from Standard storage tier into the Infrequent Access Storage tier. Objects that are already in InfrequentAccess tier or in Archive tier are left untouched. Rules using the action 'DELETE' permanently delete objects from buckets. Rules using 'ABORT' abort the uncommitted multipart-uploads and permanently delete their parts from buckets.
        :param pulumi.Input[bool] is_enabled: (Updatable) A Boolean that determines whether this rule is currently enabled.
        :param pulumi.Input[str] name: (Updatable) The name of the lifecycle rule to be applied.
        :param pulumi.Input[str] time_amount: (Updatable) Specifies the age of objects to apply the rule to. The timeAmount is interpreted in units defined by the timeUnit parameter, and is calculated in relation to each object's Last-Modified time.
        :param pulumi.Input[str] time_unit: (Updatable) The unit that should be used to interpret timeAmount.  Days are defined as starting and ending at midnight UTC. Years are defined as 365.2425 days long and likewise round up to the next midnight UTC.
        :param pulumi.Input['ObjectstorageObjectLifecyclePolicyRuleObjectNameFilterArgs'] object_name_filter: (Updatable) A filter that compares object names to a set of prefixes or patterns to determine if a rule applies to a given object. The filter can contain include glob patterns, exclude glob patterns and inclusion prefixes. The inclusion prefixes property is kept for backward compatibility. It is recommended to use inclusion patterns instead of prefixes. Exclusions take precedence over inclusions.
        :param pulumi.Input[str] target: (Updatable) The target of the object lifecycle policy rule. The values of target can be either "objects", "multipart-uploads" or "previous-object-versions". This field when declared as "objects" is used to specify ARCHIVE, INFREQUENT_ACCESS or DELETE rule for objects. This field when declared as "previous-object-versions" is used to specify ARCHIVE, INFREQUENT_ACCESS or DELETE rule for previous versions of existing objects. This field when declared as "multipart-uploads" is used to specify the ABORT (only) rule for uncommitted multipart-uploads.
        """
        pulumi.set(__self__, "action", action)
        pulumi.set(__self__, "is_enabled", is_enabled)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "time_amount", time_amount)
        pulumi.set(__self__, "time_unit", time_unit)
        if object_name_filter is not None:
            pulumi.set(__self__, "object_name_filter", object_name_filter)
        if target is not None:
            pulumi.set(__self__, "target", target)

    @property
    @pulumi.getter
    def action(self) -> pulumi.Input[str]:
        """
        (Updatable) The action of the object lifecycle policy rule. Rules using the action 'ARCHIVE' move objects from Standard and InfrequentAccess storage tiers into the [Archive storage tier](https://docs.cloud.oracle.com/iaas/Content/Archive/Concepts/archivestorageoverview.htm). Rules using the action 'INFREQUENT_ACCESS' move objects from Standard storage tier into the Infrequent Access Storage tier. Objects that are already in InfrequentAccess tier or in Archive tier are left untouched. Rules using the action 'DELETE' permanently delete objects from buckets. Rules using 'ABORT' abort the uncommitted multipart-uploads and permanently delete their parts from buckets.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: pulumi.Input[str]):
        pulumi.set(self, "action", value)

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> pulumi.Input[bool]:
        """
        (Updatable) A Boolean that determines whether this rule is currently enabled.
        """
        return pulumi.get(self, "is_enabled")

    @is_enabled.setter
    def is_enabled(self, value: pulumi.Input[bool]):
        pulumi.set(self, "is_enabled", value)

    @property
    @pulumi.getter
    def name(self) -> pulumi.Input[str]:
        """
        (Updatable) The name of the lifecycle rule to be applied.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: pulumi.Input[str]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter(name="timeAmount")
    def time_amount(self) -> pulumi.Input[str]:
        """
        (Updatable) Specifies the age of objects to apply the rule to. The timeAmount is interpreted in units defined by the timeUnit parameter, and is calculated in relation to each object's Last-Modified time.
        """
        return pulumi.get(self, "time_amount")

    @time_amount.setter
    def time_amount(self, value: pulumi.Input[str]):
        pulumi.set(self, "time_amount", value)

    @property
    @pulumi.getter(name="timeUnit")
    def time_unit(self) -> pulumi.Input[str]:
        """
        (Updatable) The unit that should be used to interpret timeAmount.  Days are defined as starting and ending at midnight UTC. Years are defined as 365.2425 days long and likewise round up to the next midnight UTC.
        """
        return pulumi.get(self, "time_unit")

    @time_unit.setter
    def time_unit(self, value: pulumi.Input[str]):
        pulumi.set(self, "time_unit", value)

    @property
    @pulumi.getter(name="objectNameFilter")
    def object_name_filter(self) -> Optional[pulumi.Input['ObjectstorageObjectLifecyclePolicyRuleObjectNameFilterArgs']]:
        """
        (Updatable) A filter that compares object names to a set of prefixes or patterns to determine if a rule applies to a given object. The filter can contain include glob patterns, exclude glob patterns and inclusion prefixes. The inclusion prefixes property is kept for backward compatibility. It is recommended to use inclusion patterns instead of prefixes. Exclusions take precedence over inclusions.
        """
        return pulumi.get(self, "object_name_filter")

    @object_name_filter.setter
    def object_name_filter(self, value: Optional[pulumi.Input['ObjectstorageObjectLifecyclePolicyRuleObjectNameFilterArgs']]):
        pulumi.set(self, "object_name_filter", value)

    @property
    @pulumi.getter
    def target(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The target of the object lifecycle policy rule. The values of target can be either "objects", "multipart-uploads" or "previous-object-versions". This field when declared as "objects" is used to specify ARCHIVE, INFREQUENT_ACCESS or DELETE rule for objects. This field when declared as "previous-object-versions" is used to specify ARCHIVE, INFREQUENT_ACCESS or DELETE rule for previous versions of existing objects. This field when declared as "multipart-uploads" is used to specify the ABORT (only) rule for uncommitted multipart-uploads.
        """
        return pulumi.get(self, "target")

    @target.setter
    def target(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "target", value)


@pulumi.input_type
class ObjectstorageObjectLifecyclePolicyRuleObjectNameFilterArgs:
    def __init__(__self__, *,
                 exclusion_patterns: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 inclusion_patterns: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 inclusion_prefixes: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input[str]]] exclusion_patterns: (Updatable) An array of glob patterns to match the object names to exclude. An empty array is ignored. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] inclusion_patterns: (Updatable) An array of glob patterns to match the object names to include. An empty array includes all objects in the bucket. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] inclusion_prefixes: (Updatable) An array of object name prefixes that the rule will apply to. An empty array means to include all objects.
        """
        if exclusion_patterns is not None:
            pulumi.set(__self__, "exclusion_patterns", exclusion_patterns)
        if inclusion_patterns is not None:
            pulumi.set(__self__, "inclusion_patterns", inclusion_patterns)
        if inclusion_prefixes is not None:
            pulumi.set(__self__, "inclusion_prefixes", inclusion_prefixes)

    @property
    @pulumi.getter(name="exclusionPatterns")
    def exclusion_patterns(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) An array of glob patterns to match the object names to exclude. An empty array is ignored. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
        """
        return pulumi.get(self, "exclusion_patterns")

    @exclusion_patterns.setter
    def exclusion_patterns(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "exclusion_patterns", value)

    @property
    @pulumi.getter(name="inclusionPatterns")
    def inclusion_patterns(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) An array of glob patterns to match the object names to include. An empty array includes all objects in the bucket. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
        """
        return pulumi.get(self, "inclusion_patterns")

    @inclusion_patterns.setter
    def inclusion_patterns(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "inclusion_patterns", value)

    @property
    @pulumi.getter(name="inclusionPrefixes")
    def inclusion_prefixes(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        (Updatable) An array of object name prefixes that the rule will apply to. An empty array means to include all objects.
        """
        return pulumi.get(self, "inclusion_prefixes")

    @inclusion_prefixes.setter
    def inclusion_prefixes(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "inclusion_prefixes", value)


@pulumi.input_type
class ObjectstorageObjectSourceUriDetailsArgs:
    def __init__(__self__, *,
                 bucket: pulumi.Input[str],
                 namespace: pulumi.Input[str],
                 object: pulumi.Input[str],
                 region: pulumi.Input[str],
                 destination_object_if_match_etag: Optional[pulumi.Input[str]] = None,
                 destination_object_if_none_match_etag: Optional[pulumi.Input[str]] = None,
                 source_object_if_match_etag: Optional[pulumi.Input[str]] = None,
                 source_version_id: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] bucket: The name of the bucket for the source object.
        :param pulumi.Input[str] namespace: The top-level namespace of the source object.
        :param pulumi.Input[str] object: The name of the source object.
        :param pulumi.Input[str] region: The region of the source object.
        :param pulumi.Input[str] destination_object_if_match_etag: The entity tag to match the target object.
        :param pulumi.Input[str] destination_object_if_none_match_etag: The entity tag to not match the target object.
        :param pulumi.Input[str] source_object_if_match_etag: The entity tag to match the source object.
        :param pulumi.Input[str] source_version_id: The version id of the object to be restored.
        """
        pulumi.set(__self__, "bucket", bucket)
        pulumi.set(__self__, "namespace", namespace)
        pulumi.set(__self__, "object", object)
        pulumi.set(__self__, "region", region)
        if destination_object_if_match_etag is not None:
            pulumi.set(__self__, "destination_object_if_match_etag", destination_object_if_match_etag)
        if destination_object_if_none_match_etag is not None:
            pulumi.set(__self__, "destination_object_if_none_match_etag", destination_object_if_none_match_etag)
        if source_object_if_match_etag is not None:
            pulumi.set(__self__, "source_object_if_match_etag", source_object_if_match_etag)
        if source_version_id is not None:
            pulumi.set(__self__, "source_version_id", source_version_id)

    @property
    @pulumi.getter
    def bucket(self) -> pulumi.Input[str]:
        """
        The name of the bucket for the source object.
        """
        return pulumi.get(self, "bucket")

    @bucket.setter
    def bucket(self, value: pulumi.Input[str]):
        pulumi.set(self, "bucket", value)

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Input[str]:
        """
        The top-level namespace of the source object.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: pulumi.Input[str]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter
    def object(self) -> pulumi.Input[str]:
        """
        The name of the source object.
        """
        return pulumi.get(self, "object")

    @object.setter
    def object(self, value: pulumi.Input[str]):
        pulumi.set(self, "object", value)

    @property
    @pulumi.getter
    def region(self) -> pulumi.Input[str]:
        """
        The region of the source object.
        """
        return pulumi.get(self, "region")

    @region.setter
    def region(self, value: pulumi.Input[str]):
        pulumi.set(self, "region", value)

    @property
    @pulumi.getter(name="destinationObjectIfMatchEtag")
    def destination_object_if_match_etag(self) -> Optional[pulumi.Input[str]]:
        """
        The entity tag to match the target object.
        """
        return pulumi.get(self, "destination_object_if_match_etag")

    @destination_object_if_match_etag.setter
    def destination_object_if_match_etag(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "destination_object_if_match_etag", value)

    @property
    @pulumi.getter(name="destinationObjectIfNoneMatchEtag")
    def destination_object_if_none_match_etag(self) -> Optional[pulumi.Input[str]]:
        """
        The entity tag to not match the target object.
        """
        return pulumi.get(self, "destination_object_if_none_match_etag")

    @destination_object_if_none_match_etag.setter
    def destination_object_if_none_match_etag(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "destination_object_if_none_match_etag", value)

    @property
    @pulumi.getter(name="sourceObjectIfMatchEtag")
    def source_object_if_match_etag(self) -> Optional[pulumi.Input[str]]:
        """
        The entity tag to match the source object.
        """
        return pulumi.get(self, "source_object_if_match_etag")

    @source_object_if_match_etag.setter
    def source_object_if_match_etag(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "source_object_if_match_etag", value)

    @property
    @pulumi.getter(name="sourceVersionId")
    def source_version_id(self) -> Optional[pulumi.Input[str]]:
        """
        The version id of the object to be restored.
        """
        return pulumi.get(self, "source_version_id")

    @source_version_id.setter
    def source_version_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "source_version_id", value)


@pulumi.input_type
class GetBucketSummariesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the bucket. Avoid entering confidential information. Example: my-new-bucket1
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the bucket. Avoid entering confidential information. Example: my-new-bucket1
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetObjectVersionsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the object. Avoid entering confidential information. Example: test/object1.log
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the object. Avoid entering confidential information. Example: test/object1.log
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetObjectsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the object.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the object.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetPreauthrequestsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The user-provided name of the pre-authenticated request.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The user-provided name of the pre-authenticated request.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetReplicationPoliciesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the policy.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the policy.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetReplicationSourcesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


