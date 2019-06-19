import boto3
import copy
from botocore.exceptions import ClientError

###Checks if a bucket exists
#Param: clientS3 - an instance of the s3 client
#Param: bucketName - the name of the bucket to check
#Returns: Whether or not the bucket exists
def bucketExists(clientS3, bucketName):
    try:
        response = clientS3.head_bucket(Bucket=bucketName)
    except ClientError as e:
        return False
    return True

###Creates a bucket
#Param: clientS3 - an instance of the s3 client
#Param: bucketName - the name of the bucket to be created
#Param: **tags - tags to tag the bucket with the function should be called as:
#           createBucket(... , tagNam = value)
#           You can add as many tags as you want
def createBucket(clientS3, bucketName, **tags):
    clientS3.create_bucket(Bucket=bucketName)

    setBucketTags(clientS3, bucketName, **tags)
        
###Deletes a bucket
#Param: clientS3 - an instance of the s3 client
#Param: bucketName - the name of the bucket to be deleted
def deleteBucket(clientS3, bucketName):
    clientS3.delete_bucket(Bucket=bucketName)

###Deletes the bucket Tags
#Param: clientS3 - an instance of the s3 client
#Param: bucketName - the name of the bucket to delete tags from
#Param: tagKey - the name of the tag to be deleted
#Param: doDeleteAllTags - optional parameter to delete all tags
#           if this tag is present the value of tagKey is still required, but ignored
def deleteBucketTags(clientS3, bucketName, tagKey, doDeleteAllTags=False):
    if doDeleteAllTags:
        clientS3.delete_bucket_tagging(Bucket=bucketName)

    else:
        new_tags = {}

        
        old = clientS3.get_bucket_tagging(
            Bucket=bucketName
        )

        new_tags = {i['Key']: i['Value'] for i in old['TagSet'] if i['Key'] != tagKey}

        response = clientS3.put_bucket_tagging(
            Bucket=bucketName,
            Tagging={
                'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()]
            }
        )

###Enables Access Logging for 
def enableAccessLogging(clientS3, bucketName, storageBucket, 
                        targetPrefix):

    #Give the group log-delievery WRITE and READ_ACP permisions to the
    #target bucket
    acl = get_bucket_acl(clientS3, storageBucket)

    new_grant = {
        'Grantee': {
            'URI': "http://acs.amazonaws.com/groups/s3/LogDelivery",
            'Type' : 'Group'
        },
        'Permission': 'FULL_CONTROL',
    }

    modified_acl = copy.deepcopy(acl)
    modified_acl['Grants'].append(new_grant)

    setBucketAcl(clientS3, storageBucket, modified_acl)

    response = clientS3.put_bucket_logging(
        Bucket=bucketName,
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': storageBucket,
                'TargetPrefix': targetPrefix
            }
        }

    )
    


def getBuckets(clientS3):
    return clientS3.list_buckets()

def getBucketTags(clientS3, bucketName):
    bucket_tagging = clientS3.get_bucket_tagging(Bucket=bucketName)
    return bucket_tagging['TagSet']

def get_bucket_acl(clientS3, bucket_name):
    """Retrieve the access control list of an Amazon S3 bucket

    :param bucket_name: string
    :return: Dictionary defining the bucket's access control list consisting
     of owner and grants. If error, return None.
    """

    # Retrieve the bucket ACL

    try:
        response = clientS3.get_bucket_acl(Bucket=bucket_name)
    except ClientError as e:
        # AllAccessDisabled error == bucket not found
        logging.error(e)
        return None

    # Return both the Owner and Grants keys
    # The Owner and Grants settings together form the Access Control Policy.
    # The Grants alone form the Access Control List.
    return {'Owner': response['Owner'], 'Grants': response['Grants']}

def listBuckets(clientS3):
    buckets = clientS3.list_buckets()
    for bucket in buckets['Buckets']:
        print(f'{bucket["Name"]}')

def listBucketTags(clientS3, bucketName):
    bucket_tagging = clientS3.get_bucket_tagging(Bucket=bucketName)
    tag_set = bucket_tagging['TagSet']
    for tag in tag_set:    
        print(tag)

def setBucketAcl(clientS3, bucket_name, acl):
    """Set the access control list of an Amazon S3 bucket

    :param bucket_name: string
    :param acl: Dictionary defining the ACL consisting of grants and permissions
    :return: True if ACL was set, otherwise False
    """
    try:
        clientS3.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=acl)
    except ClientError as e:
        # AccessDenied error == bucket prohibits public access
        # AllAccessDisabled error == bucket not found
        # AmbiguousGrantByEmailAddress == email address is associated with
        #   multiple AWS accounts
        return False
    return True


def setBucketTags(clientS3, bucketName, **new_tags):
    old_tags = {}

    try:
        old = clientS3.get_bucket_tagging(
            Bucket=bucketName,
        )

        old_tags = {i['Key']: i['Value'] for i in old['TagSet']}

    except:
        #Do nothing but cause python, it requires an indednted line
        if False:
            print("The world is ending")

    new_tags = {**old_tags, **new_tags}

    response = clientS3.put_bucket_tagging(
        Bucket=bucketName,
        Tagging={
            'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()]
        }
    )
         

def setBucketPolicy(clientS3, bucketName, policy, removeSelf=False):
    return clientS3.put_bucket_policy(Bucket=bucketName,
                                      ConfirmRemoveSelfBucketAccess=removeSelf,
                                      Policy=policy)


def uploadObject(clientS3, file, bucketName, objectName, **new_tags):
    clientS3.put_object(Body=file, Bucket=bucketName, Key=objectName)

    setObjectTags(clientS3, bucketName, objectName, **new_tags)



def deleteObject(clientS3, bucketName, objectName):
    clientS3.delete_object(Bucket=bucketName, Key=objectName)

def setObjectTags(clientS3, bucketName, objectPath, **new_tags):
    old_tags = {}

    try:
        old = clientS3.get_object_tagging(
            Bucket=bucketName,
            Key=objectPath,
        )

        old_tags = {i['Key']: i['Value'] for i in old['TagSet']}

    except:
        #Do nothing but cause python, it requires an indednted line
        if False:
            print("The world is ending")

    new_tags = {**old_tags, **new_tags}

    response = clientS3.put_object_tagging(
        Bucket=bucketName,
        Key=objectPath,
        Tagging={
            'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()]
        }
    )

def deleteObjectTags(clientS3, bucketName, objectName, tagKey, doDeleteAllTags=False):
    if doDeleteAllTags:
        clientS3.delete_object_tagging(Bucket=bucketName, Key=objectName)

    else:
        new_tags = {}

        
        old = clientS3.get_object_tagging(
            Bucket=bucketName,
            Key=objectName,
        )

        new_tags = {i['Key']: i['Value'] for i in old['TagSet'] if i['Key'] != tagKey}

        response = clientS3.put_object_tagging(
            Bucket=bucketName,
            Key=objectName,
            Tagging={
                'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()]
            }
        )
        





