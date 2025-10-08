import boto3
import json
from datetime import datetime

s3 = boto3.client('s3')
sns = boto3.client('sns')

SNS_TOPIC_ARN = 'YOUR-SNS-ARN' # EX: arn:aws:sns:us-west-1:184937483839:AlertMe

def lambda_handler(event, context):
    print("=" * 100)
    print("RECEIVED CONFIG EVENT:")
    print(json.dumps(event, indent=2, default=str))
    print("=" * 100)
    
    try:
        # AWS Config sends events in a specific structure
        if 'detail' not in event:
            print("ERROR: No 'detail' field in event")
            return {'statusCode': 400, 'body': 'Invalid event structure'}
        
        detail = event['detail']
        
        # Extract bucket name from Config event
        # Config events have different structures depending on the rule
        bucket_name = None
        
        # Method 1: Check configurationItem (most common)
        if 'configurationItem' in detail:
            config_item = detail['configurationItem']
            if config_item.get('resourceType') == 'AWS::S3::Bucket':
                bucket_name = config_item.get('resourceName') or config_item.get('resourceId')
        
        # Method 2: Check resourceId directly
        if not bucket_name and 'resourceId' in detail:
            bucket_name = detail['resourceId']
        
        # Method 3: Check newEvaluationResult
        if not bucket_name and 'newEvaluationResult' in detail:
            eval_result = detail['newEvaluationResult']
            if 'evaluationResultIdentifier' in eval_result:
                bucket_name = eval_result['evaluationResultIdentifier'].get('evaluationResultQualifier', {}).get('resourceId')
        
        if not bucket_name:
            print("ERROR: Could not extract bucket name from Config event")
            print(f"Available keys in detail: {list(detail.keys())}")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Could not find bucket name in event'})
            }
        
        print(f"✓ Extracted bucket name: {bucket_name}")
        
        # Verify bucket exists
        try:
            s3.head_bucket(Bucket=bucket_name)
            print(f"✓ Bucket exists: {bucket_name}")
        except s3.exceptions.NoSuchBucket:
            print(f"ERROR: Bucket {bucket_name} does not exist")
            return {
                'statusCode': 404,
                'body': json.dumps({'error': f'Bucket {bucket_name} not found'})
            }
        except Exception as e:
            print(f"ERROR: Cannot access bucket {bucket_name}: {str(e)}")
            return {
                'statusCode': 403,
                'body': json.dumps({'error': f'Cannot access bucket: {str(e)}'})
            }
        
        actions_taken = []
        
        # Step 1: Block all public access
        try:
            print(f"Blocking public access for {bucket_name}...")
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"✓ Blocked public access for {bucket_name}")
            actions_taken.append("Blocked all public access")
        except Exception as e:
            error_msg = f"⚠️ Could not block public access: {str(e)}"
            print(error_msg)
            actions_taken.append(f"Failed to block public access: {str(e)}")
        
        # Step 2: Enable encryption
        try:
            print(f"Enabling encryption for {bucket_name}...")
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                        'BucketKeyEnabled': True
                    }]
                }
            )
            print(f"✓ Enabled AES-256 encryption for {bucket_name}")
            actions_taken.append("Enabled AES-256 encryption")
        except Exception as e:
            error_msg = f"⚠️ Could not enable encryption: {str(e)}"
            print(error_msg)
            actions_taken.append(f"Encryption already enabled or failed: {str(e)[:50]}")
        
        # Step 3: Add compliance tags
        try:
            print(f"Adding compliance tags to {bucket_name}...")
            
            # Get existing tags first
            existing_tags = []
            try:
                response = s3.get_bucket_tagging(Bucket=bucket_name)
                existing_tags = response.get('TagSet', [])
                print(f"Found {len(existing_tags)} existing tags")
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchTagSet':
                    print(f"Warning: Could not get existing tags: {e}")
            
            # Merge with new tags (don't overwrite existing)
            new_tags = [
                {'Key': 'ComplianceStatus', 'Value': 'Remediated'},
                {'Key': 'RemediationDate', 'Value': datetime.now().isoformat()},
                {'Key': 'RemediatedBy', 'Value': 'AutomatedSecurityResponse'}
            ]
            
            # Combine tags (existing tags take precedence)
            tag_dict = {tag['Key']: tag['Value'] for tag in new_tags}
            for tag in existing_tags:
                tag_dict[tag['Key']] = tag['Value']  # Keep existing values
            
            final_tags = [{'Key': k, 'Value': v} for k, v in tag_dict.items()]
            
            s3.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={'TagSet': final_tags}
            )
            print(f"✓ Added compliance tags to {bucket_name}")
            actions_taken.append("Added compliance tags")
        except Exception as e:
            error_msg = f"⚠️ Could not add tags: {str(e)}"
            print(error_msg)
            actions_taken.append(f"Tagging failed: {str(e)[:50]}")
        
        # Step 4: Verify remediation
        try:
            block_config = s3.get_public_access_block(Bucket=bucket_name)
            public_access = block_config['PublicAccessBlockConfiguration']
            is_fully_blocked = all([
                public_access.get('BlockPublicAcls', False),
                public_access.get('IgnorePublicAcls', False),
                public_access.get('BlockPublicPolicy', False),
                public_access.get('RestrictPublicBuckets', False)
            ])
            print(f"✓ Verification: Public access fully blocked = {is_fully_blocked}")
        except Exception as e:
            print(f"⚠️ Could not verify remediation: {e}")
        
        # Step 5: Send notification
        message = f"""
            ✅ S3 Bucket Automatically Remediated
            
            Bucket Name: {bucket_name}
            
            Actions Taken:
            {chr(10).join(['• ' + action for action in actions_taken])}
            
            Config Rule Violated: s3-bucket-public-read-prohibited
            Remediation Time: {datetime.now().isoformat()}
            Lambda Function: {context.function_name}
            AWS Region: {context.invoked_function_arn.split(':')[3]}
            
            Next Steps:
            1. Verify bucket compliance in AWS Config console
            2. Review bucket policies and ACLs
            3. Confirm legitimate applications still have access
            
            Original Config Event:
            {json.dumps(detail, indent=2, default=str)[:500]}...
        """
        
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f'✅ S3 Remediation Complete: {bucket_name[:50]}',
                Message=message
            )
            print("✓ Sent SNS notification")
        except Exception as e:
            print(f"⚠️ Could not send SNS notification: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully remediated {bucket_name}',
                'actions_taken': actions_taken,
                'bucket': bucket_name
            })
        }
        
    except Exception as e:
        error_msg = f"Error remediating S3 bucket: {str(e)}"
        print("=" * 50)
        print(f"FATAL ERROR: {error_msg}")
        print("=" * 50)
        
        # Try to send error notification
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject='⚠️ S3 Remediation Failed',
                Message=f"""
                    Error in S3 Bucket Remediation Lambda
                    
                    Error: {error_msg}
                    
                    Event Details:
                    {json.dumps(event, indent=2, default=str)}
                    
                    Lambda Function: {context.function_name}
                    Request ID: {context.aws_request_id}
                """
            )
        except Exception as sns_error:
            print(f"Failed to send error notification: {str(sns_error)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
