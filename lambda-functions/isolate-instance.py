import boto3
import json
from datetime import datetime

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
sns = boto3.client('sns')

SNS_TOPIC_ARN = 'YOUR-SNS-ARN' # EX: arn:aws:sns:us-west-1:184937483839:AlertMe
FORENSICS_BUCKET = 'YOUR BUCKET NAME' # EX: forensics-evidence-bucket
QUARANTINE_SG = 'YOUR SECURITY GROUP ID' # sg-7se8b73d9f7kr738m

def lambda_handler(event, context):
    print("=" * 100)
    print("RECEIVED EVENT:")
    print(json.dumps(event, indent=2, default=str))
    print("=" * 100)
    
    try:
        # Parse the GuardDuty finding from EventBridge
        if 'detail' not in event:
            print("ERROR: No 'detail' field in event")
            return {'statusCode': 400, 'body': 'Invalid event structure'}
        
        detail = event['detail']
        
        # Extract finding information
        finding_type = detail.get('type', 'Unknown')
        severity = detail.get('severity', 0)
        
        print(f"Finding Type: {finding_type}")
        print(f"Severity: {severity}")
        
        # Get resource information
        resource = detail.get('resource', {})
        resource_type = resource.get('resourceType', '')
        
        print(f"Resource Type: {resource_type}")
        
        # Only process EC2 instance findings
        if resource_type != 'Instance':
            print(f"⚠️ Skipping non-EC2 finding: {finding_type}")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Skipped - not an EC2 instance finding',
                    'finding_type': finding_type
                })
            }
        
        # Extract instance ID
        instance_details = resource.get('instanceDetails', {})
        instance_id = instance_details.get('instanceId')
        
        if not instance_id:
            print("ERROR: No instance ID found in finding")
            return {'statusCode': 400, 'body': 'No instance ID found'}
        
        print(f"✓ Processing instance: {instance_id}")
        
        # Get instance details and check if it exists
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            
            if not response['Reservations']:
                print(f"ERROR: Instance {instance_id} not found")
                return {'statusCode': 404, 'body': 'Instance not found'}
            
            instance = response['Reservations'][0]['Instances'][0]
            instance_state = instance['State']['Name']
            
            print(f"Instance state: {instance_state}")
            
            # Only proceed if instance is running
            if instance_state not in ['running', 'stopped']:
                print(f"⚠️ Instance is {instance_state}, skipping isolation")
                send_notification(
                    f"Instance {instance_id} is {instance_state} - cannot isolate",
                    finding_type,
                    severity,
                    instance_id
                )
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': f'Instance is {instance_state}, cannot isolate'
                    })
                }
            
        except ec2.exceptions.ClientError as e:
            print(f"ERROR describing instance: {str(e)}")
            return {'statusCode': 500, 'body': f'Error describing instance: {str(e)}'}
        
        # Step 1: Create EBS snapshot for forensics (if volumes exist)
        snapshot_id = None
        block_devices = instance.get('BlockDeviceMappings', [])
        
        if block_devices:
            try:
                # Get the root volume
                root_volume = block_devices[0].get('Ebs', {})
                volume_id = root_volume.get('VolumeId')
                
                if volume_id:
                    print(f"Creating snapshot of volume: {volume_id}")
                    snapshot = ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=f'Forensic snapshot - {finding_type} - {datetime.now().isoformat()}',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Purpose', 'Value': 'Forensics'},
                                {'Key': 'InstanceId', 'Value': instance_id},
                                {'Key': 'FindingType', 'Value': finding_type},
                                {'Key': 'Severity', 'Value': str(severity)},
                                {'Key': 'CreatedBy', 'Value': 'AutomatedIncidentResponse'}
                            ]
                        }]
                    )
                    snapshot_id = snapshot['SnapshotId']
                    print(f"✓ Created forensic snapshot: {snapshot_id}")
                else:
                    print("⚠️ No EBS volume found, skipping snapshot")
            except Exception as e:
                print(f"⚠️ Error creating snapshot: {str(e)}")
                # Continue with isolation even if snapshot fails
        else:
            print("⚠️ No block devices found, skipping snapshot")
        
        # Step 2: Isolate instance by replacing security group
        try:
            print(f"Isolating instance with quarantine SG: {QUARANTINE_SG}")
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[QUARANTINE_SG]
            )
            print(f"✓ Isolated instance {instance_id}")
        except Exception as e:
            print(f"ERROR isolating instance: {str(e)}")
            raise
        
        # Step 3: Save incident metadata to S3
        incident_data = {
            'timestamp': datetime.now().isoformat(),
            'instance_id': instance_id,
            'finding_type': finding_type,
            'severity': severity,
            'snapshot_id': snapshot_id,
            'actions_taken': {
                'snapshot_created': snapshot_id is not None,
                'instance_isolated': True
            },
            'instance_state': instance_state,
            'full_finding': detail
        }
        
        try:
            s3_key = f'incidents/{instance_id}/{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
            s3.put_object(
                Bucket=FORENSICS_BUCKET,
                Key=s3_key,
                Body=json.dumps(incident_data, indent=2, default=str),
                ContentType='application/json'
            )
            print(f"✓ Saved incident data to S3: {s3_key}")
        except Exception as e:
            print(f"⚠️ Error saving to S3: {str(e)}")
            # Continue even if S3 fails
        
        # Step 4: Send SNS alert
        message = f"""
              🚨 SECURITY ALERT - Automated Incident Response Executed
              
              Instance ID: {instance_id}
              Finding Type: {finding_type}
              Severity: {severity}
              
              Actions Taken:
              ✓ Instance isolated with quarantine security group ({QUARANTINE_SG})
              {f'✓ Forensic snapshot created: {snapshot_id}' if snapshot_id else '⚠️ No snapshot created'}
              ✓ Incident data saved to S3: {FORENSICS_BUCKET}/incidents/{instance_id}/
              
              Next Steps:
              1. Review GuardDuty finding in AWS Console
              2. Investigate instance logs in CloudWatch
              {f'3. Analyze forensic snapshot: {snapshot_id}' if snapshot_id else '3. Instance uses instance-store volumes'}
              4. Create incident timeline
              
              Time: {datetime.now().isoformat()}
              Region: {context.invoked_function_arn.split(':')[3]}
        """
        
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f'🚨 SECURITY ALERT: {finding_type[:80]}',
                Message=message
            )
            print("✓ Sent SNS notification")
        except Exception as e:
            print(f"⚠️ Error sending SNS: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Incident response completed successfully',
                'instance_id': instance_id,
                'snapshot_id': snapshot_id,
                'finding_type': finding_type
            })
        }
        
    except Exception as e:
        error_msg = f"Error processing incident: {str(e)}"
        print("=" * 50)
        print(f"FATAL ERROR: {error_msg}")
        print("=" * 50)
        
        # Try to send error notification
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject='⚠️ Lambda Error - Incident Response Failed',
                Message=f"""
                    Error in Automated Incident Response Lambda
                    
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


def send_notification(message, finding_type, severity, instance_id):
    """Helper function to send simple notifications"""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'🔔 Security Alert: {finding_type[:80]}',
            Message=f"""
                Instance: {instance_id}
                Finding: {finding_type}
                Severity: {severity}
                
                {message}
                
                Time: {datetime.now().isoformat()}
            """
        )
    except Exception as e:
        print(f"Error sending notification: {str(e)}")
