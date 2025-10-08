import boto3
import json
from datetime import datetime

sns = boto3.client('sns')
s3 = boto3.client('s3')

SNS_TOPIC_ARN = 'YOUR-SNS-ARN' # EX: arn:aws:sns:us-west-1:184937483839:AlertMe
FORENSICS_BUCKET = 'YOUR BUCKET NAME' # EX: forensics-evidence-bucket

def lambda_handler(event, context):
    print("=" * 100)
    print("RECEIVED CLOUDTRAIL EVENT:")
    print(json.dumps(event, indent=2, default=str))
    print("=" * 100)
    
    try:
        # Validate event structure
        if 'detail' not in event:
            print("ERROR: No 'detail' field in event")
            return {'statusCode': 400, 'body': 'Invalid event structure'}
        
        detail = event['detail']
        
        # Extract key information
        event_name = detail.get('eventName', 'Unknown')
        event_time = detail.get('eventTime', datetime.now().isoformat())
        event_source = detail.get('eventSource', 'Unknown')
        aws_region = detail.get('awsRegion', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        user_agent = detail.get('userAgent', 'Unknown')
        error_code = detail.get('errorCode', None)
        error_message = detail.get('errorMessage', None)
        
        # User identity information
        user_identity = detail.get('userIdentity', {})
        user_type = user_identity.get('type', 'Unknown')
        principal_id = user_identity.get('principalId', 'Unknown')
        arn = user_identity.get('arn', 'Unknown')
        account_id = user_identity.get('accountId', 'Unknown')
        
        print(f"Event: {event_name}")
        print(f"User Type: {user_type}")
        print(f"Principal: {principal_id}")
        print(f"Source IP: {source_ip}")
        
        # Analyze threat level
        threat_indicators = []
        alert_level = 'INFO'
        
        # CRITICAL: Root account usage
        if user_type == 'Root':
            threat_indicators.append("🚨 ROOT ACCOUNT USAGE DETECTED")
            alert_level = 'CRITICAL'
            print("⚠️ CRITICAL: Root account activity detected!")
        
        # HIGH: IAM privilege changes
        iam_critical_events = [
            'CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
            'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy',
            'CreateRole', 'DeleteRole', 'UpdateAssumeRolePolicy',
            'CreatePolicyVersion', 'SetDefaultPolicyVersion'
        ]
        
        if any(event_name.startswith(evt) for evt in iam_critical_events):
            threat_indicators.append("⚠️ IAM privilege modification detected")
            if alert_level == 'INFO':
                alert_level = 'HIGH'
            print("⚠️ HIGH: IAM modification detected")
        
        # HIGH: Security group changes
        security_events = [
            'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
            'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
            'CreateSecurityGroup', 'DeleteSecurityGroup'
        ]
        
        if event_name in security_events:
            threat_indicators.append("🔓 Security group modification detected")
            if alert_level == 'INFO':
                alert_level = 'HIGH'
            print("⚠️ HIGH: Security group change detected")
        
        # MEDIUM: Console login attempts
        if event_name == 'ConsoleLogin':
            if error_code:
                threat_indicators.append(f"❌ Failed console login attempt: {error_message}")
                alert_level = 'MEDIUM'
                print("⚠️ MEDIUM: Failed console login")
            else:
                threat_indicators.append("✓ Successful console login")
                if alert_level == 'INFO':
                    alert_level = 'LOW'
                print("ℹ️ Console login successful")
        
        # MEDIUM: Authentication failures
        auth_failure_events = ['PasswordRecoveryRequested', 'PasswordRecoveryCompleted']
        if event_name in auth_failure_events or error_code in ['AccessDenied', 'UnauthorizedOperation']:
            threat_indicators.append(f"🔐 Authentication/authorization issue: {error_code}")
            if alert_level == 'INFO':
                alert_level = 'MEDIUM'
            print("⚠️ MEDIUM: Auth failure detected")
        
        # HIGH: S3 bucket policy changes
        s3_sensitive_events = [
            'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl',
            'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock'
        ]
        
        if event_name in s3_sensitive_events:
            threat_indicators.append("🪣 S3 bucket security policy modified")
            if alert_level not in ['CRITICAL', 'HIGH']:
                alert_level = 'MEDIUM'
            print("⚠️ MEDIUM: S3 policy change detected")
        
        # HIGH: CloudTrail modifications (trying to hide tracks)
        cloudtrail_events = [
            'StopLogging', 'DeleteTrail', 'UpdateTrail', 
            'PutEventSelectors', 'DeleteEventDataStore'
        ]
        
        if event_name in cloudtrail_events:
            threat_indicators.append("📝 CLOUDTRAIL TAMPERING ATTEMPT")
            alert_level = 'CRITICAL'
            print("⚠️ CRITICAL: CloudTrail tampering detected!")
        
        # Check for suspicious IP patterns
        if source_ip != 'Unknown':
            # Check if IP is from AWS service (these are generally safe)
            is_aws_service = source_ip.endswith('.amazonaws.com') or source_ip.startswith('AWS Internal')
            
            # Check for common suspicious patterns
            suspicious_ips = ['tor-exit', 'proxy', 'vpn']
            if not is_aws_service and any(pattern in source_ip.lower() for pattern in suspicious_ips):
                threat_indicators.append(f"🌐 Suspicious source IP: {source_ip}")
                if alert_level not in ['CRITICAL', 'HIGH']:
                    alert_level = 'MEDIUM'
        
        # Only alert if there are threat indicators
        if not threat_indicators:
            print("ℹ️ No threat indicators found - skipping alert")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Event processed but no threats detected',
                    'event_name': event_name
                })
            }
        
        print(f"Alert Level: {alert_level}")
        print(f"Threat Indicators: {len(threat_indicators)}")
        
        # Step 1: Save event to S3 for forensic analysis
        try:
            date_path = datetime.now().strftime("%Y/%m/%d")
            s3_key = f'cloudtrail-alerts/{date_path}/{alert_level}-{event_name}-{datetime.now().strftime("%H%M%S")}.json'
            
            # Enrich event data
            enriched_event = {
                'alert_metadata': {
                    'alert_level': alert_level,
                    'threat_indicators': threat_indicators,
                    'analysis_time': datetime.now().isoformat(),
                    'lambda_function': context.function_name
                },
                'original_event': detail
            }
            
            s3.put_object(
                Bucket=FORENSICS_BUCKET,
                Key=s3_key,
                Body=json.dumps(enriched_event, indent=2, default=str),
                ContentType='application/json'
            )
            print(f"✓ Saved event to S3: {s3_key}")
        except Exception as e:
            print(f"⚠️ Could not save to S3: {str(e)}")
            # Continue even if S3 fails
        
        # Step 2: Build detailed alert message
        alert_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '🔍',
            'LOW': 'ℹ️',
            'INFO': '📋'
        }
        
        message = f"""
            {alert_emoji.get(alert_level, '🔔')} CLOUDTRAIL SECURITY ALERT - {alert_level}
            
            Event Details:
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            Event Name: {event_name}
            Event Source: {event_source}
            Event Time: {event_time}
            AWS Region: {aws_region}
            
            User/Identity Information:
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            User Type: {user_type}
            Principal ID: {principal_id}
            ARN: {arn}
            Account ID: {account_id}
            
            Network Information:
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            Source IP: {source_ip}
            User Agent: {user_agent}
            
            Threat Indicators:
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            {chr(10).join(threat_indicators)}
            
            {f"Error Details:{chr(10)}Code: {error_code}{chr(10)}Message: {error_message}" if error_code else "Status: Success (No Errors)"}
            
            Forensic Evidence:
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            S3 Location: s3://{FORENSICS_BUCKET}/cloudtrail-alerts/{date_path}/
            Full Event Data: Saved with timestamp {datetime.now().strftime("%H%M%S")}
            
            Recommended Actions:
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            1. Review full CloudTrail event in AWS Console
            2. Investigate source IP address and user identity
            3. Check for additional suspicious activity from this user/IP
            4. Consider revoking credentials if unauthorized
            5. Review IAM policies and security group rules
            
            Detection Time: {datetime.now().isoformat()}
            Lambda Function: {context.function_name}
            AWS Region: {context.invoked_function_arn.split(':')[3]}
        """
        
        # Step 3: Send SNS alert
        try:
            subject = f'{alert_emoji.get(alert_level, "🔔")} {alert_level} Alert: {event_name}'
            if len(subject) > 100:
                subject = subject[:97] + '...'
            
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=subject,
                Message=message
            )
            print("✓ Sent SNS notification")
        except Exception as e:
            print(f"⚠️ Could not send SNS notification: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Alert processed successfully',
                'alert_level': alert_level,
                'event_name': event_name,
                'threat_indicators': len(threat_indicators)
            })
        }
        
    except Exception as e:
        error_msg = f"Error processing CloudTrail event: {str(e)}"
        print("=" * 50)
        print(f"FATAL ERROR: {error_msg}")
        print("=" * 50)
        
        # Try to send error notification
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject='⚠️ Lambda Error - CloudTrail Alert Processing Failed',
                Message=f"""
                    Error in CloudTrail Alert Lambda
                    
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
