# Sustainability Review Scripts

## AWS Storage Capacity Checker
script: check_storage_capacity_ec2.py

A Python script to check EC2 instance storage capacity across AWS regions.

## 🚀 Features

- Check storage capacity across all AWS regions
- Single region analysis
- Concurrent processing with configurable workers
- Comprehensive storage metrics

## 📋 Usage Examples

### Check All AWS Regions
```bash
python3 check_storage_capacity_ec2.py --mode all-regions
```

### Check All Regions with Increased Concurrency
```bash
python3 check_storage_capacity_ec2.py --mode all-regions --max-workers 10
```

### Check Single Region
```bash
python3 check_storage_capacity_ec2.py --mode single-region --region us-west-2
```

### Check Specific Instance
```bash
python3 check_storage_capacity_ec2.py --mode specific-instance --instance-id i-1234567890abcdef0 --region us-east-1
```

## 🔧 Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `--mode` | Operation mode (`all-regions`, `single-region`, `specific-instance`) | ✅ | - |
| `--region` | AWS region to check | ⚠️ | `us-east-1` |
| `--instance-id` | Specific EC2 instance ID | ⚠️ | - |
| `--max-workers` | Number of concurrent workers | ❌ | `5` |

> ⚠️ Required for specific modes

---

## AWS Idle Instance Checker 💤
script: check_idle_instances.py

A Python script to identify EC2 instances that have been stopped for extended periods, helping optimize AWS costs and resource management.

## 🚀 Features

- **Multi-region scanning**: Check all AWS regions automatically
- **Time-based categorization**: Separate instances stopped >1 week vs <1 week
- **Detailed reporting**: Instance names, types, stop times, and duration
- **Cost optimization insights**: Recommendations for long-stopped instances
- **Comprehensive parsing**: Multiple timestamp format support
- **Regional breakdown**: Summary statistics by AWS region

## 📋 Usage Examples

### Check All Regions for Idle Instances
```bash
python3 check_idle_instances.py
```

## 📊 Output Information

The script provides detailed information including:

- **Instance Details**: ID, name, type, and region
- **Stop Duration**: Days since instance was stopped
- **Categorization**: 
  - 🔴 Stopped > 1 week (potential cost savings)
  - 🟡 Stopped < 1 week (recently paused)
- **Summary Statistics**: Total instances by state and region
- **Cost Recommendations**: Actions to optimize AWS spending

---

## S3 Lifecycle Policy Checker 🪣
script: check_s3_lifecycle.sh

A bash script to audit S3 bucket lifecycle policies across your AWS account, identifying buckets without proper cost optimization rules.

## 🚀 Features

- **Account-wide scanning**: Check all S3 buckets in your account
- **Lifecycle policy detection**: Identify buckets with and without lifecycle rules
- **JSON formatted output**: Detailed policy information when available
- **Cost optimization insights**: Find buckets missing lifecycle policies
- **Error handling**: Graceful handling of access permissions

## 📋 Usage Examples

### Check All Buckets for Lifecycle Policies
```bash
chmod +x check_s3_lifecycle.sh
./check_s3_lifecycle.sh
```
---

## S3 Encryption Status Checker 🔐
script: check-versioning.sh

A bash script to audit S3 bucket encryption settings across your AWS account, ensuring data security compliance.

## 🚀 Features

- **Account-wide encryption audit**: Check all S3 buckets for encryption
- **Encryption algorithm detection**: Identify AES256, KMS, or other methods
- **Security compliance**: Ensure all buckets meet encryption requirements
- **Quick status overview**: Simple enabled/disabled reporting

## 📋 Usage Examples

### Check All Buckets for Encryption
```bash
chmod +x check-versioning.sh
./check-versioning.sh
```
---

## RDS Storage Usage Monitor 🗄️
script: check_rds_storage.py

A comprehensive Python script to monitor RDS and Aurora storage usage, trends, and optimization opportunities.

## 🚀 Features

- **Multi-database support**: RDS instances and Aurora clusters
- **Storage trend analysis**: Track usage patterns over time
- **Auto-scaling monitoring**: Check configuration and remaining capacity
- **Performance insights**: IOPS utilization and storage throughput
- **Cost optimization**: Identify over-provisioned resources
- **CloudWatch integration**: Historical metrics and trending

## 📋 Usage Examples

### Basic Storage Analysis (7 days)
```bash
python3 check_rds_storage.py
```

### Extended Analysis with Custom Region
```bash
python3 check_rds_storage.py --region us-west-2 --days 30
```

### JSON Output for Automation
```bash
python3 check_rds_storage.py --format json --days 14
```

## 🔧 Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `--region`, `-r` | AWS region to analyze | ❌ | Current session region |
| `--days`, `-d` | Analysis period in days | ❌ | `7` |
| `--format`, `-f` | Output format (`console`, `json`) | ❌ | `console` |

## 🛠️ Prerequisites

- Python 3.12+
- AWS CLI configured with appropriate permissions
- Required Python packages:
  - `boto3`
  - Standard library modules

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/Beaty-Consultancy/scripts.git
cd aws-scripts/sustainability
```

2. Install dependencies:
```bash
python3 -m venv aws-env
source aws-env/bin/activate
pip3 install -r requirements.txt
```

3. Configure AWS CLI:
```bash
aws configure
or export AWS_PROFILE=your-profile-name
```

4. Make scripts executable:
```bash
chmod +x *.sh
```