# Splunk Alerts

Three scheduled alerts were created to identify different patterns of
suspicious SSH authentication activity.

## Alert Methodology

All three alerts use the same scheduling and trigger configuration:

**Schedule:**
Every 5 minutes

**Cron:**
"*/5 * * * *"
 
**Trigger:**
Triggers when scheduled search returns one or more results

Each alert uses a different SPL search to identify a specific authentication
behavior. When the search meets the configured trigger condition, Splunk
generates an alert for analyst review.


## 1. Multiple SSH Authentication Attempts

**Purpose:**  
Identify unusually frequent SSH authentication activity that may indicate
password guessing.

**Behavior:**  
Volume — multiple authentication attempts within the search period.


## 2. Multiple Failures Followed by Success

**Purpose:**  
Identify repeated failed authentication attempts followed by successful
authentication from the same source against the same account.

**Behavior:**  
Sequence — authentication failures followed by a successful login.


## 3. One Source IP Attempting Multiple Usernames

**Purpose:**  
Identify a single source attempting SSH authentication against multiple
usernames.

**Behavior:**  
Breadth — one source targeting multiple user accounts.


## Summary

The three alerts analyze SSH authentication activity from complementary
behavioral perspectives: **volume, sequence, and breadth**.
