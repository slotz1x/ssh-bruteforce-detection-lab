# Splunk Detection Searches

## 1. Multiple SSH Authentication Attempts

### Purpose
Detect a high volume of SSH authentication attempts within a defined
time period.

### SPL
index="bruteforce_lab"
("Failed password" OR "Accepted password")
| eval result=case(
like(_raw,"%Failed password%"), "Failed",
like(_raw,"%Accepted password%"), "Successful"
)
| timechart span=10s count by result
| where Failed > 0 OR Successful > 0

### Detection Logic
Identifies unusually frequent SSH authentication activity that may
indicate password guessing.


## 2. Multiple Failures Followed by Success

### Purpose
Identify repeated failed SSH authentication attempts followed by
successful authentication from the same source against the same user.

### SPL
index="bruteforce_lab" 
("Failed Password" OR "Accepted password") 
| rex "(?:Failed|Accepted) password for (?:invalid user )?(?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})" 
| eval result=case(
like(_raw,"%Failed password%"), "failure",
like(_raw,"%Accepted password%"), "success"
)
| stats 
count(eval(result="failure")) AS failed_attempts 
count(eval(result="success")) AS successful_attempts 
earliest(_time) AS first_attempt 
latest(_time) AS last_attempt 
by src_ip username 
| where failed_attempts >= 5 AND successful_attempts >=1 
| convert ctime(first_attempt) ctime(last_attempt)

### Detection Logic
Correlates failed and successful authentication events and verifies
that the successful authentication occurred after the failures.


## 3. One Source IP Attempting Multiple Usernames

### Purpose
Identify a single source attempting authentication against multiple
user accounts.

### SPL
index="bruteforce_lab" "Failed password"
| rex "Failed password for (?:invalid user )?(?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
|stats count AS failed_attempts
dc(username) AS unique_users
values(username) AS targeted_users
by src_ip
| where failed_attempts >=5 AND unique_users >=3

### Detection Logic
Groups authentication activity by source IP and identifies sources
targeting multiple distinct usernames.
