# 🔐 Identity vs Resource-Based Policies in AWS

## 🧠 What is the Difference?

### 🟢 Identity-Based Policy

* Attached to **User / Role / Group**
* Defines:

  > “What actions can this identity perform?”

---

### 🔵 Resource-Based Policy

* Attached to **AWS Resource (like S3 bucket)**
* Defines:

  > “Who can access this resource?”

---

## 🎯 Example Scenario

* 👤 User: `DevUser`
* 📦 S3 Bucket: `my-demo-bucket`

Goal:

* Allow user to **read objects from S3**

---

# 🟢 Identity-Based Policy Example

Attach this to **IAM User (DevUser)**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-demo-bucket/*"
    }
  ]
}
```

👉 Meaning:

* User can read objects from the bucket

---

# 🔵 Resource-Based Policy Example (S3 Bucket Policy)

Attach this to **S3 Bucket**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:user/DevUser"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-demo-bucket/*"
    }
  ]
}
```

👉 Meaning:

* Bucket allows this specific user to read objects

---

## ⚖️ How AWS Evaluates

```text
Identity Policy  +  Resource Policy  → Final Decision
```

---

### ✅ Case 1: Both Allow

* Identity Policy → Allow
* Resource Policy → Allow

👉 Result: **Access Allowed**

---

### ❌ Case 2: One Deny

* Identity Policy → Allow
* Resource Policy → Deny

👉 Result: **Access Denied**

---

## 🔐 Important Rule

> **Explicit Deny overrides everything**

---

## 🧠 Key Differences

| Feature              | Identity Policy     | Resource Policy     |
| -------------------- | ------------------- | ------------------- |
| Attached to          | User / Role / Group | Resource            |
| Defines              | What you can do     | Who can access      |
| Principal field      | ❌ Not required      | ✅ Required          |
| Cross-account access | ❌ Needs role        | ✅ Directly possible |

---

## 🎯 Summary

* Identity policy → controls **actions of a user**
* Resource policy → controls **access to a resource**
* Both work together for final access decision

---

## 🧠 Key Concept

> **Access is granted only if allowed and not explicitly denied**
