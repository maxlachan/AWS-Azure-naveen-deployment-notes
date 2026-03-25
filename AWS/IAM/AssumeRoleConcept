# AWS Cross-Account Assume Role (Console Steps)

## 🎯 Scenario

* Account A → IAM User (`DevUser`)
* Account B → S3 Bucket
* Goal → User in Account A accesses S3 in Account B using Assume Role

---

## 🧠 Flow

Account A (User) → Assume Role → Account B (Role) → Access S3

---

## 🔵 Step 1: Create Role in Account B

1. Go to **IAM → Roles → Create role**
2. Select:

   * Trusted entity: **AWS account**
   * Choose: **Another AWS account**
3. Enter Account A ID:

   ```
   ACCOUNT_A_ID
   ```
4. Attach permission:

   * `AmazonS3ReadOnlyAccess`
5. Name role:

   ```
   CrossAccountS3Role
   ```
6. Click **Create role**

---

## 🔐 Step 2: Verify Trust Policy (Account B)

IAM → Roles → `CrossAccountS3Role` → Trust relationships

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::ACCOUNT_A_ID:root"
  },
  "Action": "sts:AssumeRole"
}
```

---

## 🟢 Step 3: Give Permission to User (Account A)

1. Go to **IAM → Users → DevUser**
2. Click **Add permissions → Create inline policy**
3. Add:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::ACCOUNT_B_ID:role/CrossAccountS3Role"
}
```

---

## 🟡 Step 4: Switch Role (Account A User)

1. Login as `DevUser`
2. Click top-right username → **Switch Role**
3. Enter:

   * Account ID: `ACCOUNT_B_ID`
   * Role name: `CrossAccountS3Role`
4. Click **Switch Role**

---

## ✅ Step 5: Test

* Go to **S3**
* You can now access Account B resources 🎉

---

## 🧠 Key Points

* Trust policy → Account B trusts Account A
* User policy → User allowed to assume role
* Access is temporary (STS)

---

## ⚠️ Best Practice

Instead of:

```json
"AWS": "arn:aws:iam::ACCOUNT_A_ID:root"
```

Use:

```json
"AWS": "arn:aws:iam::ACCOUNT_A_ID:user/DevUser"
```

---

## 🎯 Summary

Cross-account access is achieved by creating a role in the target account that trusts another account and allowing a user in the source account to assume that role.
