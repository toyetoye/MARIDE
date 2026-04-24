# FORCAP Roles and Permissions

## Access Model

FORCAP permissions are based on:

- user identity
- role
- vessel assignment
- module access
- action-level permission
- ship/shore context

## Initial Roles

- System Admin
- Company Admin
- Fleet Manager
- Technical Manager
- Marine Superintendent
- Technical Superintendent
- Master
- Chief Engineer
- Chief Officer
- Second Engineer
- Third Engineer
- Fourth Engineer
- Electrical Officer
- Finance User
- Procurement User
- Stores User
- Auditor / Surveyor
- Supplier / Agent
- Read-only User

## Action Permissions

- view
- create
- update
- delete
- issue
- assign
- defer
- complete
- return
- authorise
- close
- print
- export
- approve
- send_to_office
- receive_goods
- configure

## PMS-Specific Permission Rules

| Action | Typical Roles | Notes |
|---|---|---|
| View issued worksheets | Engineering officers, CE, superintendent | Vessel access required |
| Complete worksheet | Assigned rank/officer, CE | Vessel access required |
| Defer worksheet | CE, superintendent, authorised roles | Defer reason required |
| Return worksheet | CE, superintendent | Return reason required |
| Authorise worksheet | CE, authorised superintendent | Required before final history |
| Configure PM templates | Superintendent, admin | Controlled access |
| Export PMS reports | CE, superintendent, auditor | Audit event required |

