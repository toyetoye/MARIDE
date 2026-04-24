# Feature Specification: PMS Ad-hoc Maintenance

## Feature Name

Ad-hoc Maintenance

## PROP Equivalent

PROP Engineering ad-hoc maintenance entries.

## Purpose

Ad-hoc Maintenance allows ship staff to record non-scheduled maintenance work and preserve it in component history.

## User Roles

- Chief Engineer
- Engineering Officers
- Technical Superintendent
- Auditor / Surveyor, read-only

## Workflow

1. User selects vessel.
2. User opens Ad-hoc Maintenance.
3. User selects component, where applicable.
4. User enters maintenance description.
5. User enters date completed and done-by details.
6. User attaches files, where applicable.
7. Record enters ad-hoc history.
8. Chief Engineer authorisation may be required depending on configuration.

## Required Fields

- vessel
- component, where applicable
- title / brief description
- full work description
- date completed
- done by rank
- done by person
- attachments, where applicable
- linked defect/action, later phase
- Chief Engineer sign-off, if required

## Permissions

| Action | Permission |
|---|---|
| View ad-hoc maintenance | pms.adhoc.view |
| Create ad-hoc maintenance | pms.adhoc.create |
| Authorise ad-hoc maintenance | pms.adhoc.authorise |
| Export ad-hoc history | pms.adhoc.export |

## Audit Events

- pms_adhoc_created
- pms_adhoc_updated
- pms_adhoc_authorised
- pms_adhoc_exported

## Acceptance Criteria

- Ad-hoc records appear in component history.
- Ad-hoc records appear in maintenance history reports.
- Component linkage is optional but encouraged.
- Authorisation rules can be configured.

