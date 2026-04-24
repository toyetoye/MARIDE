# Feature Specification: PMS Running Hours

## Feature Name

Running Hours

## PROP Equivalent

PROP Engineering running-hour-based maintenance records.

## Purpose

Running Hours supports maintenance jobs triggered by equipment operating hours.

## User Roles

- Chief Engineer
- Second Engineer
- Third Engineer
- Technical Superintendent
- Auditor / Surveyor, read-only

## Workflow

1. User selects vessel.
2. User opens Running Hours.
3. User selects equipment/component.
4. User enters current counter reading.
5. System records reading and calculates due/overdue hourly jobs.
6. Hourly jobs are issued or flagged according to configured thresholds.

## Required Fields

- vessel
- component/equipment
- counter name
- previous reading
- current reading
- reading date/time
- entered by
- source module
- comments

## Permissions

| Action | Permission |
|---|---|
| View running hours | pms.running_hours.view |
| Enter running hours | pms.running_hours.create |
| Correct running hours | pms.running_hours.correct |
| Export running hours | pms.running_hours.export |

## Audit Events

- pms_running_hours_entered
- pms_running_hours_corrected
- pms_hourly_job_due
- pms_hourly_job_overdue

## Acceptance Criteria

- Running-hour readings are vessel-specific.
- Readings are linked to equipment/component.
- Hourly jobs can be generated or flagged.
- Corrections require audit trail.

