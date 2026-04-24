# FORCAP System Architecture

## Target Architecture

FORCAP should become one platform with one shell, one access-control model, one vessel registry, one audit trail, and module-based functionality.

## Proposed Structure

forcap-platform/
- apps/
  - web/
  - api/
- modules/
  - core/
  - pms/
  - spares/
  - finance/
  - operations/
  - compliance/
  - knowledge/
- packages/
  - ui/
  - auth/
  - db/
  - audit/
  - config/
- docs/

## Current Transition Plan

MARIDE is the current FORCAP shell candidate. Existing apps should be treated as module prototypes and gradually migrated into the unified FORCAP shell.

## Core Platform Services

- authentication
- roles and permissions
- vessel registry
- audit logging
- file storage
- notifications
- reporting
- tenant/customer management later

