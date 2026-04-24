# FORCAP Security Overview

## Security Objectives

FORCAP shall protect confidentiality, integrity, and availability of customer and vessel data.

## Initial Controls

- unique user accounts
- password hashing
- role-based access control
- vessel-level access control
- module-level access control
- action-level permissions
- session expiry
- audit logging
- secure file upload validation
- environment validation
- restricted CORS
- rate limiting
- backup and restore testing
- separation of development, staging, and production environments

## Pre-launch Security Requirements

- remove all default production passwords
- remove fallback JWT/session secrets
- centralise authentication
- remove query-string authentication tokens
- add production environment validation
- add monitoring and error logging

