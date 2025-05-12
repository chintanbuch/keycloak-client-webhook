# Keycloak Webhook Extension

A Keycloak extension that sends webhook notifications to external APIs when specific user events occur in Keycloak.

## Overview

This extension integrates with Keycloak's event system to capture user-related events such as registration, login, logout, and password resets. When these events occur, the extension sends HTTP POST requests with user data to a configured webhook endpoint.

Key features:
- Listens for REGISTER, LOGIN, LOGOUT, RESET_PASSWORD, VERIFY_EMAIL, and UPDATE_EMAIL events
- Sends structured JSON payloads with comprehensive user information
- Supports authentication with API keys
- Implements retry logic with exponential backoff
- Configurable through Keycloak client attributes

## Requirements

- Java 17 or higher
- Keycloak 26.2.2 or compatible version
- Maven for building the project

## Installation

1. Build the extension:
   ```bash
   mvn clean package
   ```

2. Copy the generated JAR file to Keycloak's providers directory:
   ```bash
   cp target/keycloak-client-webhook.jar /path/to/keycloak/providers/
   ```

3. Restart Keycloak to load the extension.

## Configuration

### 1. Enable the Event Listener

1. Log in to the Keycloak Admin Console
2. Navigate to your realm
3. Go to Realm Settings → Events
4. In the "Event Listeners" field, add `brew-event-webhook`
5. Click "Save"

### 2. Configure Webhook Endpoint

The webhook URL and API key are configured at the client level. For each client that should trigger webhooks:

1. Navigate to Clients in the Keycloak Admin Console
2. Select the client you want to configure
3. Go to the Attributes tab
4. Add the following attributes:
   - `api.url`: The URL of your webhook endpoint (e.g., `https://your-api.example.com/webhooks/keycloak`)
   - `api.key`: The API key or token for authenticating with your webhook endpoint

## Webhook Payload

The extension sends a JSON payload with the following structure:

```json
{
  "type": "LOGIN",
  "user_id": "f:6f8df73e-9c42-4f8b-b3a1-c1d9bcb45f0b",
  "user_name": "john.doe",
  "email": "john.doe@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "email_verified": true,
  "created_timestamp": 1621459200000,
  "user_ip": "192.168.1.1",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
}
```

## Supported Events

The extension currently listens for the following Keycloak events:
- `REGISTER`: When a new user registers
- `LOGIN`: When a user logs in
- `LOGOUT`: When a user logs out
- `RESET_PASSWORD`: When a user resets their password
- `VERIFY_EMAIL`: When a user verifies their email address
- `UPDATE_EMAIL`: When a user's email address is updated

## Troubleshooting

### Webhook Not Triggering

1. Verify the event listener is properly enabled in the realm settings
2. Check that the client has the correct `api.url` and `api.key` attributes
3. Examine Keycloak server logs for any error messages
4. Ensure your webhook endpoint is accessible from the Keycloak server

### HTTP Connection Issues

The extension implements retry logic with exponential backoff. If there are temporary connection issues, it will retry up to 3 times with increasing delays. Since webhook calls are executed asynchronously, these retries happen in the background and don't affect Keycloak's performance or user experience.
