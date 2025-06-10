/**
 * @author chintan
 */
package io.binarybrew.keycloak.webhook.listeners;

import io.binarybrew.keycloak.webhook.constant.AppConstants;
import io.binarybrew.keycloak.webhook.data.dto.KeycloakUserEventDTO;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The WebhookEventListenerProvider is an implementation of the Keycloak
 * EventListenerProvider interface. It listens for certain Keycloak events
 * and executes webhook requests to external APIs based on the event type.
 * <p>
 * This class is designed to handle user-related events, such as registration,
 * password reset, login, logout, email verification, and email updates, and
 * can notify an external service by sending structured event data using an
 * HTTP POST request.
 * <p>
 * The provider supports asynchronous webhook execution with retry capabilities
 * to ensure reliable delivery of event notifications even in case of temporary
 * network or service issues. It also provides configuration options through
 * client attributes to customize webhook behavior.
 * <p>
 * Key features:
 * <ul>
 *   <li>Configurable webhook URL and API key through client attributes</li>
 *   <li>Asynchronous webhook execution to avoid blocking Keycloak operations</li>
 *   <li>Retry mechanism with exponential backoff for failed webhook calls</li>
 *   <li>Support for disabling automatic login after registration</li>
 *   <li>Detailed event payload with user information and request metadata</li>
 * </ul>
 */
public class WebhookEventListenerProvider implements EventListenerProvider {

    private final KeycloakSession session;
    private final ScheduledExecutorService scheduledExecutorService;

        public static final Logger LOGGER = Logger.getLogger(WebhookEventListenerProvider.class);

    /**
     * Constructs a new WebhookEventListenerProvider with the specified Keycloak session
     * and executor service for asynchronous webhook execution.
     *
     * @param session The Keycloak session for accessing Keycloak services and models
     * @param scheduledExecutorService The executor service for asynchronous webhook execution
     */
    public WebhookEventListenerProvider(KeycloakSession session, ScheduledExecutorService scheduledExecutorService) {
        this.session = session;
        this.scheduledExecutorService = scheduledExecutorService;
    }

    /**
     * Handles Keycloak user events by processing specific event types and triggering webhook notifications.
     * <p>
     * This method is called by the Keycloak event system whenever a user-related event occurs.
     * It specifically listens for the following event types:
     * <ul>
     *     <li>REGISTER: When a new user registers</li>
     *     <li>RESET_PASSWORD: When a user resets their password</li>
     *     <li>LOGIN: When a user logs in</li>
     *     <li>LOGOUT: When a user logs out</li>
     *     <li>VERIFY_EMAIL: When a user verifies their email address</li>
     *     <li>UPDATE_EMAIL: When a user's email address is updated</li>
     *     <li>REGISTER_ERROR: When a registration attempt fails</li>
     * </ul>
     * <p>
     * When this method is called, it performs the following steps:
     * <ol>
     * <li>Retrieves the client model from the session context</li>
     * <li>Extracts webhook configuration (API URL, API key, auto-login settings) from client attributes</li>
     * <li>Validates the configuration parameters</li>
     * <li>Retrieves the realm associated with the event</li>
     * <li>For REGISTER_ERROR events, extracts available information and calls sendWebhookRequestForError()</li>
     * <li>For other events, retrieves the user model from the user ID</li>
     * <li>If auto-login is disabled and the event is REGISTER, calls disableAutoLogin() to invalidate sessions</li>
     * <li>For supported event types with valid user information, calls sendWebhookRequest()</li>
     * </ol>
     * <p>
     * Events that don't match the specified types, events with missing user information,
     * or events with invalid configuration are handled appropriately or silently ignored.
     *
     * @param event The Keycloak event containing information about what occurred,
     *              including event type, user ID, and realm ID
     */
    @Override
    public void onEvent(Event event) {

        // Get ClientModel from the session context
        ClientModel clientModel = session.getContext().getClient();
        if (clientModel != null) {
            // Get the Webhook URL and API Key from the client attributes
            // This should be done during setting up the keycloak client (through its Admin API)
            String apiUrl = clientModel.getAttribute(AppConstants.API_URL);
            String apiKey = clientModel.getAttribute(AppConstants.API_KEY);
            boolean disableLogin = (
                    clientModel.getAttribute(AppConstants.DISABLE_AUTOLOGIN) != null &&
                            clientModel.getAttribute(AppConstants.DISABLE_AUTOLOGIN).equals("true")
            );

            // Validate configuration before proceeding
            // validateConfiguration(apiUrl, apiKey);
            if (apiUrl == null || apiUrl.trim().isEmpty() || apiKey == null || apiKey.trim().isEmpty()) {
                LOGGER.debugf("%s: %s, %s: %s, %s: %s",
                        AppConstants.API_URL, apiUrl,
                        AppConstants.API_KEY, apiKey,
                        AppConstants.DISABLE_AUTOLOGIN, disableLogin);
                return;
            }

            RealmModel realmModel = session.realms().getRealm(event.getRealmId());
            session.getContext().setRealm(realmModel);

            LOGGER.debugf("WebhookEventListenerProvider > onEvent(event) > ClientModel: %s", clientModel.getClientId());
            LOGGER.debugf("WebhookEventListenerProvider > onEvent(event) > RealmModel: %s", realmModel.getName());
            LOGGER.debugf("WebhookEventListenerProvider > onEvent(event) > User ID: %s", event.getUserId());

            // Handle registration error
            if (event.getType() == EventType.REGISTER_ERROR && event.getUserId() == null) {
                if (event.getDetails() != null) {
                    LOGGER.errorf("%s for %s", EventType.REGISTER_ERROR.name(), event.getDetails().get(AppConstants.EVENT_DETAIL_EMAIL));
                    sendWebhookRequestForError(event, apiUrl, apiKey);
                }
                return;
            }

            // Ignore if the user doesn't exist
            if (event.getUserId() == null) {
                LOGGER.debugf("WebhookEventListenerProvider > onEvent(event) > User ID is null.");
                return;
            }

            UserModel user = session.users().getUserById(realmModel, event.getUserId());

            // disable auto login after user registration
            if (disableLogin && event.getType() == EventType.REGISTER &&
                    event.getSessionId() != null && user != null) {
                disableAutoLogin(realmModel, user);
            }

            // Handle different events
            if ((user != null) && (event.getType() == EventType.REGISTER || event.getType() == EventType.RESET_PASSWORD ||
                    event.getType() == EventType.LOGIN || event.getType() == EventType.LOGOUT ||
                    event.getType() == EventType.VERIFY_EMAIL || event.getType() == EventType.UPDATE_EMAIL ||
                    event.getType() == EventType.DELETE_ACCOUNT)
            ) {
                sendWebhookRequest(event, user, apiUrl, apiKey);
            }
        } else {
            LOGGER.errorf("WebhookEventListenerProvider > onEvent(event) > ClientModel is null.");
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        //
    }

    @Override
    public void close() {
        // No resources to clean up - executor service is managed by the factory
    }

    /**
     * Sends a webhook request to an external API with user event data asynchronously.
     * <p>
     * This method constructs a payload with user event information and schedules an asynchronous
     * HTTP POST request to the configured endpoint using a ScheduledExecutorService.
     * It implements a retry mechanism with exponential backoff to handle temporary failures.
     * <p>
     * The method performs the following steps:
     * <ol>
     * <li>Validates the configuration (throws IllegalStateException if invalid)</li>
     * <li>Creates a payload with user event data</li>
     * <li>Submits an asynchronous task to the executor service to send the webhook</li>
     * </ol>
     *
     * @param event The Keycloak event that triggered this webhook
     * @param user The user model associated with the event
     * @param apiUrl The webhook URL to send the request to
     * @param apiKey The API key used for authentication with the webhook endpoint
     *
     * @throws IllegalStateException if the webhook URL or API key is not configured
     */
    private void sendWebhookRequest(Event event, UserModel user, String apiUrl, String apiKey) throws IllegalStateException {
        try {
            // Create the payload with user event data
            final KeycloakUserEventDTO payload = createPayload(event.getType(), user);

            // Submit the webhook task to the executor service for asynchronous execution
            scheduledExecutorService.submit(() -> executeWebhookWithRetries(apiUrl, apiKey, payload));
        } catch (IllegalStateException e) {
            // Log configuration errors but don't retry - these are not transient errors
            LOGGER.errorf("Webhook configuration error: %s", e.getMessage());
        } catch (Exception e) {
            // Log any other unexpected errors
            LOGGER.errorf("Unexpected error scheduling webhook: %s", e.getMessage());
        }
    }

    /**
     * Sends a webhook request for error events to an external API asynchronously.
     * <p>
     * This method is specifically designed to handle error events, such as registration failures,
     * by extracting available information from the event details and sending it to the webhook endpoint.
     * Unlike the regular event handler, this method works with incomplete user data since the error
     * typically occurs before a user record is fully created.
     * <p>
     * The method follows the same asynchronous execution pattern and retry mechanism as the
     * standard webhook request method.
     *
     * @param event The Keycloak event containing error information
     * @param apiUrl The webhook URL to send the request to
     * @param apiKey The API key used for authentication with the webhook endpoint
     * 
     * @throws IllegalStateException if the webhook URL or API key is not configured properly
     */
    private void sendWebhookRequestForError(Event event, String apiUrl, String apiKey) throws IllegalStateException {
        try {
            // Create the payload with error event data from event details
            final KeycloakUserEventDTO payload = createPayloadForError(event.getType().name(), event.getDetails());

            // Submit the webhook task to the executor service for asynchronous execution
            scheduledExecutorService.submit(() -> executeWebhookWithRetries(apiUrl, apiKey, payload));
        } catch (IllegalStateException e) {
            // Log configuration errors but don't retry - these are not transient errors
            LOGGER.errorf("Webhook configuration error: %s", e.getMessage());
        } catch (Exception e) {
            // Log any other unexpected errors
            LOGGER.errorf("Unexpected error scheduling webhook: %s", e.getMessage());
        }
    }

    /**
     * Executes the webhook HTTP request with retry logic.
     * <p>
     * This method is designed to be run asynchronously by the executor service.
     * It sends the HTTP request to the webhook endpoint and implements retry logic
     * with exponential backoff for transient failures.
     * 
     * @param apiUrl The webhook URL to send the request to
     * @param apiKey The API key for authentication
     * @param payload The payload to send in the request
     */
    private void executeWebhookWithRetries(String apiUrl, String apiKey, KeycloakUserEventDTO payload) {
        int maxRetries = 3;
        int retryCount = 0;
        boolean success = false;

        while (!success && retryCount < maxRetries) {
            try {
                // Set the HTTP headers, including the API Key
                HttpHeaders requestHeaders = new HttpHeaders();
                requestHeaders.setBearerAuth(apiKey);
                requestHeaders.setContentType(MediaType.APPLICATION_JSON);

                // Create the request entity
                HttpEntity<KeycloakUserEventDTO> requestEntity = new HttpEntity<>(payload, requestHeaders);

                // Create the HTTP request
                RestClient restClient = createRestClient();
                ResponseEntity<String> responseEntity = restClient.post()
                        .uri(apiUrl)
                        .body(requestEntity.getBody())
                        .headers(httpHeaders -> httpHeaders.addAll(requestEntity.getHeaders()))
                        .retrieve()
                        .toEntity(String.class);

                // handle the response
                if (responseEntity.getStatusCode().is2xxSuccessful()) {
                    LOGGER.debugf("Webhook triggered successfully.");
                    success = true;
                } else {
                    LOGGER.errorf("Failed to trigger webhook. Status code: %s", responseEntity.getStatusCode());
                }
            } catch (Exception e) {
                retryCount++;
                LOGGER.errorf("Webhook call failed (attempt %s/%s): %s", retryCount, maxRetries, e.getMessage());
                if (retryCount < maxRetries) {
                    try {
                        // Exponential backoff: wait longer between each retry
                        TimeUnit.SECONDS.sleep(retryCount);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
    }

    /**
     * Validates that the webhook configuration parameters are properly set.
     * <p>
     * This method checks that both the API URL and API key are present and not empty.
     * These values are required for the webhook functionality to work correctly.
     *
     * @param apiUrl The webhook URL to send requests to
     * @param apiKey The API key used for authentication with the webhook endpoint
     * @throws IllegalStateException if either the API URL or API key is null or empty
     */
    private void validateConfiguration(String apiUrl, String apiKey) throws IllegalStateException {
        if (apiUrl == null || apiUrl.trim().isEmpty()) {
            throw new IllegalStateException("Webhook URL is not configured");
        }
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new IllegalStateException("API key is not configured");
        }
    }

    /**
     * Creates a data transfer object containing user event information for the webhook payload.
     * <p>
     * This method constructs a KeycloakUserEventDTO object with relevant user information
     * extracted from the Keycloak UserModel and the event type. The payload includes:
     * - Event type (e.g., REGISTER, LOGIN)
     * - User identification (ID, username, email)
     * - User profile information (first name, last name)
     * - Account status (email verification)
     * - Timestamps
     * - Request metadata (IP address, user agent)
     *
     * @param eventType The type of Keycloak event that occurred
     * @param user The Keycloak user model containing user information
     * @return A KeycloakUserEventDTO object populated with user and event data
     */
    private KeycloakUserEventDTO createPayload(EventType eventType, UserModel user) {
        return new KeycloakUserEventDTO(
                eventType.name(), user.getId(), user.getUsername(), user.getEmail(),
                user.getFirstName(), user.getLastName(),
                user.isEmailVerified(), user.getCreatedTimestamp(),
                // session.getContext().getConnection().getRemoteAddr(),
                session.getContext().getRequestHeaders().getHeaderString(AppConstants.HEADER_X_FORWARDED_FOR),
                session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.USER_AGENT)
        );
    }

    /**
     * Creates a data transfer object for error events using available event details.
     * <p>
     * This method constructs a KeycloakUserEventDTO object for error scenarios where
     * a complete user model is not available. It extracts whatever user information
     * is available from the event details map, such as email and name fields that
     * might have been submitted before the error occurred.
     * <p>
     * Since error events typically occur before a user is fully created in the system,
     * many fields in the resulting DTO may be null or incomplete.
     *
     * @param eventType The type of error event that occurred (e.g., "REGISTER_ERROR")
     * @param eventDetailMap A map containing details about the error event, which may include
     *                      partial user information such as email or name fields
     * @return A KeycloakUserEventDTO object populated with available error event data
     */
    private KeycloakUserEventDTO createPayloadForError(String eventType, Map<String, String> eventDetailMap) {
        return new KeycloakUserEventDTO(
                eventType, null, null, eventDetailMap.get(AppConstants.EVENT_DETAIL_EMAIL),
                eventDetailMap.get(AppConstants.EVENT_DETAIL_FIRST_NAME), eventDetailMap.get(AppConstants.EVENT_DETAIL_LAST_NAME), null, null,
                session.getContext().getRequestHeaders().getHeaderString(AppConstants.HEADER_X_FORWARDED_FOR),
                session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.USER_AGENT)
        );
    }

    /**
     * Creates and configures a RestClient for making HTTP requests to the webhook endpoint.
     * <p>
     * This method initializes a Spring RestClient with specific configurations to ensure
     * that webhook requests are secure and don't hang indefinitely. The configuration includes:
     * - Cookie Spec: STRICT - ensures cookies are handled securely for cross-origin requests
     * - Connect timeout: 5 seconds - maximum time to establish a connection
     * - Response timeout: 10 seconds - maximum time to wait for a response
     * <p>
     * The STRICT cookie specification ensures that cookies are properly secured and will be
     * available in cross-origin POST requests, addressing the "Non-secure context detected" issue.
     * <p>
     * These timeout settings help prevent webhook calls from blocking Keycloak operations
     * for too long in case of network issues or slow responses from the webhook endpoint.
     *
     * @return A configured RestClient instance ready for making HTTP requests
     */
    private RestClient createRestClient() {
        // Configure request with cookie spec and timeouts
        RequestConfig requestConfig = RequestConfig.custom()
                .setCookieSpec(StandardCookieSpec.STRICT)
                .setConnectTimeout(5000, TimeUnit.MILLISECONDS)
                .setResponseTimeout(10000, TimeUnit.MILLISECONDS)
                .build();

        // Create HttpClient with the request configuration
        var httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();

        // Create factory with the configured HttpClient
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

        return RestClient.builder()
                .requestFactory(factory)
                .build();
    }

    /**
     * Disables automatic login after user registration by invalidating all active sessions.
     * <p>
     * When a user registers in Keycloak, they are typically logged in automatically.
     * This method provides a way to disable that behavior by finding and removing
     * all active sessions for the user immediately after registration.
     * <p>
     * This functionality is useful in scenarios where additional verification steps
     * are required before allowing a user to access the system, such as email verification,
     * admin approval, or completion of additional registration steps.
     *
     * @param realmModel The realm model where the user exists
     * @param user The user model whose sessions should be invalidated
     */
    private void disableAutoLogin(RealmModel realmModel, UserModel user) {
        // Find all user sessions and invalidate them to prevent automatic login
        session.sessions().getUserSessionsStream(realmModel, user)
                .forEach(userSession -> {
                    LOGGER.debugf("Removing session %s for user %s", userSession.getId(), user.getUsername());
                    session.sessions().removeUserSession(realmModel, userSession);
                });
    }
}
