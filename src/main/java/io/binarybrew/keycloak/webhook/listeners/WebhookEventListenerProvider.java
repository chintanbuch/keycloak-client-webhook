/**
 * @author chintan
 */
package io.binarybrew.keycloak.webhook.listeners;

import io.binarybrew.keycloak.webhook.data.dto.KeycloakUserEventDTO;
import lombok.extern.slf4j.Slf4j;
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

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.classic.HttpClients;

/**
 * The WebhookEventListenerProvider is an implementation of the Keycloak
 * EventListenerProvider interface. It listens for certain Keycloak events
 * and executes webhook requests to external APIs based on the event type.
 * <p>
 * This class is designed to handle user-related events, such as registration,
 * password reset, login, logout, email verification, and email updates, and 
 * can notify an external service by sending structured event data using an 
 * HTTP POST request.
 */
@Slf4j
public class WebhookEventListenerProvider implements EventListenerProvider {

    private final KeycloakSession session;
    private final ScheduledExecutorService scheduledExecutorService;

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
     * </ul>
     * <p>
     * When one of these events is detected, the method:
     * <ol>
     * <li>Retrieves the realm associated with the event</li>
     * <li>Sets the realm context for the current session</li>
     * <li>Gets the user ID from event</li>
     * <li>Looks up the complete user information from Keycloak user store</li>
     * <li>If the user exists, triggers a webhook notification by calling sendWebhookRequest()</li>
     * </ol>
     * <p>
     * Events that don't match the specified types or events with missing user information
     * are silently ignored.
     *
     * @param event The Keycloak event containing information about what occurred,
     *              including event type, user ID, and realm ID
     */
    @Override
    public void onEvent(Event event) {
        // Get ClientModel from the session context
        ClientModel clientModel = session.getContext().getClient();

        // Get the Webhook URL and API Key from the client attributes
        // This should be done during setting up the keycloak client (through its Admin API)
        String apiUrl = clientModel.getAttribute("api.url");
        String apiKey = clientModel.getAttribute("api.key");

        // Validate configuration before proceeding
        // validateConfiguration(apiUrl, apiKey);
        if (apiUrl == null || apiUrl.trim().isEmpty() || apiKey == null || apiKey.trim().isEmpty()) {
            return;
        }

        // Handle different events
        if (event.getType() == EventType.REGISTER || event.getType() == EventType.RESET_PASSWORD ||
                event.getType() == EventType.LOGIN || event.getType() == EventType.LOGOUT ||
                event.getType() == EventType.VERIFY_EMAIL || event.getType() == EventType.UPDATE_EMAIL) {

            RealmModel realmModel = session.realms().getRealm(event.getRealmId());
            session.getContext().setRealm(realmModel);

            String userId = event.getUserId();
            UserModel user = session.users().getUserById(realmModel, userId);
            if (user != null) {
                sendWebhookRequest(event, user, apiUrl, apiKey);
            }
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        //
    }

    @Override
    public void close() {
        // Close any resources if needed
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
            scheduledExecutorService.submit(() -> {
                executeWebhookWithRetries(apiUrl, apiKey, payload);
            });
        } catch (IllegalStateException e) {
            // Log configuration errors but don't retry - these are not transient errors
            log.error("Webhook configuration error: {}", e.getMessage());
        } catch (Exception e) {
            // Log any other unexpected errors
            log.error("Unexpected error scheduling webhook: {}", e.getMessage());
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
                    log.debug("Webhook triggered successfully.");
                    success = true;
                } else {
                    log.error("Failed to trigger webhook. Status code: {}", responseEntity.getStatusCode());
                }
            } catch (Exception e) {
                retryCount++;
                log.error("Webhook call failed (attempt {}/{}): {}", retryCount, maxRetries, e.getMessage());
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
                session.getContext().getRequestHeaders().getHeaderString("X-Forwarded-For"),
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
                .setConnectTimeout(5000, java.util.concurrent.TimeUnit.MILLISECONDS)
                .setResponseTimeout(10000, java.util.concurrent.TimeUnit.MILLISECONDS)
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
}
