/**
 * @author chintan
 */
package io.binarybrew.keycloak.webhook.data.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object (DTO) for Keycloak user events sent to webhook endpoints.
 * 
 * This class encapsulates all relevant information about a user event that occurred in Keycloak,
 * including the event type, user identification details, profile information, account status,
 * timestamps, and request metadata. It is used to structure the payload for webhook notifications
 * when user-related events (such as registration, login, profile updates, etc.) occur in Keycloak.
 * 
 * The fields are serialized to JSON using the specified property names through @JsonProperty annotations.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeycloakUserEventDTO {

    /**
     * The type of Keycloak event that occurred (e.g., REGISTER, LOGIN, UPDATE_PROFILE).
     * This field is populated from EventType.name() in Keycloak.
     */
    @JsonProperty("type")
    private String type;

    /**
     * The unique identifier of the user in Keycloak.
     * This is the internal ID used by Keycloak to identify the user.
     */
    @JsonProperty("user_id")
    private String userId;

    /**
     * The username of the user in Keycloak.
     * This is the login name used by the user to authenticate.
     */
    @JsonProperty("user_name")
    private String userName;

    /**
     * The email address of the user.
     * This field may be null if the user hasn't provided an email address.
     */
    @JsonProperty("email")
    private String email;

    /**
     * The first name of the user.
     * This field may be null if the user hasn't provided a first name.
     */
    @JsonProperty("first_name")
    private String firstName;

    /**
     * The last name of the user.
     * This field may be null if the user hasn't provided a last name.
     */
    @JsonProperty("last_name")
    private String lastName;

    /**
     * Indicates whether the user's email address has been verified.
     * True if the email has been verified, False otherwise.
     */
    @JsonProperty("email_verified")
    private Boolean emailVerified;

    /**
     * The timestamp when the user account was created in Keycloak.
     * This has been represented as milliseconds since the Unix epoch.
     */
    @JsonProperty("created_timestamp")
    private Long createdTimestamp;

    /**
     * The IP address of the user who triggered the event.
     * This is typically extracted from the X-Forwarded-For header.
     */
    @JsonProperty("user_ip")
    private String userIp;

    /**
     * The user agent string of the browser or client that triggered the event.
     * This provides information about the client software used by the user.
     */
    @JsonProperty("user_agent")
    private String userAgent;

}
