/**
 * @author chintan
 */
package io.binarybrew.keycloak.webhook.listeners;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Factory for creating WebhookEventListenerProvider instances.
 * 
 * This factory initializes and manages a ScheduledExecutorService that is used
 * for asynchronous execution of webhook requests. The executor service is shared
 * across all provider instances created by this factory.
 */
@Slf4j
public class WebhookEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final int THREAD_POOL = 5;
    public static final String PROVIDER_ID = "brew-event-webhook";

    private ScheduledExecutorService scheduledExecutorService;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new WebhookEventListenerProvider(session, scheduledExecutorService);
    }

    @Override
    public void init(Config.Scope config) {
        // Initialize the executor service with a thread pool
        scheduledExecutorService = Executors.newScheduledThreadPool(THREAD_POOL);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post-initialization logic (e.g., if you need to connect to another service)
    }

    @Override
    public void close() {
        // Shutdown the executor service gracefully
        if (scheduledExecutorService != null && !scheduledExecutorService.isShutdown()) {
            scheduledExecutorService.shutdown();
            try {
                // Wait for existing tasks to terminate
                if (!scheduledExecutorService.awaitTermination(60, TimeUnit.SECONDS)) {
                    // Force shutdown if tasks don't terminate in time
                    scheduledExecutorService.shutdownNow();
                    if (!scheduledExecutorService.awaitTermination(60, TimeUnit.SECONDS)) {
                        log.error("ExecutorService did not terminate");
                    }
                }
            } catch (InterruptedException e) {
                log.error("ExecutorService exception occurred {}", e.getMessage());
                // (Re)Cancel if current thread also interrupted
                scheduledExecutorService.shutdownNow();
                // Preserve interrupt status
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public String getId() {
        // Name of the event listener
        return PROVIDER_ID;
    }
}
