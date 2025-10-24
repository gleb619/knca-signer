package knca.signer;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.StaticHandler;
import knca.signer.config.ApplicationConfig;
import knca.signer.config.BeanFactory;
import knca.signer.controller.CertificatorHandler;
import knca.signer.controller.VerifierHandler;
import knca.signer.util.Util;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.util.Properties;

import static knca.signer.kalkan.KalkanAdapter.isKalkanAvailable;

@Slf4j
public class App extends AbstractVerticle {

    private final ApplicationConfig config;
    private final BeanFactory beanFactory;
    private HttpServer httpServer;
    private boolean kalkanAvailable;
    private String appVersion = "unknown";
    private String buildTimestamp = "unknown";
    private String buildCommit = "unknown";

    public App(ApplicationConfig config, BeanFactory beanFactory) {
        this.config = config;
        this.beanFactory = beanFactory;
    }

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        ConfigRetriever.create(vertx, new ConfigRetrieverOptions()
                        .addStore(new ConfigStoreOptions()
                                .setType("file")
                                .setFormat("yaml")
                                .setConfig(new JsonObject().put("path", "application.yaml"))))
                .getConfig(ar -> {
                    if (ar.succeeded()) {
                        JsonObject yamlConfigJson = ar.result();
                        ApplicationConfig yamlConfig = yamlConfigJson.mapTo(ApplicationConfig.class)
                                .merge(Util.createApplicationConfigFromEnv());

                        vertx.deployVerticle(new App(yamlConfig, new BeanFactory(vertx, yamlConfig)), d -> {
                            if (d.succeeded()) {
                                log.info("Deployed successfully");
                            } else {
                                log.error("Deploy failed", d.cause());
                                System.exit(1);
                            }
                        });
                    } else {
                        log.error("Config load failed", ar.cause());
                        System.exit(1);
                    }
                });
    }

    @Override
    public void start(Promise<Void> startPromise) {
        try {
            vertx.exceptionHandler(t -> log.error("Uncaught Vert.x exception: {}", t.getMessage(), t));

            loadBuildInfo();
            kalkanAvailable = isKalkanAvailable();
            httpServer = vertx.createHttpServer(new HttpServerOptions()
                    .setPort(config.getHttp().getPort())
                    .setHost(config.getHttp().getHost()));

            Router router = Router.router(vertx);
            setupRoutes(router);
            setupWebSocket();

            httpServer.requestHandler(router).listen(ar -> {
                if (ar.succeeded()) {
                    log.debug("Started bean construction...");
                    beanFactory.init();

                    int port = config.getHttp().getPort();
                    log.info("KNCA Signer Server started on port {}", port);
                    log.info("HTTP: http://localhost:{}", port);
                    log.info("WebSocket: ws://localhost:{}{}", port, config.getWebsocket().getPath());
                    startPromise.complete();
                } else {
                    log.error("Failed to start server", ar.cause());
                    startPromise.fail(ar.cause());
                }
            });
        } catch (Exception e) {
            log.error("Server initialization failed", e);
            startPromise.fail(e);
        }
    }

    private void setupWebSocket() {
        httpServer.webSocketHandler(ws -> {
            try {
                log.debug("WebSocket from: {}", ws.remoteAddress());
                beanFactory.getWebSocketHandler().handle(ws);
            } catch (Exception e) {
                log.error("WebSocket error from {}", ws.remoteAddress(), e);
                try {
                    ws.reject(500);
                } catch (Exception ex) {
                    log.error("Reject failed", ex);
                }
            }
        });
    }

    private void loadBuildInfo() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("build-info.properties")) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                this.appVersion = props.getProperty("version", "unknown");
                this.buildTimestamp = props.getProperty("build.timestamp", "unknown");
                this.buildCommit = props.getProperty("build.commit", "unknown");
                log.info("Loaded build info - version: {}, commit: {}", appVersion, buildCommit);
            } else {
                log.warn("build-info.properties not found in resources");
            }
        } catch (Exception e) {
            log.error("Failed to load build info", e);
        }
    }

    private void setupRoutes(Router router) {
        Handler<RoutingContext> errorWrapper = ctx -> {
            try {
                ctx.next();
            } catch (Exception e) {
                log.error("Route error [{} {}]", ctx.request().method(), ctx.request().path(), e);
                if (!ctx.response().ended()) {
                    ctx.response().setStatusCode(500)
                            .putHeader("content-type", "application/json")
                            .end(new JsonObject()
                                    .put("error", "Internal Server Error")
                                    .put("message", "An unexpected error occurred")
                                    .encode());
                }
            }
        };

        CorsHandler cors = CorsHandler.create(config.getCors().getAllowedOrigins());
        config.getCors().getAllowedMethods().forEach(m -> cors.allowedMethod(HttpMethod.valueOf(m)));
        config.getCors().getAllowedHeaders().forEach(cors::allowedHeader);

        // Add global error wrapper BEFORE handlers to avoid platform handler conflicts
        router.route().handler(cors).handler(errorWrapper);

        router.get("/health").handler(ctx -> {
            log.debug("Health check");
            ctx.response().putHeader("content-type", "application/json")
                    .end(new JsonObject()
                            .put("status", "healthy")
                            .put("service", "KNCA Signer")
                            .put("version", appVersion)
                            .put("buildTimestamp", buildTimestamp)
                            .put("buildCommit", buildCommit)
                            .put("kalkan", kalkanAvailable ? "available" : "not available")
                            .encode());
        });

        CertificatorHandler ch = beanFactory.getCertificateHandler();
        VerifierHandler sh = beanFactory.getSigningHandler();

        router.post("/api/sign").handler(BodyHandler.create()).handler(sh.handleSignData());
        router.post("/api/verify").handler(BodyHandler.create()).handler(sh.handleValidateXml());
        router.get("/api/certificates/ca").handler(ch.handleGetCACertificate());
        router.get("/api/certificates/user").handler(ch.handleGetUserCertificate());
        router.get("/api/certificates/legal").handler(ch.handleGetLegalCertificate());
        router.post("/api/certificates/generate/ca").handler(BodyHandler.create()).handler(ch.handleGenerateCACertificate());
        router.post("/api/certificates/generate/user").handler(BodyHandler.create()).handler(ch.handleGenerateUserCertificate());
        router.post("/api/certificates/generate/legal").handler(BodyHandler.create()).handler(ch.handleGenerateLegalCertificate());
        router.get("/api/certificates/download/:alias/:format").handler(ch.handleDownloadCertificate());

        router.route("/*").handler(StaticHandler.create(config.getStaticConfig().getWebRoot()));
    }

    @Override
    public void stop(Promise<Void> stopPromise) {
        if (httpServer != null) {
            httpServer.close(ar -> {
                if (ar.succeeded()) {
                    log.info("Server stopped");
                    stopPromise.complete();
                } else {
                    log.error("Stop error", ar.cause());
                    stopPromise.fail(ar.cause());
                }
            });
        } else {
            stopPromise.complete();
        }
    }
}
