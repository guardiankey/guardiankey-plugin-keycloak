package io.guardiankey.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class GKTincAPI {


    private boolean enableGKTinc = true;
    private boolean verbose = false;
    private String apiUrl = "https://api.guardiankey.io/";
    private String apiKey = "";
    private String protectionGroupHashId = "";
    private int defaultChallengeLevel = 2;
    private String agentId = "gktinc-keycloak-plugin-v1.0.0";
    private boolean useIpReputation = false;

    public void setConfig(Map<String, String> config) {
        if (config == null) return;
        if (config.get("gktinc.enablegktinc") != null)
            this.enableGKTinc = "true".equals(config.get("gktinc.enablegktinc"));
        if (config.get("gktinc.verbose") != null)
            this.verbose = "true".equals(config.get("gktinc.verbose"));
        if (config.get("gktinc.apiurl") != null && !config.get("gktinc.apiurl").isEmpty())
            this.apiUrl = config.get("gktinc.apiurl").replaceAll("/$", "") + "/";
        if (config.get("gktinc.apikey") != null)
            this.apiKey = config.get("gktinc.apikey");
        if (config.get("gktinc.protectiongrouphashid") != null)
            this.protectionGroupHashId = config.get("gktinc.protectiongrouphashid");
        if (config.get("gktinc.agentid") != null && !config.get("gktinc.agentid").isEmpty())
            this.agentId = config.get("gktinc.agentid");
        if (config.get("gktinc.useipreputation") != null)
            this.useIpReputation = "true".equals(config.get("gktinc.useipreputation"));

        if (enableGKTinc) {
            if (verbose) System.out.println("GKTincAPI configuration:");
            if (verbose) System.out.println("  API URL: " + apiUrl);
            if (verbose) System.out.println("  Protection Group Hash ID: " + protectionGroupHashId);
            if (verbose) System.out.println("  Agent ID: " + agentId);
            if (verbose) System.out.println("  Use IP Reputation: " + useIpReputation);
        } else {
            if (verbose) System.out.println("GKTincAPI is disabled by configuration. This class should not be used.");
        }
    }

    public String getSalt() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest((apiKey + protectionGroupHashId).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> doGet(CloseableHttpClient client, String url) {
        try {
            if (verbose) System.out.println("GKTincAPI GET " + url);
            HttpGet get = new HttpGet(url);
            get.setHeader("X-API-Key", apiKey);
            get.setHeader("Content-Type", "application/json");
            HttpResponse response = client.execute(get);
            if (response.getStatusLine().getStatusCode() != 200) {
                if (verbose) System.out.println("GKTincAPI GET error: " + response.getStatusLine().toString());
                return null;
            }
            HttpEntity entity = response.getEntity();
            String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            if (verbose) System.out.println("GKTincAPI GET response: " + json);
            Gson gson = new GsonBuilder().create();
            return gson.fromJson(json, Map.class);
        } catch (Exception e) {
            if (verbose) e.printStackTrace();
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> doPost(CloseableHttpClient client, String url, String body) {
        try {
            HttpPost post = new HttpPost(url);
            post.setHeader("X-API-Key", apiKey);
            post.setHeader("Content-Type", "application/json");
            post.setEntity(new StringEntity(body, StandardCharsets.UTF_8));
            HttpResponse response = client.execute(post);
            if (response.getStatusLine().getStatusCode() != 200) {
                if (verbose) System.out.println("GKTincAPI POST error: " + response.getStatusLine().toString());
                return null;
            }
            HttpEntity entity = response.getEntity();
            String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            if (verbose) System.out.println("GKTincAPI POST response: " + json);
            Gson gson = new GsonBuilder().create();
            return gson.fromJson(json, Map.class);
        } catch (Exception e) {
            if (verbose) e.printStackTrace();
            return null;
        }
    }

    private Map<String, Object> defaultAcceptResult(String description, String clientIp) {
        if (verbose) System.out.println("GKTincAPI defaultAcceptResult: " + description + " (client_ip: " + clientIp + ")");
        Map<String, Object> result = new HashMap<String, Object>();
        result.put("action", "ACCEPT");
        result.put("challenge_level", defaultChallengeLevel);
        result.put("sign", "");
        result.put("description", description);
        result.put("client_ip", clientIp);
        result.put("city", "-");
        result.put("country", "-");
        result.put("region", "-");
        result.put("country_code", "-");
        result.put("time_zone", "-");
        result.put("longitude", "0.000000");
        result.put("latitude", "0.000000");
        result.put("asn", "");
        result.put("ip_policy", "not_listed");
        return result;
    }

    public Map<String, Object> getChallengeLevel(final KeycloakSession session, final String clientIp) {
        if (!useIpReputation) {
            return defaultAcceptResult("IP reputation disabled, using default challenge level " + defaultChallengeLevel, clientIp);
        }

        final String url = apiUrl + "v3/tinc/" + protectionGroupHashId + "/get_challenge_level/" + clientIp;
        final HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
        final CloseableHttpClient client = provider.getHttpClient();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Map<String, Object>> future = executor.submit(new Callable<Map<String, Object>>() {
            @Override
            public Map<String, Object> call() {
                return doGet(client, url);
            }
        });
        executor.shutdown();

        Map<String, Object> result = null;
        try {
            result = future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) { }
        if (!executor.isTerminated()) executor.shutdownNow();

        return result != null ? result : defaultAcceptResult("API error - fail open", clientIp);
    }



    public Map<String, Object> validateChallenge(final KeycloakSession session, String gktincSolution,
            String username, String clientIp, String url, String once,
            int formPayloadSize, String userAgent, String secChUa,
            String secChUaMobile, String secChUaPlatform, Integer challengeLevel,String salt) {

        if (verbose) {
            System.out.println("GKTincAPI validateChallenge called with:");
            System.out.println("  gktincSolution: " + gktincSolution);
            System.out.println("  username: " + username);
            System.out.println("  clientIp: " + clientIp);
            System.out.println("  url: " + url);
            System.out.println("  once: " + once);
            System.out.println("  formPayloadSize: " + formPayloadSize);
            System.out.println("  userAgent: " + userAgent);
            System.out.println("  secChUa: " + secChUa);
            System.out.println("  secChUaMobile: " + secChUaMobile);
            System.out.println("  secChUaPlatform: " + secChUaPlatform);
            System.out.println("  challengeLevel: " + challengeLevel);
            System.out.println("  salt: " + salt);
        }
        Map<String, Object> payload = new HashMap<String, Object>();
        payload.put("agent_id", agentId);
        payload.put("gktinc_solution", gktincSolution != null ? gktincSolution : "");
        payload.put("salt", salt != null ? salt : getSalt());
        payload.put("client_ip", clientIp != null ? clientIp : "");
        payload.put("url", url != null ? url : "");
        payload.put("once", once != null ? once : "");
        payload.put("form_payload_size", formPayloadSize);
        payload.put("form_input_element_value", username != null ? username : "");
        payload.put("time", System.currentTimeMillis() / 1000);
        payload.put("user_agent", userAgent != null ? userAgent : "");
        payload.put("sec_ch_ua", secChUa != null ? secChUa : "");
        payload.put("sec_ch_ua_mobile", secChUaMobile != null ? secChUaMobile : "");
        payload.put("sec_ch_ua_platform", secChUaPlatform != null ? secChUaPlatform : "");
        if (challengeLevel != null && challengeLevel >= 0 ) payload.put("challenge_level", challengeLevel);

        Gson gson = new GsonBuilder().create();
        final String body = gson.toJson(payload);
        final String endpoint = apiUrl + "v3/tinc/" + protectionGroupHashId + "/validate_challenge";

        final HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
        final CloseableHttpClient client = provider.getHttpClient();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Map<String, Object>> future = executor.submit(new Callable<Map<String, Object>>() {
            @Override
            public Map<String, Object> call() {
                return doPost(client, endpoint, body);
            }
        });
        executor.shutdown();

        Map<String, Object> result = null;
        try {
            result = future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) { }
        if (!executor.isTerminated()) executor.shutdownNow();

        if (result == null) return defaultAcceptResult("Validation error - fail open", clientIp);
        if (!result.containsKey("action")) return defaultAcceptResult("No action in response - fail open", clientIp);

        return result;
    }

    public String getJavascriptConfig(Map<String, Object> challengeLevelResult, boolean preCheck, boolean preEnforceBlock, String clientIp, String url, String salt, String once) {
        int level = defaultChallengeLevel;
        String sign = "";
        if (salt == null) salt = getSalt();
        if (verbose) {
            System.out.println("GKTincAPI getJavascriptConfig called with:");
            System.out.println("  preCheck: " + preCheck);
            System.out.println("  preEnforceBlock: " + preEnforceBlock);
            System.out.println("  clientIp: " + clientIp);
            System.out.println("  url: " + url);
            System.out.println("  salt: " + salt);
            System.out.println("  once: " + once);
        }

        if (preCheck && challengeLevelResult != null) {
            if (preEnforceBlock && "BLOCK".equals(challengeLevelResult.get("action"))) {
                return "// Your origin is blocked by GKTinc policy.\nvar gktinc_blocked = true;";
            }
            Object cl = challengeLevelResult.get("challenge_level");
            if (cl instanceof Number) level = ((Number) cl).intValue();
            Object s = challengeLevelResult.get("sign");
            if (s != null) sign = s.toString();
        }

        long time = System.currentTimeMillis() / 1000;

        return "var gktinc_config = {\n" +
               "  client_ip: \"" + escapeJs(clientIp) + "\",\n" +
               "  url: \"" + escapeJs(url) + "\",\n" +
               "  challenge_level: " + level + ",\n" +
               "  salt: \"" + escapeJs(salt) + "\",\n" +
               "  once: \"" + escapeJs(once) + "\",\n" +
               "  time: \"" + time + "\",\n" +
               "  sign: \"" + escapeJs(sign) + "\"\n" +
               "};";
    }

    private String escapeJs(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r");
    }
}
