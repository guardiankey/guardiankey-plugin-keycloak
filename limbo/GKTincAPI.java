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

    private String apiUrl = "https://api.guardiankey.io/";
    private String apiKey = "";
    private String protectionGroupHashId = "";
    private int defaultChallengeLevel = 2;
    private String agentId = "gktinc-keycloak-plugin-v1.0.0";
    private boolean useIpReputation = false;
    private boolean failOpen = true;

    public void setConfig(Map<String, String> config) {
        if (config == null) return;
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
        if (config.get("gktinc.failopen") != null)
            this.failOpen = "true".equals(config.get("gktinc.failopen"));
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
            HttpGet get = new HttpGet(url);
            get.setHeader("X-API-Key", apiKey);
            get.setHeader("Content-Type", "application/json");
            HttpResponse response = client.execute(get);
            if (response.getStatusLine().getStatusCode() != 200) return null;
            HttpEntity entity = response.getEntity();
            String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            Gson gson = new GsonBuilder().create();
            return gson.fromJson(json, Map.class);
        } catch (Exception e) {
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
            if (response.getStatusLine().getStatusCode() != 200) return null;
            HttpEntity entity = response.getEntity();
            String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            Gson gson = new GsonBuilder().create();
            return gson.fromJson(json, Map.class);
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> defaultAcceptResult(String description) {
        Map<String, Object> result = new HashMap<String, Object>();
        result.put("action", "ACCEPT");
        result.put("challenge_level", defaultChallengeLevel);
        result.put("sign", "");
        result.put("description", description);
        return result;
    }

    public Map<String, Object> getChallengeLevel(final KeycloakSession session, final String clientIp) {
        if (!useIpReputation) {
            return defaultAcceptResult("IP reputation disabled, using default challenge level " + defaultChallengeLevel);
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

        return result != null ? result : defaultAcceptResult("API error - fail open");
    }

    public Map<String, Object> validateChallenge(final KeycloakSession session, String gktincSolution,
            String username, String clientIp, String url, String once,
            int formPayloadSize, String userAgent, String secChUa,
            String secChUaMobile, String secChUaPlatform, Integer challengeLevel) {

        Map<String, Object> payload = new HashMap<String, Object>();
        payload.put("agent_id", agentId);
        payload.put("gktinc_solution", gktincSolution != null ? gktincSolution : "");
        payload.put("salt", getSalt());
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
        if (challengeLevel != null) payload.put("challenge_level", challengeLevel);

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

        if (result == null) return defaultAcceptResult("Validation error - fail open");
        if (!result.containsKey("action")) return defaultAcceptResult("No action in response - fail open");

        return result;
    }

    public String getJavascriptConfig(Map<String, Object> challengeLevelResult, String clientIp, String url, String once) {
        int level = defaultChallengeLevel;
        String sign = "";

        if (challengeLevelResult != null) {
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
               "  salt: \"" + escapeJs(getSalt()) + "\",\n" +
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
