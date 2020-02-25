package com.dantorrey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.graylog2.gelfclient.GelfConfiguration;
import org.graylog2.gelfclient.GelfMessage;
import org.graylog2.gelfclient.GelfTransports;
import org.graylog2.gelfclient.transport.GelfTransport;
import org.joda.time.DateTime;

import java.io.IOException;
import java.time.Instant;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class Main {
    private static final Logger LOG = LogManager.getLogger(Main.class);

    public static void main(String[] args) throws InterruptedException {

        LOG.info("Starting up and sending sample data...");
        final GelfConfiguration gelfConfiguration = new GelfConfiguration("localhost", 12201)
                .transport(GelfTransports.TCP);

        final GelfTransport gelfTransport = GelfTransports.create(gelfConfiguration);

        //noinspection InfiniteLoopStatement
        while (true) {
            final String messageId = UUID.randomUUID().toString();
            LOG.debug("Sending message [" + messageId + "]");
            gelfTransport.send(buildMessage(messageId));

            // Add some randomness to the sleep over time.
            // Add a fixed additional time within 10 minute span to get a more random message distribution over time.
            TimeUnit.MILLISECONDS.sleep(calculateDelay()); // Multiply by 10 to amplify the deviation.
        }
    }

    /**
     * Calculates a delay that varies more or less as time progresses throughout the hour.
     */
    private static int calculateDelay() {
        return randomInRange(1, 100) + (DateTime.now().getMinuteOfHour() % 10) * 10;
    }

    private static GelfMessage buildMessage(String messageId) {

        final GelfMessage gelfMessage = new GelfMessage(messageId);
        int responseStatus = randomStatus();
        String method = getRandomMethod();

        gelfMessage.setTimestamp(Instant.now().getEpochSecond());

        // Building JSON with string concatenation is not fun, but it's
        gelfMessage.addAdditionalField("CacheCacheStatus", pickRandom("hit", "unknown", "unknown", "unknown"));
        gelfMessage.addAdditionalField("CacheResponseBytes", randomInRange(50, 1024));
        gelfMessage.addAdditionalField("CacheResponseStatus", responseStatus);
        gelfMessage.addAdditionalField("CacheTieredFill", false);
        gelfMessage.addAdditionalField("ClientASN", 7922);
        gelfMessage.addAdditionalField("ClientCountry", "us");
        gelfMessage.addAdditionalField("ClientDeviceType", pickRandom("desktop", "mobile"));
        gelfMessage.addAdditionalField("ClientIP", randomIp());
        gelfMessage.addAdditionalField("ClientIPClass", "noRecord");
        gelfMessage.addAdditionalField("ClientRequestBytes", randomInRange(50, 1024));
        gelfMessage.addAdditionalField("ClientRequestHost", "graylog.com:8080");
        gelfMessage.addAdditionalField("ClientRequestMethod", method);
        gelfMessage.addAdditionalField("ClientRequestPath", "/search");
        gelfMessage.addAdditionalField("ClientRequestProtocol", pickRandom("HTTP/1.1", "HTTP/2.0"));
        gelfMessage.addAdditionalField("ClientRequestReferer", pickRandom("graylog.com", "graylog.org", "torch.sh"));
        gelfMessage.addAdditionalField("ClientRequestURI", "/search");
        gelfMessage.addAdditionalField("ClientRequestUserAgent", randomAgent());
        gelfMessage.addAdditionalField("ClientSSLCipher", "NONE");
        gelfMessage.addAdditionalField("ClientSSLProtocol", "none");
        gelfMessage.addAdditionalField("ClientSrcPort", 52039);
        gelfMessage.addAdditionalField("EdgeColoCode", "DFW");
        gelfMessage.addAdditionalField("EdgeColoID", 15);
        gelfMessage.addAdditionalField("EdgeEndTimestamp", Instant.now().getEpochSecond());
        gelfMessage.addAdditionalField("EdgePathingOp", " " + pickRandom("wl", "ban", "chl") + " ");
        gelfMessage.addAdditionalField("EdgePathingSrc", " " + pickRandom("c", "hot", "macro", "user", "filterBasedFirewall") + " ");
        gelfMessage.addAdditionalField("EdgePathingStatus", " " + pickRandom("nr", "unknown", "ip", "ctry", "ipr16", "ipr24", "captchaErr", "captchaFail", "captchaNew", "jschlFail", "jschlNew", "jschlErr", "captchaNew", "captchaSucc") + " ");
        gelfMessage.addAdditionalField("EdgeRateLimitAction", "");
        gelfMessage.addAdditionalField("EdgeRateLimitID", 0);
        gelfMessage.addAdditionalField("EdgeRequestHost", "test.com:80");
        gelfMessage.addAdditionalField("EdgeResponseBytes", randomInRange(50, 1024));
        gelfMessage.addAdditionalField("EdgeResponseCompressionRatio", 2.48);
        gelfMessage.addAdditionalField("EdgeResponseContentType", "text/html");
        gelfMessage.addAdditionalField("EdgeResponseStatus", responseStatus);
        gelfMessage.addAdditionalField("EdgeServerIP", randomIp());
        gelfMessage.addAdditionalField("EdgeStartTimestamp", Instant.now().getEpochSecond());
        gelfMessage.addAdditionalField("OriginIP", randomIp());
        gelfMessage.addAdditionalField("OriginResponseBytes", randomInRange(50, 1024));
        gelfMessage.addAdditionalField("OriginResponseHTTPExpires", "");
        gelfMessage.addAdditionalField("OriginResponseHTTPLastModified", "");
        gelfMessage.addAdditionalField("OriginResponseStatus", responseStatus);
        gelfMessage.addAdditionalField("OriginSSLProtocol", "unknown");
        gelfMessage.addAdditionalField("ParentRayID", "00");
        gelfMessage.addAdditionalField("RayID", "8709870987");
        gelfMessage.addAdditionalField("SecurityLevel", "med");
        gelfMessage.addAdditionalField("WAFAction", "unknown");
        gelfMessage.addAdditionalField("WAFFlags", "0");
        gelfMessage.addAdditionalField("WAFMatchedVar", "");
        gelfMessage.addAdditionalField("WAFProfile", "unknown");
        gelfMessage.addAdditionalField("WAFRuleID", "");
        gelfMessage.addAdditionalField("WAFRuleMessage", "");
        gelfMessage.addAdditionalField("WorkerCPUTime", 0);
        gelfMessage.addAdditionalField("WorkerStatus", "unknown");
        gelfMessage.addAdditionalField("WorkerSubrequest", false);
        gelfMessage.addAdditionalField("WorkerSubrequestCount", 0);

        return gelfMessage;
    }

    private static Integer randomStatus() {
        return pickRandom(200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
                          200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
                          200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
                          200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
                          200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
                          200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 300, 301, 302,
                          304, 307, 400, 401, 403, 404, 410, 500, 501, 503, 550);
    }

    private static String getRandomMethod() {
        return pickRandom("GET", "GET", "GET", "GET", "GET", "POST", "DELETE", "PUT");
    }

    private static String pickRandom(String... strings) {
        Random random = new Random();
        int index = random.nextInt(strings.length);
        return strings[index];
    }

    private static Integer pickRandom(Integer... integers) {
        Random random = new Random();
        int index = random.nextInt(integers.length);
        return integers[index];
    }

    private static int randomInRange(int min, int max) {
        Random random = new Random();
        return random.nextInt((max - min) + 1) + min;
    }

    private static String randomIp() {
        return randomInRange(10, 254) + "." + randomInRange(10, 254) + "." + randomInRange(10, 254) + "." + randomInRange(10, 254);
    }

    private static String randomAgent() {

        return pickRandom("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
                          "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
                          "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
                          "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                          "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)",
                          "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)",
                          "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
                          "Mozilla/5.0 (iPad; CPU OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1",
                          "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1",
                          "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/603.1.23 (KHTML, like Gecko) Version/10.0 Mobile/14E5239e Safari/602.1When the Request Desktop Site feature is enabled, the Desktop Safari UA is sent:",
                          "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1",
                          "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1",
                          "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1",
                          "Mozilla/5.0 (Linux; <Android Version>; <Build Tag etc.>) AppleWebKit/<WebKit Rev> (KHTML, like Gecko) Chrome/<Chrome Rev> Mobile Safari/<WebKit Rev>",
                          "Mozilla/5.0 (Linux; <Android Version>; <Build Tag etc.>) AppleWebKit/<WebKit Rev>(KHTML, like Gecko) Chrome/<Chrome Rev> Safari/<WebKit Rev>",
                          "Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19",
                          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
                          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.1 Safari/605.1.15",
                          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15",
                          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15",
                          "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-en) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0");
    }
}
