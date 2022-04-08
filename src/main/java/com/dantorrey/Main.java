package com.dantorrey;

import com.sun.org.apache.xpath.internal.operations.Bool;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.graylog2.gelfclient.GelfConfiguration;
import org.graylog2.gelfclient.GelfMessage;
import org.graylog2.gelfclient.GelfTransports;
import org.graylog2.gelfclient.transport.GelfTransport;
import org.joda.time.DateTime;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class Main {
    private static final Logger LOG = LogManager.getLogger(Main.class);

    private static final String GELF_SAMPLE_HOSTNAME = getEnvironmentValue("GELF_SAMPLE_HOSTNAME", "localhost");
    private static int GELF_SAMPLE_PORT = Integer.parseInt(getEnvironmentValue("GELF_SAMPLE_PORT", "12201"));
    private static int GELF_SAMPLE_MAX_SLEEP_TIME = Integer.parseInt(getEnvironmentValue("GELF_SAMPLE_MAX_SLEEP_TIME", "100"));
    private static boolean GELF_SAMPLE_NO_SLEEP = Boolean.parseBoolean(getEnvironmentValue("GELF_SAMPLE_NO_SLEEP", "false"));

    private static String getEnvironmentValue(String key, String defaultValue) {
        return Optional.ofNullable(System.getenv(key))
                       .orElse(defaultValue);
    }

    public static void main(String[] args) throws InterruptedException {

        LOG.info("Starting up and sending sample data...");
        final GelfConfiguration gelfConfiguration = new GelfConfiguration(GELF_SAMPLE_HOSTNAME, GELF_SAMPLE_PORT)
                .transport(GelfTransports.TCP);

        final GelfTransport gelfTransport = GelfTransports.create(gelfConfiguration);

        // start creating events 25 hours ago
        long secondsAgo = 90000;
        int totalMessages = 0;
        int badLogons = 0;
        while (secondsAgo > 0) {
            String user = pickRandomUser();
            // Three percent of the time throw in a single bad login
            if (randomInRange(0, 100) <= 3) {
                // LOG.info("Sending failed Logon event for user {}", user);
                gelfTransport.send(buildBadLogonMessage(UUID.randomUUID().toString(), secondsAgo, user));
                secondsAgo -= randomInRange(3, 10);
                badLogons++;
            }

            // every 1 in 1000, throw in a brute force attack
            if (randomInRange(0, 1000) <= 1) {
                LOG.info("Sending 20 failed Logon events for user {} at {}", user, Instant.now().minusSeconds(secondsAgo).toString());
                for (int i = 0; i < 20; i++) {
                    gelfTransport.send(buildBadLogonMessage(UUID.randomUUID().toString(), secondsAgo, user));
                }
                badLogons += 20;
            }

            // LOG.info("Sending Logon/Logoff events for user {}", user);
            gelfTransport.send(buildGoodLogonMessage(UUID.randomUUID().toString(), secondsAgo, user));
            secondsAgo -= randomInRange(5,10);
            gelfTransport.send(buildLogoffMessage(UUID.randomUUID().toString(), secondsAgo, user));
            totalMessages += 2;
            secondsAgo -= randomInRange(10, 15);
        }
        LOG.info("Total Messages sent: {}", totalMessages+badLogons);
        LOG.info("Total bad logins: {}", badLogons);
    }

    private static GelfMessage buildGoodLogonMessage(String messageId, long ago, String user) {

        final GelfMessage gelfMessage = new GelfMessage(messageId);
        gelfMessage.setTimestamp(Math.floor(gelfMessage.getTimestamp()-ago));

        gelfMessage.addAdditionalField("winlogbeat_event_created", "2020-09-02T19:21:00.901Z");
        gelfMessage.addAdditionalField("winlogbeat_winlog_opcode", "Info");
        gelfMessage.addAdditionalField("winlogbeat_agent_id", "50d1f93d-a25f-418d-aa49-9db8d4ebace8");
        gelfMessage.addAdditionalField("winlogbeat_ecs_version", "1.5.0");
        gelfMessage.addAdditionalField("winlogbeat_tags", Collections.singletonList("windows"));
        gelfMessage.addAdditionalField("winlogbeat_event_code", 4624);
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_VirtualAccount", "%%1843");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LmPackageName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_ProcessName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_ImpersonationLevel", "%%1840");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_AuthenticationPackageName", "Kerberos");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectDomainName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_ProcessId", "0x0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_activity_id", "{6725DC1F-812D-0001-3ADC-25672D81D601}");
        gelfMessage.addAdditionalField("winlogbeat_event_action", "Logon");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectLogonId", "0x0");
        gelfMessage.addAdditionalField("winlogbeat_@timestamp", "2020-09-02T19:20:59.870Z");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetDomainName", "TESTLAB.INTERNAL");
        gelfMessage.addAdditionalField("winlogbeat_agent_version", "7.9.0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_RestrictedAdminMode", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetUserSid", "S-1-5-21-98903719-2683663973-4168234638-1134");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LogonType", "3");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TransmittedServices", "-");
        gelfMessage.addAdditionalField("winlogbeat_agent_ephemeral_id", "9126b5d2-e9ee-4573-89f5-aa441a38bf01");
        gelfMessage.addAdditionalField("winlogbeat_winlog_version", 2);
        gelfMessage.addAdditionalField("winlogbeat_@metadata_version", "7.9.0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_record_id", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_agent_hostname", "WIN-S7BEGVIPQ2J");
        gelfMessage.addAdditionalField("winlogbeat_log_level", "information");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_type", "_doc");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_ElevatedToken", "%%1842");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_beat", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectUserSid", "S-1-0-0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_IpAddress", "10.222.111.50");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetLinkedLogonId", "0x0");
        gelfMessage.addAdditionalField("winlogbeat_event_provider", "Microsoft-Windows-Security-Auditing");
        gelfMessage.addAdditionalField("beats_type", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetOutboundDomainName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_KeyLength", "0");
        gelfMessage.addAdditionalField("winlogbeat_agent_name", "WIN-S7BEGVIPQ2J");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_id", 4624);
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LogonProcessName", "Kerberos");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectUserName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_task", "Logon");
        gelfMessage.addAdditionalField("winlogbeat_host_name", "WIN-S7BEGVIPQ2J.testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_winlog_channel", "Security");
        gelfMessage.addAdditionalField("winlogbeat_winlog_computer_name", "WIN-S7BEGVIPQ2J.testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_collector_node_id", "WIN-S7BEGVIPQ2J");
        gelfMessage.addAdditionalField("winlogbeat_event_kind", "event");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_WorkstationName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetUserName", user);
        gelfMessage.addAdditionalField("winlogbeat_winlog_process_thread_id", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetLogonId", "0x378dbb");
        gelfMessage.addAdditionalField("winlogbeat_winlog_api", "wineventlog");
        gelfMessage.addAdditionalField("message", "An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nImpersonation Level:\t\tDelegation\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-98903719-2683663973-4168234638-1134\n\tAccount Name:\t\ttestuser20\n\tAccount Domain:\t\tTESTLAB.INTERNAL\n\tLogon ID:\t\t0x378DBB\n\tLinked Logon ID:\t\t0x0\n\tNetwork Account Name:\t-\n\tNetwork Account Domain:\t-\n\tLogon GUID:\t\t{1864DA6C-2A2A-FE4C-8F29-13244F7ACE37}\n\nProcess Information:\n\tProcess ID:\t\t0x0\n\tProcess Name:\t\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t10.222.111.50\n\tSource Port:\t\t50940\n\nDetailed Authentication Information:\n\tLogon Process:\t\tKerberos\n\tAuthentication Package:\tKerberos\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\n\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\n\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\n\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_IpPort", "50940");
        gelfMessage.addAdditionalField("winlogbeat_winlog_provider_guid", "{54849625-5478-4994-A5BA-3E3B0328C30D}");
        gelfMessage.addAdditionalField("winlogbeat_agent_type", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetOutboundUserName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_provider_name", "Microsoft-Windows-Security-Auditing");
        gelfMessage.addAdditionalField("winlogbeat_winlog_process_pid", 588);
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LogonGuid", "{1864DA6C-2A2A-FE4C-8F29-13244F7ACE37}");
        gelfMessage.addAdditionalField("winlogbeat_winlog_keywords", Collections.singletonList("Audit Success"));
        gelfMessage.addAdditionalField("host", "michael-Precision-5540");
        gelfMessage.addAdditionalField("version", "1.1");
        gelfMessage.addAdditionalField("replayed_log", "true");
        gelfMessage.addAdditionalField("gim_test_id", "WINSEC.100001.00");
        gelfMessage.addAdditionalField("failed_windows_logon", 0);

        return gelfMessage;
    }


    private static GelfMessage buildLogoffMessage(String messageId, long ago, String user) {

        final GelfMessage gelfMessage = new GelfMessage(messageId);

        gelfMessage.setTimestamp(Math.floor(gelfMessage.getTimestamp()-ago));

        gelfMessage.addAdditionalField("winlogbeat_event_created", "2020-09-02T19:21:00.901Z");
        gelfMessage.addAdditionalField("winlogbeat_winlog_opcode", "Info");
        gelfMessage.addAdditionalField("winlogbeat_agent_id", "50d1f93d-a25f-418d-aa49-9db8d4ebace8");
        gelfMessage.addAdditionalField("winlogbeat_ecs_version", "1.5.0");
        gelfMessage.addAdditionalField("winlogbeat_tags", Collections.singletonList("windows"));
        gelfMessage.addAdditionalField("winlogbeat_event_code", 4647);
        gelfMessage.addAdditionalField("winlogbeat_winlog_activity_id", "{5c1e1a57-814c-0000-631b-1e5c4c81d601}");
        gelfMessage.addAdditionalField("winlogbeat_event_action", "Logoff");
        gelfMessage.addAdditionalField("winlogbeat_@timestamp", "2020-09-02T21:20:59.870Z");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetDomainName", "TESTLAB");
        gelfMessage.addAdditionalField("winlogbeat_agent_version", "7.9.0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetUserSid", "S-1-5-21-98903719-2683663973-4168234638-1134");
        gelfMessage.addAdditionalField("winlogbeat_agent_ephemeral_id", "9126b5d2-e9ee-4573-89f5-aa441a38bf01");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_version", "7.9.0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_record_id", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_agent_hostname", "WIN-S7BEGVIPQ2J");
        gelfMessage.addAdditionalField("winlogbeat_log_level", "information");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_type", "_doc");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_beat", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_event_provider", "Microsoft-Windows-Security-Auditing");
        gelfMessage.addAdditionalField("beats_type", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_agent_name", "WIN-S7BEGVIPQ2J");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_id", 4647);
        gelfMessage.addAdditionalField("winlogbeat_winlog_task", "Logoff");
        gelfMessage.addAdditionalField("winlogbeat_host_name", "WIN-S7BEGVIPQ2J.testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_winlog_channel", "Security");
        gelfMessage.addAdditionalField("winlogbeat_winlog_computer_name", "WIN-S7BEGVIPQ2J.testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_collector_node_id", "WIN-S7BEGVIPQ2J");
        gelfMessage.addAdditionalField("winlogbeat_event_kind", "event");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetUserName", user);
        gelfMessage.addAdditionalField("winlogbeat_winlog_process_thread_id", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetLogonId", "0x3b82f4");
        gelfMessage.addAdditionalField("winlogbeat_winlog_api", "wineventlog");
        gelfMessage.addAdditionalField("message", "User initiated logoff:\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-98903719-2683663973-4168234638-1134\n\tAccount Name:\t\ttestuser20\n\tAccount Domain:\t\tTESTLAB\n\tLogon ID:\t\t0x3B82F4\n\nThis event is generated when a logoff is initiated. No further user-initiated activity can occur. This event can be interpreted as a logoff event.");
        gelfMessage.addAdditionalField("winlogbeat_winlog_provider_guid", "{54849625-5478-4994-A5BA-3E3B0328C30D}");
        gelfMessage.addAdditionalField("winlogbeat_agent_type", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetOutboundUserName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_provider_name", "Microsoft-Windows-Security-Auditing");
        gelfMessage.addAdditionalField("winlogbeat_winlog_process_pid", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LogonGuid", "{1864DA6C-2A2A-FE4C-8F29-13244F7ACE37}");
        gelfMessage.addAdditionalField("winlogbeat_winlog_keywords", Collections.singletonList("Audit Success"));
        gelfMessage.addAdditionalField("host", "michael-Precision-5540");
        gelfMessage.addAdditionalField("replayed_log", "true");
        gelfMessage.addAdditionalField("gim_test_id", "WINSEC.100001.00");
        gelfMessage.addAdditionalField("failed_windows_logon", 0);

        return gelfMessage;
    }

    private static GelfMessage buildBadLogonMessage(String messageId, long ago, String user) {

        final GelfMessage gelfMessage = new GelfMessage(messageId);

        gelfMessage.setTimestamp(Math.floor(gelfMessage.getTimestamp()-ago));

        gelfMessage.addAdditionalField("winlogbeat_event_created", "2020-09-02T19:22:10.222Z");
        gelfMessage.addAdditionalField("winlogbeat_agent_id", "50d1f93d-a25f-418d-aa49-9db8d4ebace8");
        gelfMessage.addAdditionalField("winlogbeat_winlog_opcode", "Info");
        gelfMessage.addAdditionalField("winlogbeat_ecs_version", "1.5.0");
        gelfMessage.addAdditionalField("winlogbeat_tags", Collections.singletonList("windows"));
        gelfMessage.addAdditionalField("winlogbeat_event_code", 4625);
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LmPackageName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_ProcessName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_AuthenticationPackageName", "NTLM");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectDomainName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_ProcessId", "0x0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_FailureReason", "%%2313");
        gelfMessage.addAdditionalField("winlogbeat_winlog_activity_id", "{5c1e1a57-814c-0000-631b-1e5c4c81d601}");
        gelfMessage.addAdditionalField("winlogbeat_event_action", "Logon");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectLogonId", "0x0");
        gelfMessage.addAdditionalField("winlogbeat_@timestamp", "2020-09-02T19:21:38.082Z");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetDomainName", "testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_agent_version", "7.9.0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetUserSid", "S-1-0-0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TransmittedServices", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LogonType", "3");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubStatus", "0xc000006e");
        gelfMessage.addAdditionalField("winlogbeat_agent_ephemeral_id", "9126b5d2-e9ee-4573-89f5-aa441a38bf01");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_version", "7.9.0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_record_id", randomInRange(1000, 999999));
        gelfMessage.addAdditionalField("winlogbeat_agent_hostname", "hacking-laptop");
        gelfMessage.addAdditionalField("winlogbeat_log_level", "information");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_type", "_doc");
        gelfMessage.addAdditionalField("winlogbeat_@metadata_beat", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectUserSid", "S-1-0-0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_IpAddress", "10.222.111.1");
        gelfMessage.addAdditionalField("winlogbeat_event_provider", "Microsoft-Windows-Security-Auditing");
        gelfMessage.addAdditionalField("beats_type", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_KeyLength", "0");
        gelfMessage.addAdditionalField("winlogbeat_agent_name", "hacking-laptop");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_id", 4625);
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_Status", "0xc000006e");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_LogonProcessName", "NtLmSsp");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_SubjectUserName", "-");
        gelfMessage.addAdditionalField("winlogbeat_winlog_task", "Logon");
        gelfMessage.addAdditionalField("winlogbeat_host_name", "DESKTOP-HMVU4PF.testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_winlog_channel", "Security");
        gelfMessage.addAdditionalField("winlogbeat_winlog_computer_name", "DESKTOP-HMVU4PF.testlab.internal");
        gelfMessage.addAdditionalField("winlogbeat_collector_node_id", "hacking-laptop");
        gelfMessage.addAdditionalField("winlogbeat_event_kind", "event");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_WorkstationName", "hacking-laptop");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_TargetUserName", user);
        gelfMessage.addAdditionalField("winlogbeat_winlog_process_thread_id", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_winlog_api", "wineventlog");
        gelfMessage.addAdditionalField("message", "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tbadguy\n\tAccount Domain:\t\ttestlab.internal\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006E\n\tSub Status:\t\t0xC000006E\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\thacking-laptop\n\tSource Network Address:\t10.222.111.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.");
        gelfMessage.addAdditionalField("winlogbeat_winlog_event_data_IpPort", "0");
        gelfMessage.addAdditionalField("winlogbeat_winlog_provider_guid", "{54849625-5478-4994-a5ba-3e3b0328c30d}");
        gelfMessage.addAdditionalField("winlogbeat_agent_type", "winlogbeat");
        gelfMessage.addAdditionalField("winlogbeat_winlog_provider_name", "Microsoft-Windows-Security-Auditing");
        gelfMessage.addAdditionalField("winlogbeat_winlog_process_pid", randomInRange(500, 999999));
        gelfMessage.addAdditionalField("winlogbeat_winlog_keywords", Collections.singletonList("Audit Failure"));
        gelfMessage.addAdditionalField("host", "hacking-laptop");
        gelfMessage.addAdditionalField("replayed_log", "true");
        gelfMessage.addAdditionalField("gim_test_id", "WINSEC.100001.00");
        gelfMessage.addAdditionalField("failed_windows_logon", 1);

        return gelfMessage;
    }

    private static String pickRandomUser() {
        return pickRandom("testuser20", "zking", "badguy", "graylog_user1", "another_user", "user2", "admin", "reader");
    }

    private static int randomInRange(int min, int max) {
        Random random = new Random();
        return random.nextInt((max - min) + 1) + min;
    }

    private static String pickRandom(String... strings) {
        Random random = new Random();
        int index = random.nextInt(strings.length);
        return strings[index];
    }

}
