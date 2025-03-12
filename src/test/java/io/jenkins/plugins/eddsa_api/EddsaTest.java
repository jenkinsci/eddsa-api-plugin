package io.jenkins.plugins.eddsa_api;

import static org.junit.Assert.assertTrue;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.model.Descriptor;
import hudson.model.Node;
import hudson.model.Slave;
import hudson.plugins.sshslaves.SSHLauncher;
import hudson.plugins.sshslaves.verifiers.NonVerifyingKeyVerificationStrategy;
import hudson.slaves.DumbSlave;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;

public class EddsaTest implements Serializable {
    public static final String SSH_AGENT_NAME = "ssh-agent-ed25519";
    public static final String SSH_KEY_PATH = "ssh/ed25519key";
    public static final String SSH_KEY_PUB_PATH = "ssh/ed25519key.pub";
    public static final String SSH_AUTHORIZED_KEYS = "ssh/authorized_keys";
    public static final String AGENTS_RESOURCES_PATH = "/io/jenkins/plugins/eddsa_api/";
    public static final String SSH_SSHD_CONFIG = "ssh/sshd_config";
    public static final String DOCKERFILE = "Dockerfile";
    public static final int SSH_PORT = 22;
    public static final String AGENT_WORK_DIR = "/home/jenkins";
    public static final String USER = "jenkins";

    @Rule
    public transient GenericContainer agentContainer = new GenericContainer(new ImageFromDockerfile(
                            SSH_AGENT_NAME, false)
                    .withFileFromClasspath(
                            SSH_AUTHORIZED_KEYS,
                            AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_AUTHORIZED_KEYS)
                    .withFileFromClasspath(
                            SSH_KEY_PATH, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_KEY_PATH)
                    .withFileFromClasspath(
                            SSH_KEY_PUB_PATH, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_KEY_PUB_PATH)
                    .withFileFromClasspath(
                            SSH_SSHD_CONFIG, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_SSHD_CONFIG)
                    .withFileFromClasspath(DOCKERFILE, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + DOCKERFILE))
            .withExposedPorts(22);

    @Rule(order = 10)
    public transient RealJenkinsRule j =
            new RealJenkinsRule().withDebugPort(8000).withDebugServer(true).withDebugSuspend(true);

    @Test
    public void connectionTests() throws Throwable {
        String host = agentContainer.getHost();
        int port = agentContainer.getMappedPort(SSH_PORT);
        String keyPath = SSH_AGENT_NAME + "/" + SSH_KEY_PATH;
        j.then(r -> {
            Node node = createPermanentAgent(r, SSH_AGENT_NAME, host, port, keyPath, "");
            waitForAgentConnected(r, node);
            assertTrue(isSuccessfullyConnected(node));
        });
    }

    private Node createPermanentAgent(
            JenkinsRule r, String name, String host, int sshPort, String keyResourcePath, String passphrase)
            throws Descriptor.FormException, IOException {
        String credId = "sshCredentialsId";
        createSshKeyCredentials(credId, keyResourcePath, passphrase);
        final SSHLauncher launcher = new SSHLauncher(host, sshPort, credId);
        launcher.setSshHostKeyVerificationStrategy(new NonVerifyingKeyVerificationStrategy());
        DumbSlave agent = new DumbSlave(name, AGENT_WORK_DIR, launcher);
        r.jenkins.addNode(agent);
        return r.jenkins.getNode(agent.getNodeName());
    }

    private void createSshKeyCredentials(String id, String keyResourcePath, String passphrase) throws IOException {
        String privateKey = IOUtils.toString(getClass().getResourceAsStream(keyResourcePath), StandardCharsets.UTF_8);
        BasicSSHUserPrivateKey.DirectEntryPrivateKeySource privateKeySource =
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(privateKey);
        BasicSSHUserPrivateKey credentials = new BasicSSHUserPrivateKey(
                CredentialsScope.SYSTEM, id, USER, privateKeySource, passphrase, "Private Key ssh credentials");
        SystemCredentialsProvider.getInstance()
                .getDomainCredentialsMap()
                .put(Domain.global(), Collections.singletonList(credentials));
    }

    private void waitForAgentConnected(JenkinsRule r, Node node) throws InterruptedException {
        try {
            r.waitOnline((Slave) node);
        } catch (InterruptedException | RuntimeException x) {
            throw x;
        } catch (Exception x) {
            throw new RuntimeException(x);
        }
    }

    private boolean isSuccessfullyConnected(Node node) throws IOException, InterruptedException {
        int count = 0;
        while (count < 30) {
            Thread.sleep(1000);
            String log = node.toComputer().getLog();
            if (log.contains("Agent successfully connected and online")) {
                return true;
            }
        }
        return false;
    }
}
