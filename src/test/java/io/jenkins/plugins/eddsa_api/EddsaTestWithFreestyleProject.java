package io.jenkins.plugins.eddsa_api;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertTrue;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.model.*;
import hudson.plugins.sshslaves.SSHLauncher;
import hudson.plugins.sshslaves.verifiers.NonVerifyingKeyVerificationStrategy;
import hudson.slaves.DumbSlave;
import hudson.slaves.OfflineCause;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.shaded.org.awaitility.Awaitility;

public class EddsaTestWithFreestyleProject implements Serializable {
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
            Iterator<CredentialsStore> stores =
                    CredentialsProvider.lookupStores(r.jenkins).iterator();
            assertTrue(stores.hasNext());
            CredentialsStore store = stores.next();
            String privateKey = IOUtils.toString(getClass().getResourceAsStream(keyPath), StandardCharsets.UTF_8);
            BasicSSHUserPrivateKey basicSSHUserPrivateKey = new BasicSSHUserPrivateKey(
                    CredentialsScope.SYSTEM,
                    "sshCredentialsId",
                    USER,
                    new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(privateKey),
                    "",
                    null);

            store.addCredentials(Domain.global(), basicSSHUserPrivateKey);

            final SSHLauncher launcher = new SSHLauncher(host, port, "sshCredentialsId");
            launcher.setSshHostKeyVerificationStrategy(new NonVerifyingKeyVerificationStrategy());
            DumbSlave agent = new DumbSlave(SSH_AGENT_NAME, AGENT_WORK_DIR, launcher);
            r.jenkins.addNode(agent);

            Computer computer = agent.toComputer();
            try {
                computer.connect(false).get();
            } catch (ExecutionException x) {
                throw new AssertionError("failed to connect: " + computer.getLog(), x);
            }

            assertThat(computer.getLog(), containsString("Agent successfully connected and online"));

            FreeStyleProject p = r.jenkins.createProject(FreeStyleProject.class, "p");
            p.setAssignedNode(agent);

            try {
                computer.disconnect(OfflineCause.create(null)).get();
            } catch (ExecutionException x) {
                throw new AssertionError("failed to disconnect: " + computer.getLog(), x);
            }

            // Wait for the real disconnections
            Awaitility.await().atMost(Duration.ofSeconds(15)).until(() -> computer.getLog()
                    .contains("Connection terminated"));

            try {
                computer.connect(true).get();
            } catch (ExecutionException x) {
                throw new AssertionError("failed to connect: " + computer.getLog(), x);
            }

            assertThat(computer.getLog(), containsString("Agent successfully connected and online"));
            r.buildAndAssertSuccess(p);
        });
    }
}
