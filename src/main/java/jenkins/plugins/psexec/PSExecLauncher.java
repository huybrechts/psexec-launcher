/*
 * The MIT License
 * 
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi, Stephen Connolly
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package jenkins.plugins.psexec;

import hudson.EnvVars;
import hudson.Util;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.slaves.ComputerLauncher;
import hudson.slaves.Messages;
import hudson.slaves.SlaveComputer;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;
import jenkins.model.Jenkins;
import hudson.model.TaskListener;
import hudson.util.StreamCopyThread;
import hudson.util.ProcessTree;

import java.io.IOException;
import java.net.URL;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.json.JSONObject;
import org.jinterop.dcom.common.JIDefaultAuthInfoImpl;
import org.jinterop.dcom.core.JISession;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import static hudson.Util.copyStreamAndClose;
import static hudson.Util.nullify;

/**
 * {@link ComputerLauncher} through a remote login mechanism like ssh/rsh.
 *
 * @author Stephen Connolly
 * @author Kohsuke Kawaguchi
*/
public class PSExecLauncher extends ComputerLauncher {

    private final String userName;
    private final String password;
    private final String hostName;
    private final boolean runInteractive;
    private final boolean runAsSystem;
    private final String javaHome;


    @DataBoundConstructor
    public PSExecLauncher(String userName, String password, String hostName, boolean runInteractive, boolean runAsSystem, String javaHome) {
        this.userName = userName;
        this.password = password;
        this.runInteractive = runInteractive;
        this.runAsSystem = runAsSystem;
        this.javaHome = Util.fixEmptyAndTrim(javaHome);
        this.hostName = Util.fixEmptyAndTrim(hostName);
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public String getHostName() {
        return hostName;
    }

    public boolean isRunInteractive() {
        return runInteractive;
    }

    public boolean isRunAsSystem() {
        return runAsSystem;
    }

    public String getJavaHome() {
        return javaHome;
    }

    /**
     * Gets the formatted current time stamp.
     */
    private static String getTimestamp() {
        return String.format("[%1$tD %1$tT]", new Date());
    }

    @Override
    public void launch(SlaveComputer computer, final TaskListener listener) {
        String hostName = this.hostName != null ? this.hostName : computer.getName();

        String psexec = Hudson.getInstance().getDescriptorByType(DescriptorImpl.class).getPsexec();
        if (psexec == null) {
            psexec = "psexec.exe";
        }

        String javaw = "javaw";
        String javaHome = Util.fixEmptyAndTrim(this.javaHome);
        if (javaHome != null) javaw = javaHome + "\\bin\\" + javaw;

        String remoteCommand = String.format("%s -cp \"%s\\slave.jar\" hudson.remoting.jnlp.Main -noreconnect -headless " +
                "-url \"%s\" %s \"%s\"", javaw, computer.getNode().getRemoteFS(), Hudson.getInstance().getRootUrl(), Hudson.getInstance().getSecretKey(), computer.getName());

        String interActive = runInteractive ? "-i": "";
        String system = runAsSystem ? "-s":"";
        String async = Boolean.getBoolean(getClass().getName() + ".SYNC") ? "" : "-d";

        String command = String.format("%s \\\\%s -accepteula %s %s %s -u \"%s\" -p \"%s\" %s",
                psexec, hostName, interActive, async, system, userName, password, remoteCommand);

        copySlaveJar(computer, hostName, listener);

        EnvVars _cookie = null;
        Process _proc = null;
        try {
            listener.getLogger().println(hudson.model.Messages.Slave_Launching(getTimestamp()));
            if(command.trim().length()==0) {
                listener.getLogger().println("CommandLauncher_NoLaunchCommand");
                return;
            }
            listener.getLogger().println("$ " + command.replace(password, "<...>"));

            ProcessBuilder pb = new ProcessBuilder(Util.tokenize(command));
            final EnvVars cookie = _cookie = EnvVars.createCookie();
            pb.environment().putAll(cookie);

            {// system defined variables
                String rootUrl = Jenkins.getInstance().getRootUrl();
                if (rootUrl!=null) {
                    pb.environment().put("HUDSON_URL", rootUrl);    // for backward compatibility
                    pb.environment().put("JENKINS_URL", rootUrl);
                    pb.environment().put("SLAVEJAR_URL", rootUrl+"/jnlpJars/slave.jar");
                }
            }

            final Process proc = _proc = pb.start();

            // capture error information from stderr. this will terminate itself
            // when the process is killed.
            new StreamCopyThread("stderr copier for remote agent on " + computer.getDisplayName(),
                    proc.getErrorStream(), listener.getLogger()).start();
            new StreamCopyThread("stdout copier for remote agent on " + computer.getDisplayName(),
                    proc.getInputStream(), listener.getLogger()).start();

            LOGGER.info("slave agent launched for " + computer.getDisplayName());
        } catch (RuntimeException e) {
            e.printStackTrace(listener.error(Messages.ComputerLauncher_unexpectedError()));
        } catch (Error e) {
            e.printStackTrace(listener.error(Messages.ComputerLauncher_unexpectedError()));
        } catch (IOException e) {
            Util.displayIOException(e, listener);

            String msg = Util.getWin32ErrorMessage(e);
            if (msg == null) {
                msg = "";
            } else {
                msg = " : " + msg;
            }
            msg = hudson.model.Messages.Slave_UnableToLaunch(computer.getDisplayName(), msg);
            LOGGER.log(Level.SEVERE, msg, e);
            e.printStackTrace(listener.error(msg));

            if(_proc!=null)
                try {
                    ProcessTree.get().killAll(_proc, _cookie);
                } catch (InterruptedException x) {
                    x.printStackTrace(listener.error(Messages.ComputerLauncher_abortedLaunch()));
                }
        }
    }

    private void copySlaveJar(SlaveComputer computer, String hostName, TaskListener listener) {
        try {
            JIDefaultAuthInfoImpl auth = createAuth();
            JISession session = JISession.createSession(auth);
            session.setGlobalSocketTimeout(60000);

            final String path = computer.getNode().getRemoteFS();
            if (path.indexOf(':') == -1)
                throw new IOException("Remote file system root path of the slave needs to be absolute: " + path);
            SmbFile remoteRoot = new SmbFile("smb://" + hostName + "/" + path.replace('\\', '/').replace(':', '$') + "/", createSmbAuth());

            if (!remoteRoot.exists())
                remoteRoot.mkdirs();

            listener.getLogger().println("Copying slave.jar");
            URL slaveJarURL = Hudson.getInstance().getJnlpJars("slave.jar").getURL();
            copyStreamAndClose(slaveJarURL.openStream(), new SmbFile(remoteRoot, "slave.jar").getOutputStream());
        } catch (IOException e) {
            e.printStackTrace(listener.getLogger());
        }
    }

    private static final Logger LOGGER = Logger.getLogger(PSExecLauncher.class.getName());

    private JIDefaultAuthInfoImpl createAuth() {
        String[] tokens = userName.split("\\\\");
        if (tokens.length == 2)
            return new JIDefaultAuthInfoImpl(tokens[0], tokens[1], password.toString());
        return new JIDefaultAuthInfoImpl("", userName, password.toString());
    }
    private NtlmPasswordAuthentication createSmbAuth() {
        JIDefaultAuthInfoImpl auth = createAuth();
        return new NtlmPasswordAuthentication(auth.getDomain(), auth.getUserName(), auth.getPassword());
    }


    @Extension
    public static class DescriptorImpl extends Descriptor<ComputerLauncher> {

        private String psexec;

        public DescriptorImpl() {
            load();
        }

        public String getPsexec() {
            return psexec;
        }

        public void setPsexec(String psexec) {
            this.psexec = psexec;
        }

        public String getDisplayName() {
            return "Launch using psexec.exe";
        }

        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            setPsexec(Util.nullify(json.getString("psexec")));
            save();
            return true;
        }
        }
}
