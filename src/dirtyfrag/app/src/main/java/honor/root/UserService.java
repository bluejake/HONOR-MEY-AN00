package honor.root;

import android.os.IBinder;

/** Runs inside Shizuku's shell-domain process (v210 bait executor). */
public class UserService extends IUserService.Stub {

    @Override
    public String runShell(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            byte[] out = new byte[4096];
            int n;
            StringBuilder sb = new StringBuilder();
            java.io.InputStream is = p.getInputStream();
            while ((n = is.read(out)) > 0) sb.append(new String(out, 0, n));
            java.io.InputStream es = p.getErrorStream();
            while ((n = es.read(out)) > 0) sb.append(new String(out, 0, n));
            int rc = p.waitFor();
            return "rc=" + rc + "\n" + sb;
        } catch (Throwable t) {
            return "ERR:" + t;
        }
    }

    @Override
    public void destroy() {
        System.exit(0);
    }

    @Override
    public String spawnOrphans(int count) {
        // Each cycle: launch a background sleeper then exit the shell -
        // the sleeper is orphaned and adopted/reaped by init (tid 1).
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            try {
                Process p = Runtime.getRuntime().exec(
                        new String[]{"sh", "-c", "(sleep 2 &) ; sleep 1"});
                byte[] out = new byte[1024];
                int n = p.getInputStream().read(out);
                if (n > 0) sb.append(new String(out, 0, n));
                p.waitFor();
                sb.append("orphan ").append(i + 1).append(" spawned\n");
            } catch (Throwable t) {
                sb.append("ERR:").append(t).append('\n');
            }
        }
        return sb.toString();
    }

    @Override
    public IBinder asBinder() {
        return null;
    }


}
