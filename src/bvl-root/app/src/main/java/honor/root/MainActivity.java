package honor.root;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private ExploitRunner runner;
    private TextView logView;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);

        runner = new ExploitRunner();
        logView = findViewById(R.id.log);

        Button race = findViewById(R.id.btn_race);
        Button load = findViewById(R.id.btn_load);
        race.setOnClickListener(v -> runRace());
        load.setOnClickListener(v -> runLoad());
    }

    private void runRace() {
        append("--- 43499 harness ---");
        new Thread(() -> {
            // DEV: license gate stub returns true in this clean build.
            runner.n0(null, null, null);
            String r = runner.n7();
            append(r);
        }).start();
    }

    private void runLoad() {
        append("--- KSU load ---");
        new Thread(() -> {
            String ko = runner.extractAsset(this, "kernelsu-android14-6.1.ko");
            String ksud = runner.extractAsset(this, "ksud");
            if (ko == null) {
                append("KO asset missing (expected: kernelsu-android14-6.1.ko)");
                return;
            }
            append("KO: " + ko);
            append("ksud: " + (ksud == null ? "(none — insmod only)" : ksud));
            int rc = runner.n1(ko, ksud, ksud != null);
            append("loadKsu rc=" + rc + (rc == 0 ? "  => /proc/modules has kernelsu" : ""));
        }).start();
    }

    private void append(String s) {
        runOnUiThread(() -> {
            logView.append(s + "\n");
            runner.report(s);
        });
    }
}
