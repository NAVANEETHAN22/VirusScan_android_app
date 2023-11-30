package com.example.virusscan;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

public class SQLInjectionActivity extends AppCompatActivity {

    private EditText sqlQueryEditText;
    private Button scanSqlInjectionButton;
    private TextView scanResultTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sql_injection);

        sqlQueryEditText = findViewById(R.id.sqlQueryEditText);
        scanSqlInjectionButton = findViewById(R.id.scanSqlInjectionButton);
        scanResultTextView = findViewById(R.id.scanResultTextView);

        scanSqlInjectionButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String sqlQuery = sqlQueryEditText.getText().toString();
                if (!sqlQuery.isEmpty()) {
                    scanSQLInjection(sqlQuery);
                } else {
                    Toast.makeText(getApplicationContext(), "Please enter an SQL query", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void scanSQLInjection(String sqlQuery) {
        // Perform the SQL injection scan here and determine if it's malicious

        // For demonstration purposes, let's assume it's a simple check
        boolean isMalicious = sqlQuery.contains("DROP TABLE");

        // Display the scan result
        if (isMalicious) {
            scanResultTextView.setText("This SQL query is malicious.");
        } else {
            scanResultTextView.setText("This SQL query is not malicious.");
        }
    }
}
