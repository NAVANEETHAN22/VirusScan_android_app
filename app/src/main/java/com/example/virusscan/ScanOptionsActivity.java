package com.example.virusscan;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import androidx.appcompat.app.AppCompatActivity;

public class ScanOptionsActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_scan_options);

        // Initialize buttons and set click listeners
        Button scanFilesButton = findViewById(R.id.scanFilesButton);
        Button scanLinksButton = findViewById(R.id.scanLinksButton);
        Button sqlInjectionButton = findViewById(R.id.sqlInjectionButton);
        Button xssButton = findViewById(R.id.xssButton); // Add this line

        scanFilesButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // Handle the click event for scanning files
                startActivity(new Intent(ScanOptionsActivity.this, MainActivity.class));
            }
        });

        scanLinksButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // Handle the click event for scanning links
                startActivity(new Intent(ScanOptionsActivity.this, LinkScannerActivity.class));
            }
        });

        sqlInjectionButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // Handle the click event for SQL Injection
                startActivity(new Intent(ScanOptionsActivity.this, SQLInjectionActivity.class));
            }
        });

        xssButton.setOnClickListener(new View.OnClickListener() { // Add this block
            @Override
            public void onClick(View view) {
                // Handle the click event for XSS scanning
                startActivity(new Intent(ScanOptionsActivity.this, XSSActivity.class)); // Replace 'XSSActivity' with the actual activity for XSS scanning
            }
        });
    }
}
